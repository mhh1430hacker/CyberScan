"""Local SQLite conversation persistence with principal-scoped access."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator
from typing import Any

from AI.contracts import Conversation


class ConversationStoreError(RuntimeError):
    """Conversation data could not be safely stored or retrieved."""


class SQLiteConversationStore:
    MAX_MESSAGES = 200
    MAX_MESSAGE_CHARS = 100_000

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ConversationStoreError("Conversation database path must not be a symbolic link.")
        self._initialize()
        if os.name != "nt":
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        try:
            with self._connection() as connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS conversations (
                        principal TEXT NOT NULL,
                        conversation_id TEXT NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (principal, conversation_id)
                    )"""
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS messages (
                        principal TEXT NOT NULL,
                        conversation_id TEXT NOT NULL,
                        position INTEGER NOT NULL,
                        role TEXT NOT NULL,
                        content TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY (principal, conversation_id, position),
                        FOREIGN KEY (principal, conversation_id)
                            REFERENCES conversations(principal, conversation_id)
                            ON DELETE CASCADE
                    )"""
                )
        except sqlite3.Error as exc:
            raise ConversationStoreError(f"Conversation database initialization failed: {type(exc).__name__}.") from exc

    @staticmethod
    def _validate_id(value: str, field: str) -> None:
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"{field} must be non-empty text of at most 256 characters.")

    @classmethod
    def _validate_messages(cls, messages: tuple[dict[str, Any], ...]) -> None:
        if len(messages) > cls.MAX_MESSAGES:
            raise ValueError(f"A conversation may contain at most {cls.MAX_MESSAGES} messages.")
        for item in messages:
            if (
                not isinstance(item, dict)
                or set(item) - {"role", "content", "created_at"}
                or item.get("role") not in {"system", "user", "assistant"}
                or not isinstance(item.get("content"), str)
                or len(item["content"]) > cls.MAX_MESSAGE_CHARS
            ):
                raise ValueError("Conversation contains an invalid or oversized message.")
            if "created_at" in item and not isinstance(item["created_at"], (int, float)):
                raise ValueError("created_at must be numeric.")

    def get(self, conversation_id: str, *, principal: str = "local") -> Conversation | None:
        self._validate_id(principal, "principal")
        self._validate_id(conversation_id, "conversation_id")
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT 1 FROM conversations WHERE principal = ? AND conversation_id = ?",
                    (principal, conversation_id),
                ).fetchone()
                if row is None:
                    return None
                rows = connection.execute(
                    "SELECT role, content, created_at FROM messages "
                    "WHERE principal = ? AND conversation_id = ? ORDER BY position",
                    (principal, conversation_id),
                ).fetchall()
        except sqlite3.Error as exc:
            raise ConversationStoreError(f"Conversation could not be read: {type(exc).__name__}.") from exc
        return Conversation(
            conversation_id,
            tuple({"role": role, "content": content, "created_at": created} for role, content, created in rows),
        )

    def save(self, conversation: Conversation, *, principal: str = "local") -> None:
        self._validate_id(principal, "principal")
        self._validate_id(conversation.conversation_id, "conversation_id")
        if not isinstance(conversation.messages, tuple):
            raise ValueError("conversation.messages must be a tuple.")
        self._validate_messages(conversation.messages)
        now = time.time()
        try:
            with self._connect() as connection:
                other_owner = connection.execute(
                    "SELECT 1 FROM conversations WHERE conversation_id = ? AND principal != ?",
                    (conversation.conversation_id, principal),
                ).fetchone()
                if other_owner:
                    raise ConversationStoreError("Conversation belongs to a different principal.")
                connection.execute(
                    "INSERT INTO conversations (principal, conversation_id, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(principal, conversation_id) DO UPDATE SET updated_at = excluded.updated_at",
                    (principal, conversation.conversation_id, now),
                )
                connection.execute(
                    "DELETE FROM messages WHERE principal = ? AND conversation_id = ?",
                    (principal, conversation.conversation_id),
                )
                connection.executemany(
                    "INSERT INTO messages (principal, conversation_id, position, role, content, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (principal, conversation.conversation_id, index, item["role"], item["content"],
                         item.get("created_at", now))
                        for index, item in enumerate(conversation.messages[-self.MAX_MESSAGES:])
                    ],
                )
        except sqlite3.Error as exc:
            raise ConversationStoreError(f"Conversation could not be saved: {type(exc).__name__}.") from exc

    def delete(self, conversation_id: str, *, principal: str = "local") -> bool:
        self._validate_id(principal, "principal")
        self._validate_id(conversation_id, "conversation_id")
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    "DELETE FROM conversations WHERE principal = ? AND conversation_id = ?",
                    (principal, conversation_id),
                )
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise ConversationStoreError(f"Conversation could not be deleted: {type(exc).__name__}.") from exc
