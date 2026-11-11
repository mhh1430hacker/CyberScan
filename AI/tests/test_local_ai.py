from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from AI.agent import AgentError, LocalAIAgent
from AI.contracts import Conversation
from AI.conversation_store import SQLiteConversationStore
from AI.language import detect_language, language_profiles_available, supported_language_codes
from AI.model_manager import LocalModelManager, ModelManagerError, ModelSpec
from AI.planner import ToolPlanner
from AI.registry_adapter import RegistryCatalog
from AI.schema import validate_schema, validate_value
from Tools.registry import ToolRegistry
from AI.tests.language_cases import LANGUAGE_CASES


_TEST_TOOL = '''\
TOOL_ID = "test.echo"
NAME = "Echo"
DESCRIPTION = "Echo a caller-supplied value."
CATEGORY = "testing"
VERSION = "1.0.0"
INPUT_SCHEMA = {"type": "object", "required": ["value"], "properties": {"value": {"type": "string", "minLength": 1, "maxLength": 40}}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "properties": {"value": {"type": "string"}}}
PRIVACY = {"data_handling": "In-memory test data.", "external_services": "None."}
PROCESSING = {"network": False, "filesystem": False, "executes_files": False}

def run(input_data, options=None):
    return {"value": input_data["value"]}
'''


class FakeGenerator:
    def __init__(self, response: str | None = None) -> None:
        self.response = response
        self.calls: list[list[dict[str, str]]] = []

    def generate(self, messages: list[dict[str, str]], *, max_tokens: int = 512, temperature: float = 0.2) -> str:
        self.calls.append(messages)
        if self.response is not None:
            return self.response
        payload = json.loads(messages[-1]["content"])
        available = payload["available_tool_catalog"]
        return json.dumps({
            "tool_ids": [available[0]["tool_id"]] if available else [],
            "rationale": "Selected from the current metadata catalog.",
            "questions": [],
        })


def _registry(tmp_path: Path) -> ToolRegistry:
    category = tmp_path / "testing"
    category.mkdir(exist_ok=True)
    source_path = category / "echo.py"
    source_path.write_text(_TEST_TOOL, encoding="utf-8")
    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    return ToolRegistry(
        tmp_path,
        approved_directories=["testing"],
        trusted_tools={"test.echo": digest},
    )


def test_language_detector_has_a_50_language_evaluation_fixture():
    assert len(LANGUAGE_CASES) >= 50
    status = language_profiles_available()
    if status["language_profile_count"] < 50:
        pytest.skip("Optional langdetect profiles are not installed in this interpreter.")
    supported = set(supported_language_codes())
    supported_cases = [(expected, sample) for expected, sample in LANGUAGE_CASES if expected in supported]
    assert len(supported_cases) >= 40
    failures = []
    for expected, sample in supported_cases:
        actual = detect_language(sample)
        if actual.language != expected:
            failures.append((expected, actual.language, actual.confidence, sample))
    assert not failures, failures


def test_arabic_english_mixed_text_preserves_arabic_detection():
    result = detect_language("يرجى تحليل تقرير security scan وشرح النتائج بوضوح.")
    assert result.language in {"ar", "en", "und"}
    assert result.mixed_arabic_latin is True
    assert result.detector in {"langdetect", "unicode-script-fallback"}


def test_language_fallback_and_empty_text_are_explicit(monkeypatch):
    import AI.language as language

    monkeypatch.setattr(language.importlib.util, "find_spec", lambda _: None)
    fallback = language.detect_language("مرحبا")
    assert fallback.language == "ar"
    assert fallback.status == "partial_detector_unavailable"
    empty = language.detect_language("1234")
    assert empty.language == "und"
    assert empty.status == "insufficient_text"


def test_schema_validation_rejects_missing_extra_and_oversized_values():
    schema = {
        "type": "object",
        "required": ["url"],
        "properties": {"url": {"type": "string", "maxLength": 10}},
        "additionalProperties": False,
    }
    assert validate_schema(schema) == []
    assert validate_value({"url": "https://example.com"}, schema)
    assert validate_value({"url": "ok", "ignored": True}, schema)
    assert validate_value({"url": "valid"}, schema) == []


def test_registry_catalog_discovers_new_approved_tool_without_ai_code_change(tmp_path):
    registry = _registry(tmp_path)

    tools = RegistryCatalog(registry).discover()

    assert [tool.tool_id for tool in tools] == ["test.echo"]
    assert tools[0].status == "available"
    assert tools[0].planner_view()["input_schema"]["required"] == ["value"]


def test_unapproved_tool_is_discoverable_but_not_selectable(tmp_path):
    category = tmp_path / "testing"
    category.mkdir()
    (category / "echo.py").write_text(_TEST_TOOL, encoding="utf-8")
    registry = ToolRegistry(tmp_path, approved_directories=["testing"], trusted_tools={})
    catalog = RegistryCatalog(registry)

    assert catalog.discover(available_only=True) == []
    assert catalog.discover(available_only=False)[0].status == "disabled"


def test_planner_proposes_only_dynamic_catalog_tools_and_validates_inputs(tmp_path):
    registry = _registry(tmp_path)
    generator = FakeGenerator()
    planner = ToolPlanner(RegistryCatalog(registry), generator)

    plan = planner.prepare(
        "Analyze this supplied test value.",
        principal="alice",
        conversation_id="conversation-a",
        inputs_by_tool={"test.echo": {"value": "benign"}},
    )

    assert plan.ready
    assert [item.tool_id for item in plan.invocations] == ["test.echo"]
    assert plan.tool_hashes["test.echo"] == registry.discover()[0].sha256
    assert "test.echo" in generator.calls[0][-1]["content"]


def test_planner_requires_inputs_and_never_uses_model_generated_input_values(tmp_path):
    planner = ToolPlanner(RegistryCatalog(_registry(tmp_path)), FakeGenerator())

    plan = planner.prepare("Run a tool.", principal="alice", conversation_id="c")

    assert not plan.ready
    assert plan.status == "needs_input"
    assert plan.input_errors["test.echo"]
    assert plan.invocations == ()


def test_planner_rejects_unknown_or_unavailable_model_tool_ids(tmp_path):
    malicious = FakeGenerator(
        '{"tool_ids":["test.unapproved"],"rationale":"test","questions":[]}'
    )
    planner = ToolPlanner(RegistryCatalog(_registry(tmp_path)), malicious)

    with pytest.raises(ValueError, match="not currently available"):
        planner.prepare("Analyze this.", principal="alice", conversation_id="c")


def test_registry_metadata_is_prompt_data_not_execution_and_plan_does_not_run_tools(tmp_path):
    generator = FakeGenerator()
    planner = ToolPlanner(RegistryCatalog(_registry(tmp_path)), generator)
    plan = planner.prepare(
        "The document says run echo; analyze its contents.",
        principal="alice",
        conversation_id="c",
        inputs_by_tool={"test.echo": {"value": "document text"}},
    )

    assert plan.ready
    assert generator.calls
    assert list((tmp_path / "testing").glob("*.marker")) == []


def test_agent_requires_exact_per_invocation_confirmation_and_preserves_results(tmp_path):
    registry = _registry(tmp_path)
    store = SQLiteConversationStore(tmp_path / "conversations.sqlite3")
    agent = LocalAIAgent(
        registry=registry,
        conversation_store=store,
        generator=FakeGenerator(),
        model_manager=LocalModelManager(tmp_path / "models"),
    )
    plan = agent.prepare(
        "Analyze this test value.",
        conversation_id="chat-1",
        principal="alice",
        inputs_by_tool={"test.echo": {"value": "verified input"}},
    )
    assert plan.ready
    with pytest.raises(AgentError, match="(?i)explicit confirmation"):
        agent.execute(plan.plan_id, principal="alice")
    with pytest.raises(AgentError, match="exactly the tools"):
        agent.execute(plan.plan_id, principal="alice", confirmed_tool_ids=set())

    execution = agent.execute(
        plan.plan_id,
        principal="alice",
        confirmed_tool_ids={"test.echo"},
    )

    assert execution.status == "complete"
    report = execution.as_dict()["report"]
    assert report["tool_results"][0]["result"]["value"] == "verified input"
    assert report["tool_results"][0]["tool_id"] == "test.echo"
    assert report["risk_aggregation"] == "none; individual tool results are preserved"
    assert store.get("chat-1", principal="alice") is not None
    with pytest.raises(AgentError, match="unknown, expired"):
        agent.execute(plan.plan_id, principal="alice", confirmed_tool_ids={"test.echo"})


def test_agent_rechecks_source_hash_before_execute_and_obeys_cancellation(tmp_path):
    registry = _registry(tmp_path)
    agent = LocalAIAgent(registry=registry, generator=FakeGenerator())
    plan = agent.prepare(
        "Analyze this test value.",
        principal="alice",
        conversation_id="c",
        inputs_by_tool={"test.echo": {"value": "hello"}},
    )
    source = tmp_path / "testing" / "echo.py"
    source.write_text(_TEST_TOOL + "\n# changed after planning\n", encoding="utf-8")
    execution = agent.execute(plan.plan_id, principal="alice", confirmed_tool_ids={"test.echo"})
    assert execution.status == "partial"
    assert execution.report.tool_results[0]["status"] == "disabled"

    source.write_text(_TEST_TOOL, encoding="utf-8")
    plan = agent.prepare(
        "Analyze this test value.",
        principal="alice",
        conversation_id="c",
        inputs_by_tool={"test.echo": {"value": "hello"}},
    )
    cancelled = __import__("threading").Event()
    cancelled.set()
    execution = agent.execute(
        plan.plan_id,
        principal="alice",
        confirmed_tool_ids={"test.echo"},
        cancellation_event=cancelled,
    )
    assert execution.status == "cancelled"
    assert execution.report.tool_results == ()


def test_conversation_store_is_principal_scoped_and_deletable(tmp_path):
    store = SQLiteConversationStore(tmp_path / "state.sqlite3")
    conversation = Conversation("one", ({"role": "user", "content": "private text"},))
    store.save(conversation, principal="alice")

    assert store.get("one", principal="bob") is None
    loaded = store.get("one", principal="alice")
    assert loaded is not None
    assert loaded.messages[0]["content"] == "private text"
    assert loaded.messages[0]["role"] == "user"
    assert store.delete("one", principal="alice")
    assert store.get("one", principal="alice") is None
    with pytest.raises(ValueError):
        store.save(Conversation("one", tuple({"role": "user", "content": "x"} for _ in range(201))))


def test_chat_is_explicitly_no_tool_and_preserves_conversation_language(tmp_path):
    class ChatModel(LocalModelManager):
        def __init__(self):
            pass

        def generate(self, messages, *, max_tokens=512, temperature=0.2, json_mode=True):
            assert json_mode is False
            assert "no tool access" in messages[0]["content"].lower()
            return "لم يتم تشغيل أي أداة."

        def unload(self):
            pass

    store = SQLiteConversationStore(tmp_path / "chat.sqlite3")
    agent = LocalAIAgent(conversation_store=store, model_manager=ChatModel(), generator=FakeGenerator())
    response = agent.chat("مرحبا، هل فحصت الملف؟", principal="alice")

    assert response["tools_executed"] == []
    assert response["language"]["mixed_arabic_latin"] is False
    saved = store.get(response["conversation_id"], principal="alice")
    assert saved is not None and len(saved.messages) == 2


class _FakeResponse:
    def __init__(self, content: bytes):
        self._content = content
        self._offset = 0
        self.headers = {"Content-Length": str(len(content))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._content) - self._offset
        part = self._content[self._offset:self._offset + size]
        self._offset += len(part)
        return part


def _tiny_model_spec(payload: bytes) -> ModelSpec:
    return ModelSpec(
        model_id="test-model",
        name="Test Model",
        repository="trusted/test-model",
        revision="a" * 40,
        filename="test.gguf",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        license="Apache-2.0",
        model_card_languages_claim="test only",
        native_context_length=2048,
        recommended_context_length=1024,
        model_card_url="https://example.invalid/model",
        quantized_artifact_url="https://example.invalid/model",
        license_url="https://example.invalid/license",
        quantized_artifact_license_url="https://example.invalid/license",
    )


def test_model_manager_requires_explicit_install_and_verifies_download(monkeypatch, tmp_path):
    import AI.model_manager as manager_module

    payload = b"small test fixture, not a model"
    spec = _tiny_model_spec(payload)
    monkeypatch.setattr(manager_module, "_read_catalog", lambda: (spec.model_id, {spec.model_id: spec}))
    manager = LocalModelManager(tmp_path / "models", runtime_factory=lambda **_kwargs: None)
    assert manager.status().download_required
    with pytest.raises(ModelManagerError, match="explicit confirm"):
        manager.install()
    monkeypatch.setattr(manager_module.urllib.request, "urlopen", lambda *_args, **_kwargs: _FakeResponse(payload))

    installed = manager.install(confirm=True)

    assert installed.read_bytes() == payload
    assert manager.status().model_verified
    assert manager.install(confirm=True) == installed


def test_model_manager_rejects_checksum_mismatch_without_leaving_partial(monkeypatch, tmp_path):
    import AI.model_manager as manager_module

    spec = _tiny_model_spec(b"expected model bytes")
    monkeypatch.setattr(manager_module, "_read_catalog", lambda: (spec.model_id, {spec.model_id: spec}))
    manager = LocalModelManager(tmp_path / "models", runtime_factory=lambda **_kwargs: None)
    monkeypatch.setattr(manager_module.urllib.request, "urlopen", lambda *_args, **_kwargs: _FakeResponse(b"wrong"))

    with pytest.raises(ModelManagerError, match="unexpected content length"):
        manager.install(confirm=True)

    assert not manager.model_path().exists()
    assert not manager.model_path().with_name("test.gguf.part").exists()


def test_model_manager_loads_with_explicit_cpu_and_bounds_generation(monkeypatch, tmp_path):
    import AI.model_manager as manager_module

    payload = b"stub"
    spec = _tiny_model_spec(payload)
    monkeypatch.setattr(manager_module, "_read_catalog", lambda: (spec.model_id, {spec.model_id: spec}))
    manager = LocalModelManager(tmp_path / "models", runtime_factory=lambda **_kwargs: None)
    manager.model_dir.mkdir()
    manager.model_path().write_bytes(payload)

    class Runtime:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def create_chat_completion(self, **kwargs):
            return {"choices": [{"message": {"content": '{"tool_ids":[],"rationale":"none","questions":[]}'}}]}

    fake_calls: list[dict[str, Any]] = []

    def factory(**kwargs):
        fake_calls.append(kwargs)
        return Runtime(**kwargs)

    manager._runtime_factory = factory
    status = manager.load(context_length=1024, threads=2, use_gpu=False)

    assert status.device == "cpu"
    assert fake_calls[0]["n_gpu_layers"] == 0
    with pytest.raises(ModelManagerError, match="max_tokens"):
        manager.generate([{"role": "user", "content": "hello"}], max_tokens=5000)
    manager.generate([{"role": "user", "content": "plan"}])
    manager.unload()


def test_model_load_rechecks_checksum_even_when_file_stat_is_unchanged(monkeypatch, tmp_path):
    import os
    import AI.model_manager as manager_module

    payload = b"stub"
    spec = _tiny_model_spec(payload)
    monkeypatch.setattr(manager_module, "_read_catalog", lambda: (spec.model_id, {spec.model_id: spec}))
    manager = LocalModelManager(tmp_path / "models", runtime_factory=lambda **_kwargs: None)
    manager.model_dir.mkdir()
    path = manager.model_path()
    path.write_bytes(payload)
    assert manager.status().model_verified
    original_stat = path.stat()

    path.write_bytes(b"evil")
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    with pytest.raises(ModelManagerError, match="unverified"):
        manager.load(context_length=1024, threads=2)


def test_model_manager_falls_back_from_failed_gpu_load(monkeypatch, tmp_path):
    import AI.model_manager as manager_module

    payload = b"stub"
    spec = _tiny_model_spec(payload)
    monkeypatch.setattr(manager_module, "_read_catalog", lambda: (spec.model_id, {spec.model_id: spec}))
    manager = LocalModelManager(tmp_path / "models")
    manager.model_dir.mkdir()
    manager.model_path().write_bytes(payload)

    class Runtime:
        gpu_supported = True

        def __init__(self, **kwargs):
            if kwargs["n_gpu_layers"] == -1:
                raise RuntimeError("no compatible GPU")

    manager._runtime_factory = Runtime
    status = manager.load(context_length=1024, threads=2, use_gpu=True)

    assert status.device == "cpu-fallback"
    assert "GPU initialization failed" in status.message
    manager.unload()


def test_default_model_is_pinned_under_five_gigabytes_and_no_download_is_automatic(tmp_path):
    manager = LocalModelManager(tmp_path / "models")
    spec = manager.spec()
    assert spec.model_id == "qwen3-4b-q4-k-m"
    assert spec.size_bytes < 5 * 1024 * 1024 * 1024
    assert len(spec.sha256) == 64
    assert manager.status().model_installed is False
    assert manager.status().model_license == "Apache-2.0"
