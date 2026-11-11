"""Explicit local-model management commands; there is no automatic download."""
from __future__ import annotations

import argparse
import json

from AI.model_manager import LocalModelManager, ModelManagerError


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage CyberScan's optional local AI model.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show local runtime and pinned-model status.")
    install = commands.add_parser("install", help="Download the pinned model after explicit confirmation.")
    install.add_argument("--model-id", default=None)
    install.add_argument("--confirm", action="store_true", help="Confirm downloading the selected model (~2.5 GB).")
    args = parser.parse_args()
    manager = LocalModelManager()
    try:
        if args.command == "status":
            print(json.dumps(manager.status().__dict__, indent=2))
            return 0
        path = manager.install(args.model_id, confirm=args.confirm)
        print(f"Verified model installed at: {path}")
        return 0
    except ModelManagerError as exc:
        parser.exit(2, f"Model operation refused or failed: {exc}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
