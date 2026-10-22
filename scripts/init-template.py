#!/usr/bin/env python3
"""Personalize a repository created from the ALVA Go template."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURRENT_MODULE = "github.com/dgtl-alv/alva-go-web-app-template"


def valid_application_id(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", value):
        raise argparse.ArgumentTypeError("use 3-63 lowercase letters, numbers, or hyphens")
    return value


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(old, new), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True, help="Go module, e.g. github.com/dgtl-alv/inventory-app")
    parser.add_argument("--app-name", required=True, help="Human-readable product name")
    parser.add_argument("--application-id", required=True, type=valid_application_id)
    args = parser.parse_args()

    go_mod = ROOT / "go.mod"
    if CURRENT_MODULE not in go_mod.read_text(encoding="utf-8"):
        parser.error("template already initialized or go.mod has an unexpected module")

    for path in ROOT.rglob("*.go"):
        replace(path, CURRENT_MODULE, args.module)
    replace(go_mod, CURRENT_MODULE, args.module)
    for path in (ROOT / ".env.example", ROOT / "docker-compose.yml"):
        replace(path, "ALVA Web App", args.app_name)
        replace(path, "alva-web-app", args.application_id)
    replace(ROOT / "README.md", "ALVA Go Web App Template", args.app_name)
    print(f"Initialized {args.app_name} ({args.application_id}) with module {args.module}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
