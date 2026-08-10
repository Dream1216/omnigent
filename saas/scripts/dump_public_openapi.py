"""Generate or verify the frozen isolated public API OpenAPI document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from saas.public_api_contract import public_openapi_document

_DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "openapi-v1.json"


def serialized_document() -> str:
    return json.dumps(public_openapi_document(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the frozen file differs instead of updating it",
    )
    args = parser.parse_args()
    expected = serialized_document()
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != expected:
            parser.error(f"{args.output} is stale; regenerate it with this command")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
