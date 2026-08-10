"""Fail when a candidate public OpenAPI file breaks a released baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from saas.public_api_compatibility import find_breaking_changes


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load OpenAPI document {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"OpenAPI document {path} must contain a JSON object")
    return cast(dict[str, object], value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    try:
        baseline = _load(args.baseline)
        candidate = _load(args.candidate)
    except ValueError as error:
        parser.error(str(error))
    changes = find_breaking_changes(baseline, candidate)
    if changes:
        for change in changes:
            print(change.render())
        return 1
    print("public OpenAPI compatibility check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
