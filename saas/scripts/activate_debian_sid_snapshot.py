"""Replace the one rolling Debian Sid source with an exact snapshot."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

_SNAPSHOT = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
_COMMENTED_SOURCE = re.compile(
    r"(?m)^# (http://snapshot[.]debian[.]org/archive/debian/[0-9]{8}T[0-9]{6}Z)\n"
    r"URIs: http://deb[.]debian[.]org/debian$"
)


def activate(path: Path, snapshot: str) -> str:
    if _SNAPSHOT.fullmatch(snapshot) is None:
        raise ValueError(f"invalid Debian snapshot timestamp: {snapshot!r}")
    source = path.read_text(encoding="utf-8")
    uri = f"http://snapshot.debian.org/archive/debian/{snapshot}"
    normalized, count = _COMMENTED_SOURCE.subn(
        lambda match: f"# {match.group(1)}\nURIs: {uri}", source
    )
    if count != 1:
        raise ValueError(f"expected one Debian Sid snapshot source, found {count}")
    uris = re.findall(r"(?m)^URIs: (\S+)$", normalized)
    suites = re.findall(r"(?m)^Suites: (.+)$", normalized)
    if uris != [uri] or suites != ["sid"]:
        raise ValueError(f"unexpected Debian Sid source contract: {uris!r}, {suites!r}")
    path.write_text(normalized, encoding="utf-8")
    return uri


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True)
    parser.add_argument(
        "--path", type=Path, default=Path("/etc/apt/sources.list.d/debian.sources")
    )
    args = parser.parse_args()
    print(f"Debian Sid snapshot coordinate: {activate(args.path, args.snapshot)}")


if __name__ == "__main__":
    main()
