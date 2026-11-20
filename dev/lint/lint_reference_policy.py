"""Check added text and paths against the repository reference policy."""

from __future__ import annotations

import argparse
import difflib
import os
import re
import subprocess
import sys
from bisect import bisect_right
from pathlib import Path

POLICY_FILES = frozenset({"dev/lint/lint_reference_policy.py"})
PROHIBITED_NAMES = frozenset(
    {
        "arca",
        "arcas",
        "arclet",
        "arclets",
        "isaac",
        "dbcert",
        "dbcerts",
        "lakebox",
        "ucode",
        "dbexec",
        "spog",
    }
)
PHRASES = re.compile(
    r"databricks[\s_-]*(?:internal|corp(?:orate)?|employees?|network|only)"
    r"|(?:internal|corp(?:orate)?)[\s_-]*databricks"
    r"|databricks-eng(?:/|\b)"
    r"|\binternal[-_]beta\b"
    r"|\be2[-_]dogfood\b",
    re.IGNORECASE,
)
HOST_SUFFIXES = ("databricks.com", "databricksapps.com", "azuredatabricks.net")
PUBLIC_HOSTS = frozenset(
    {
        "www.databricks.com",
        "docs.databricks.com",
        "accounts.cloud.databricks.com",
        "login.databricks.com",
    }
)


def host_pattern(suffixes: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(suffix) for suffix in suffixes)
    return re.compile(
        r"(?<![\w.-])(?:[a-z0-9-]+\.)+(?:" + alternatives + r")(?![\w-]|\.[\w-])",
        re.IGNORECASE,
    )


HOST = host_pattern(HOST_SUFFIXES)


def _violation_lines(text: str) -> set[int]:
    """Return LF-based locations, including phrases that wrap across lines."""
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", words)
    lines = set()
    original_lines = text.split("\n")
    for line_number, normalized in enumerate(words.split("\n"), 1):
        if PROHIBITED_NAMES.intersection(re.findall(r"[a-z]+", normalized.lower())) or any(
            match.group().lower() not in PUBLIC_HOSTS
            for match in HOST.finditer(original_lines[line_number - 1])
        ):
            lines.add(line_number)
    line_starts = [0, *(match.end() for match in re.finditer("\n", words))]
    position = 0
    while match := PHRASES.search(words, position):
        first_line = bisect_right(line_starts, match.start())
        for offset, segment in enumerate(match.group().split("\n")):
            if segment.strip():
                lines.add(first_line + offset)
        position = match.start() + 1
    return lines


def violates(text: str) -> bool:
    """Match names in prose, snake_case, camelCase, and filenames."""
    return bool(_violation_lines(text))


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True).stdout


def _added_blob_lines(root: Path, old: bytes, new: bytes, options: list[str]) -> set[int]:
    patch = git(
        root,
        "diff",
        *options,
        "--text",
        "--unified=0",
        "--inter-hunk-context=0",
        old.decode(),
        new.decode(),
        "--",
    ).decode("utf-8", errors="replace")
    added_lines = set()
    line_number = None
    for line in patch.split("\n"):
        hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            line_number = int(hunk[1])
        elif line_number is not None and line.startswith("+"):
            added_lines.add(line_number)
            line_number += 1
        elif line_number is not None and line.startswith(" "):
            line_number += 1
    return added_lines


def _novel_phrases(root: Path, old: bytes | None, text: str) -> list[set[int]]:
    """Retain a new phrase formed by joining otherwise unchanged lines."""
    previous = (
        git(root, "cat-file", "blob", old.decode()).decode("utf-8", errors="replace")
        if old
        else ""
    )
    blocks = difflib.SequenceMatcher(
        None, previous.split("\n"), text.split("\n"), autojunk=False
    ).get_matching_blocks()
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", words)
    starts = [0, *(match.end() for match in re.finditer("\n", words))]
    result = []
    position = 0
    while match := PHRASES.search(words, position):
        first = bisect_right(starts, match.start())
        last = bisect_right(starts, match.end() - 1)
        if not any(block.b <= first - 1 and block.b + block.size >= last for block in blocks):
            result.append(set(range(first, last + 1)))
        position = match.start() + 1
    return result


def check(
    root: Path,
    base: str | None = None,
    head: str | None = None,
    *,
    remote: str | None = None,
    adopted_base: str | None = None,
) -> list[str]:
    """Check staged changes, or the branch diff from a merge base."""
    if head and not base:
        raise ValueError("--head requires --base")
    revisions = ["--cached"]
    if base:
        target = head or "HEAD"
        ancestor = git(root, "merge-base", base, target).decode().strip()
        if remote:
            try:
                upstream = git(
                    root,
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    f"refs/remotes/{remote}/HEAD^{{commit}}",
                )
            except subprocess.CalledProcessError as error:
                if error.returncode != 1:
                    raise
            else:
                # Check the whole branch, excluding history already on the remote default.
                # The old push tip can retain prerequisite commits from before a rebase.
                ancestor = (
                    git(root, "merge-base", upstream.decode().strip(), target).decode().strip()
                )
        revisions = [ancestor, target]
    adopted_blobs: dict[str, bytes] = {}
    if adopted_base is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", adopted_base):
            raise ValueError("adopted base requires an exact commit")
        git(root, "rev-parse", "--verify", f"{adopted_base}^{{commit}}")
        targets = [head or "HEAD"]
        if not base:
            try:
                merge_heads = (
                    git(root, "rev-parse", "--verify", "MERGE_HEAD").decode().splitlines()
                )
                if len(merge_heads) != 1:
                    raise ValueError("adoption requires one merge parent")
                targets.extend(merge_heads)
            except subprocess.CalledProcessError as error:
                if error.returncode not in (1, 128):
                    raise
        adopted = False
        for target in targets:
            try:
                git(root, "merge-base", "--is-ancestor", adopted_base, target)
            except subprocess.CalledProcessError as error:
                if error.returncode != 1:
                    raise
            else:
                adopted = True
                break
        if not adopted:
            raise ValueError("adopted base is not in the inspected lineage")
        try:
            git(root, "merge-base", "--is-ancestor", adopted_base, ancestor if base else "HEAD")
        except subprocess.CalledProcessError as error:
            if error.returncode != 1:
                raise
            for entry in git(root, "ls-tree", "-rz", "--full-tree", adopted_base).split(b"\0"):
                if not entry:
                    continue
                metadata, path = entry.split(b"\t", 1)
                _mode, kind, object_id = metadata.split()
                if kind == b"blob":
                    adopted_blobs[os.fsdecode(path)] = object_id
    options = ["--no-ext-diff", "--no-textconv", "--no-color"]
    entries = iter(
        git(
            root,
            "diff",
            *options,
            "--find-renames",
            *revisions,
            "--raw",
            "--no-abbrev",
            "-z",
            "--diff-filter=AMRT",
            "--",
        ).split(b"\0")
    )
    findings = []
    for metadata in entries:
        if not metadata:
            break
        old_mode, mode, old_object_id, object_id, status = metadata[1:].split()
        old_path = os.fsdecode(next(entries))
        renamed = status.startswith(b"R")
        path = os.fsdecode(next(entries)) if renamed else old_path
        if path in POLICY_FILES:
            continue
        adopted_object = adopted_blobs.get(path)
        if (status == b"A" or renamed) and adopted_object is None and violates(path):
            findings.append(f"{path}:1: prohibited reference in new path")
        if mode == b"160000" or object_id == adopted_object:
            continue
        contents = git(root, "cat-file", "blob", object_id.decode())
        if b"\0" in contents[:8000]:
            continue
        text = contents.decode("utf-8", errors="replace")
        violation_lines = _violation_lines(text)
        if not violation_lines:
            continue
        if status == b"A" or old_mode == b"160000" or old_path in POLICY_FILES:
            added_lines = violation_lines
        else:
            added_lines = _added_blob_lines(root, old_object_id, object_id, options)
        original_added_lines = set(added_lines)
        if adopted_object is not None:
            phrases = _novel_phrases(
                root, old_object_id if status != b"A" and old_mode != b"160000" else None, text
            )
            added_lines &= _added_blob_lines(root, adopted_object, object_id, options)
            adopted_phrases = _novel_phrases(root, adopted_object, text)
            phrases = [phrase for phrase in phrases if phrase in adopted_phrases]
            for phrase in phrases:
                added_lines.update(phrase & original_added_lines)
        findings.extend(
            f"{path}:{line_number}: prohibited reference in added text"
            for line_number in sorted(violation_lines & added_lines)
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("PRE_COMMIT_FROM_REF"))
    parser.add_argument("--head", default=os.environ.get("PRE_COMMIT_TO_REF"))
    parser.add_argument(
        "--adopted-base",
        help="Exact reviewed upstream commit already adopted by this integration.",
    )
    parser.add_argument(
        "--pre-push",
        action="store_true",
        default="PRE_COMMIT_REMOTE_NAME" in os.environ,
        help="Require both push revisions.",
    )
    args = parser.parse_args()
    try:
        if args.pre_push and not (args.base and args.head):
            raise ValueError("--pre-push requires both --base and --head")
        findings = check(
            Path.cwd(),
            args.base,
            args.head,
            remote=os.environ.get("PRE_COMMIT_REMOTE_NAME", "origin") if args.pre_push else None,
            adopted_base=args.adopted_base,
        )
    except (subprocess.CalledProcessError, ValueError):
        print(
            "reference-policy: cannot determine changes; check the base/head revisions",
            file=sys.stderr,
        )
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print("Use generic names and synthetic examples. Do not add inline suppressions.")
    return int(bool(findings))


if __name__ == "__main__":
    sys.exit(main())
