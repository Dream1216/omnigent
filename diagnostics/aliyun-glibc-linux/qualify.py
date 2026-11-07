"""Run the original Debian glibc build with an explicit negative control."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROBE = Path(__file__).resolve().parent
PINS = json.loads((PROBE / "pins.json").read_text())
WORK = Path("/work")
SOURCE = WORK / "glibc"
TARGET = "intl/tst-gettext-path-traversal"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def material_patch(variant: str) -> Path:
    document = json.loads((PROBE / "candidate-patch.json").read_text())
    body = "".join(document["lines"])
    assert hashlib.sha256(body.encode()).hexdigest() == PINS["candidate_sha256"]
    if variant == "control":
        selected = {
            "a/intl/Makefile b/intl/Makefile",
            "a/intl/tst-gettext-path-traversal.c b/intl/tst-gettext-path-traversal.c",
        }
        body = "".join(
            "diff --git " + part
            for part in body.split("diff --git ")[1:]
            if part.splitlines()[0] in selected
        )
    assert hashlib.sha256(body.encode()).hexdigest() == PINS[f"{variant}_sha256"]
    path = WORK / f"{variant}.patch"
    path.write_text(body)
    return path


def command(args: list[str], log: Path, *, cwd: Path = WORK, env=None) -> int:
    with log.open("wb") as handle:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT)
    if result.returncode:
        print(f"Command failed ({result.returncode}); full log: {log}", file=sys.stderr)
        print(log.read_text(errors="replace")[-4000:], file=sys.stderr)
    return result.returncode


def prepare() -> None:
    WORK.mkdir(exist_ok=True)
    assert digest(PROBE / "debian-signer.gpg") == PINS["keyring_sha256"]
    assert digest(PROBE / "glibc_2.43-7.dsc") == PINS["dsc_sha256"]
    for variant in ("candidate", "control"):
        material_patch(variant)
    shutil.copy2(PROBE / "glibc_2.43-7.dsc", WORK)
    home = WORK / "gpg-home"
    home.mkdir(mode=0o700)
    signature = WORK / "source-signature.log"
    assert (
        command(
            [
                "gpgv",
                "--homedir",
                str(home),
                "--keyring",
                str(PROBE / "debian-signer.gpg"),
                "--status-fd",
                "1",
                str(WORK / "glibc_2.43-7.dsc"),
            ],
            signature,
        )
        == 0
    )
    status = signature.read_text()
    valid = [line for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    assert len(valid) == 1
    assert valid[0].split()[2] == PINS["signing_fingerprint"]
    assert valid[0].split()[-1] == PINS["primary_fingerprint"]
    assert not any(token in status for token in ("BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG"))
    for material in PINS["source_archives"]:
        path = WORK / material["name"]
        assert (
            command(
                [
                    "curl",
                    "--fail",
                    "--location",
                    "--show-error",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--retry",
                    "2",
                    "--max-time",
                    "180",
                    "--output",
                    str(path),
                    "https://deb.debian.org/debian/pool/main/g/glibc/" + material["name"],
                ],
                WORK / (material["name"] + ".download.log"),
            )
            == 0
        )
        assert path.stat().st_size == material["size"] and digest(path) == material["sha256"]
    help_text = subprocess.check_output(["dpkg-source", "--help"], text=True)
    certs = (
        ["--no-vendor-certs", "--signer-certs=" + str(PROBE / "debian-signer.gpg")]
        if "--signer-certs" in help_text
        else ["--keyring=" + str(PROBE / "debian-signer.gpg")]
    )
    assert (
        command(
            [
                "dpkg-source",
                *certs,
                "--require-valid-signature",
                "--require-strong-checksums",
                "--extract",
                str(WORK / "glibc_2.43-7.dsc"),
                str(SOURCE),
            ],
            WORK / "strict-source-extraction.log",
        )
        == 0
    )
    applied = (SOURCE / ".pc/applied-patches").read_text().splitlines()
    assert len(applied) == PINS["vendor_series_patches"] == 84
    for name, expected in PINS["baseline_target_sha256"].items():
        assert digest(SOURCE / name) == expected
    (WORK / "authenticated-inputs.json").write_text(
        json.dumps(
            {
                "source_version": PINS["source_version"],
                "vendor_patches_applied": len(applied),
                "signature_status_sha256": digest(signature),
                "pins_sha256": digest(PROBE / "pins.json"),
                "source_keyring_sha256": PINS["keyring_sha256"],
                "signature_verified": True,
                "all_archives_verified": True,
                "production_admission": False,
            },
            indent=2,
        )
        + "\n"
    )


def symbols(library: Path) -> list[str]:
    text = subprocess.check_output(["readelf", "--dyn-syms", "--wide", str(library)], text=True)
    exported = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[4] in {"GLOBAL", "WEAK"} and fields[6] != "UND":
            if fields[5] in {"DEFAULT", "PROTECTED"}:
                exported.add(fields[7])
    assert exported
    return sorted(exported)


def collect_tests(evidence: Path) -> dict:
    suites = {}
    for path in sorted((SOURCE / "build-tree").glob("*/tests.sum")):
        name = path.parent.name
        records = []
        for line in path.read_text().splitlines():
            status, separator, test = line.partition(": ")
            if separator and status in {
                "PASS",
                "FAIL",
                "XFAIL",
                "XPASS",
                "UNSUPPORTED",
                "UNRESOLVED",
            }:
                records.append({"status": status, "test": test})
        assert records
        counts = dict(Counter(row["status"] for row in records))
        suites[name] = {"counts": counts, "records": records, "sha256": digest(path)}
        shutil.copy2(path, evidence / (name + ".tests.sum"))
        for row in records:
            if row["status"] in {"FAIL", "XPASS", "UNRESOLVED"} or row["test"] == TARGET:
                for suffix in (".test-result", ".out"):
                    detail = path.parent / (row["test"] + suffix)
                    if detail.is_file():
                        target = evidence / "test-details" / name / (row["test"] + suffix)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(detail, target)
    return suites


def run(variant: str, evidence: Path) -> None:
    assert variant in {"control", "candidate"}
    assert os.getuid() == 1000
    assert not os.environ.get("DEB_BUILD_PROFILES")
    assert os.environ.get("DEB_BUILD_OPTIONS", "") in {"", "parallel=2"}
    evidence.mkdir(parents=True, exist_ok=True)
    result = {
        "at_utc": datetime.now(timezone.utc).isoformat(),
        "variant": variant,
        "component_only": True,
        "production_admission": False,
        "full_Host_or_cloud_acceptance": False,
        "raw_Gen2_Host_13High_not_reduced": True,
        "upstream_accepted_fix_not_proven": True,
        "passed": False,
        "source_version": PINS["source_version"],
        "build_profiles": [],
        "build_options": "parallel=2",
        "source_pins_sha256": digest(PROBE / "pins.json"),
    }
    try:
        for name, args in {
            "kernel": ["uname", "-a"],
            "compiler": ["gcc-15", "--version"],
            "installed-packages": ["dpkg-query", "-W"],
        }.items():
            assert command(args, evidence / f"environment-{name}.log") == 0
        shutil.copy2(WORK / "authenticated-inputs.json", evidence)
        shutil.copy2(WORK / "source-signature.log", evidence)
        shutil.copy2(WORK / "strict-source-extraction.log", evidence)
        baseline = symbols(Path("/lib/x86_64-linux-gnu/libc.so.6"))
        (evidence / "official-baseline-exported-symbols.json").write_text(
            json.dumps(baseline) + "\n"
        )
        patch = material_patch(variant)
        assert digest(patch) == PINS[f"{variant}_sha256"]
        assert (
            command(
                ["git", "apply", "--check", str(patch)],
                evidence / "strict-patch-check.log",
                cwd=SOURCE,
            )
            == 0
        )
        destination = SOURCE / "debian/patches/omnigent-diagnostic.patch"
        shutil.copy2(patch, destination)
        with (SOURCE / "debian/patches/series").open("a") as handle:
            handle.write("\nomnigent-diagnostic.patch\n")
        assert (
            command(
                ["dpkg-source", "--before-build", str(SOURCE)],
                evidence / "diagnostic-quilt-application.log",
            )
            == 0
        )
        assert len((SOURCE / ".pc/applied-patches").read_text().splitlines()) == 85
        if variant == "control":
            assert (
                digest(SOURCE / "intl/dcigettext.c")
                == PINS["baseline_target_sha256"]["intl/dcigettext.c"]
            )
        changelog = SOURCE / "debian/changelog"
        original = changelog.read_text()
        date = subprocess.check_output(
            ["dpkg-parsechangelog", "-l", str(changelog), "-S", "Date"], text=True
        ).strip()
        epoch = subprocess.check_output(
            ["dpkg-parsechangelog", "-l", str(changelog), "-S", "Timestamp"], text=True
        ).strip()
        version = "2.43-7+omnigentdiag" + variant + "1"
        entry = (
            f"glibc ({version}) UNRELEASED; urgency=medium\n\n"
            f"  * Private {variant} diagnostic; upstream proposal acceptance not claimed.\n\n"
            f" -- Omnigent diagnostic <noreply@users.noreply.github.com>  {date}\n\n"
        )
        changelog.write_text(entry + original)
        result["diagnostic_package_version"] = version
        result["source_date_epoch"] = int(epoch)
        env = dict(os.environ, DEB_BUILD_OPTIONS="parallel=2", SOURCE_DATE_EPOCH=epoch)
        args = ["dpkg-buildpackage", "-b", "--no-sign", "-j2"]
        result["build_command"] = args
        code = command(args, evidence / "complete-debian-build.log", cwd=SOURCE, env=env)
        result["debian_build_exit_code"] = code
        suites = collect_tests(evidence)
        result["full_original_suites"] = suites
        assert "amd64-libc" in suites, "No complete native test summary"
        unexpected = [
            (name, row["test"], row["status"])
            for name, suite in suites.items()
            for row in suite["records"]
            if row["status"] in {"FAIL", "XPASS", "UNRESOLVED"}
        ]
        result["unexpected_or_control_failures"] = unexpected
        native = suites["amd64-libc"]["records"]
        cve = [row["status"] for row in native if row["test"] == TARGET]
        assert cve == (["FAIL"] if variant == "control" else ["PASS"]), cve
        if variant == "candidate":
            assert code == 0 and not unexpected
        else:
            assert code != 0 and unexpected
            assert all(test == TARGET and status == "FAIL" for _, test, status in unexpected)
        built = SOURCE / "build-tree/amd64-libc"
        current = symbols(built / "libc.so")
        (evidence / "built-exported-symbols.json").write_text(json.dumps(current) + "\n")
        result["removed_exported_symbols"] = sorted(set(baseline) - set(current))
        result["added_exported_symbols"] = sorted(set(current) - set(baseline))
        assert current == baseline, "Unexpected ABI difference"
        result["native_exported_symbol_count"] = len(current)
        loader = built / "elf/ld.so"
        consumers = [
            ["/bin/bash", "-c", "printf '中文\\n' | /usr/bin/grep -q ."],
            [
                "/usr/bin/python3",
                "-c",
                "import ctypes,datetime,json,locale,os,subprocess; c=ctypes.CDLL(None); "
                "c.gnu_get_libc_version.restype=ctypes.c_char_p; "
                "assert c.gnu_get_libc_version()==b'2.43'; "
                f"assert {str(built)!r} in open('/proc/self/maps').read(); "
                "assert subprocess.check_output(['/bin/echo','中文']).decode().strip()=='中文'; "
                "json.loads(json.dumps({'路径':'中文'})); "
                "datetime.datetime.now(); print('consumer-ok')",
            ],
            ["/usr/bin/getent", "passwd", "builder"],
            ["/usr/bin/iconv", "--version"],
        ]
        for index, args in enumerate(consumers):
            assert (
                command(
                    [str(loader), "--library-path", str(built), *args],
                    evidence / f"consumer-{index}.log",
                    env=dict(env, LD_LIBRARY_PATH=str(built)),
                )
                == 0
            )
        result["real_dynamic_loader_consumers_passed"] = [args[0] for args in consumers]
        result["native_libc_sha256"] = digest(built / "libc.so")
        result["native_loader_sha256"] = digest(loader)
        result["built_package_checksums"] = {
            path.name: digest(path) for path in WORK.glob("*.deb")
        }
        result["passed"] = True
    except BaseException as error:
        result["error"] = repr(error)
        raise
    finally:
        for path in WORK.glob("*.buildinfo"):
            shutil.copy2(path, evidence)
        for path in WORK.glob("*.changes"):
            shutil.copy2(path, evidence)
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":

    def interrupted(signum, _frame):
        raise RuntimeError(f"Diagnostic interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "run"])
    parser.add_argument("--variant", choices=["control", "candidate"])
    parser.add_argument("--evidence", type=Path)
    options = parser.parse_args()
    if options.mode == "prepare":
        prepare()
    else:
        assert options.variant and options.evidence
        run(options.variant, options.evidence)
