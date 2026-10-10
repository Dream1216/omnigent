from __future__ import annotations

import copy

import pytest

from saas.scripts.compare_elf_exports import compare


def library():
    return {
        "sha256": "a" * 64,
        "identity": {"Class": "ELF64", "Data": "little endian", "Machine": "x86-64"},
        "soname": "libcurl-gnutls.so.4",
        "exports": {"curl_easy_init@@CURL_GNUTLS_3": {"type": "FUNC", "size": 123}},
    }


def test_additive_exports_are_partial_proof_only() -> None:
    baseline = library()
    candidate = copy.deepcopy(baseline)
    candidate["exports"]["new_function@@CURL_GNUTLS_3"] = {"type": "FUNC", "size": 20}
    report = compare(baseline, candidate)
    assert report["status"] == "pass"
    assert report["production_admission"] is False
    assert "typed-ABI-comparison" in report["required_followup"]


@pytest.mark.parametrize("field", ["soname", "identity", "exports"])
def test_incompatible_library_fails(field) -> None:
    baseline = library()
    candidate = copy.deepcopy(baseline)
    candidate[field] = {} if field != "soname" else "libcurl.so.4"
    assert compare(baseline, candidate)["status"] == "fail"


def test_symbol_version_change_is_not_hidden() -> None:
    baseline = library()
    candidate = copy.deepcopy(baseline)
    candidate["exports"] = {"curl_easy_init@@CURL_GNUTLS_4": {"type": "FUNC", "size": 123}}
    assert compare(baseline, candidate)["missing_exports"] == ["curl_easy_init@@CURL_GNUTLS_3"]


def test_old_nondefault_alias_preserves_versioned_binding() -> None:
    baseline = library()
    candidate = copy.deepcopy(baseline)
    candidate["exports"] = {
        "curl_easy_init@CURL_GNUTLS_3": {"type": "FUNC", "size": 150},
        "curl_easy_init@@CURL_GNUTLS_4": {"type": "FUNC", "size": 150},
    }
    report = compare(baseline, candidate)
    assert report["status"] == "pass"
    assert report["missing_exports"] == []
    assert report["changed_default_exports"] == ["curl_easy_init@@CURL_GNUTLS_3"]
    assert report["production_admission"] is False


def test_old_alias_data_size_change_still_fails() -> None:
    baseline = library()
    baseline["exports"] = {"state@@V1": {"type": "OBJECT", "size": 8}}
    candidate = copy.deepcopy(baseline)
    candidate["exports"] = {"state@V1": {"type": "OBJECT", "size": 16}}
    assert compare(baseline, candidate)["status"] == "fail"
