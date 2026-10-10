from pathlib import Path


def test_curl_source_tests_keep_fd_exhaustion_bounded_and_nonroot() -> None:
    recipe = (
        Path(__file__).resolve().parents[2] / "saas/supply_chain/curl-source-build/Dockerfile"
    ).read_text()
    assert "su -s /bin/sh curltest" in recipe
    assert "ulimit -n 65536 && make test-nonflaky" in recipe
    assert "--enable-ntlm" in recipe
    assert "nghttp2-proxy" in recipe
