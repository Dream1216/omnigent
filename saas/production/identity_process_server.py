"""Direct TLS serving for private identity processes without forwarded-header trust."""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from saas.production.identity_process_config import IdentityProcessTls


def create_private_identity_server(
    app: FastAPI, *, tls: IdentityProcessTls, host: str = "0.0.0.0", port: int = 8443
) -> uvicorn.Server:
    if (
        host not in {"0.0.0.0", "127.0.0.1", "::"}
        or type(port) is not int
        or not 1 <= port <= 65535
    ):
        raise ValueError("private identity bind settings are invalid")
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        http="h11",
        ws="none",
        proxy_headers=False,
        access_log=False,
        server_header=False,
        ssl_certfile=str(tls.certificate),
        ssl_keyfile=str(tls.private_key),
        limit_concurrency=64,
        h11_max_incomplete_event_size=16384,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=30,
        log_config=None,
    )
    return uvicorn.Server(config)


def run_private_identity_app(app: FastAPI, *, tls: IdentityProcessTls) -> None:
    create_private_identity_server(app, tls=tls).run()
