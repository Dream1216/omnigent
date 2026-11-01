"""Run release-verified identity ingress and reconciliation with no IdP admin key."""

from __future__ import annotations

import sys

from saas.production.identity_process_config import load_identity_worker_config
from saas.production.identity_process_server import run_private_identity_app
from saas.production.identity_sync_server import build_identity_sync_server


def main() -> None:
    sessions = None
    try:
        config = load_identity_worker_config()
        app, sessions = build_identity_sync_server(config)
        run_private_identity_app(app, tls=config.tls)
    except Exception:  # noqa: BLE001 - never print database driver parameters or credentials.
        print("identity sync startup rejected", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        if sessions is not None:
            try:
                sessions.close()
            except Exception:  # noqa: BLE001 - teardown has the same secret boundary.
                print("identity sync shutdown failed", file=sys.stderr)
                raise SystemExit(1) from None


if __name__ == "__main__":
    main()
