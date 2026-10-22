"""Managed Runner entrypoint that installs metering before official startup."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from omnigent.runner._entry import main as official_runner_main
from omnigent.runner.identity import RUNNER_ID_ENV_VAR
from saas.runner_adapter.metering import (
    MANAGED_METERING_ENVELOPE_ENV_VAR,
    ManagedMeteringError,
    ProviderUsageMeter,
    build_metering_client,
    consume_metering_envelope,
)


def main() -> None:
    envelope_value = os.environ.pop(MANAGED_METERING_ENVELOPE_ENV_VAR, None)
    official_runner_id = os.environ.get(RUNNER_ID_ENV_VAR, "")
    if not envelope_value or not official_runner_id:
        raise ManagedMeteringError(
            "managed_metering_envelope_missing",
            "managed Runner requires a one-time metering envelope",
        )
    grant = consume_metering_envelope(Path(envelope_value), official_runner_id=official_runner_id)
    client = build_metering_client(grant)
    try:
        meter = ProviderUsageMeter(grant=grant, client=client)
    except BaseException:
        client.close()
        raise
    try:
        official_runner_main()
    finally:
        delivery_complete = meter.close()
        if not delivery_complete and sys.exc_info()[0] is None:
            raise ManagedMeteringError(
                "managed_metering_delivery_incomplete",
                "managed Runner stopped with undelivered usage",
            )


if __name__ == "__main__":
    main()
