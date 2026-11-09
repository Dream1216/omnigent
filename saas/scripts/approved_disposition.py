"""One finite classifier shared by the existing scan/promotion/signed chain."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from saas.scripts.combined_runtime_disposition import inspect_combined_disposition
from saas.scripts.scan_oci_candidates import scan_report
from saas.scripts.sqlite_component_disposition import inspect_disposition


def inspect_approved_disposition(
    image: Path,
    report: Path,
    *,
    platform: str,
    now: datetime,
    database_age_disposition: object = None,
) -> dict[str, Any]:
    counts = scan_report(json.loads(report.read_bytes()))["counts"]
    if counts == {"Critical": 0, "High": 2}:
        return inspect_combined_disposition(
            image,
            report,
            platform=platform,
            now=now,
            scanner_exit=2,
            database_age_disposition=database_age_disposition,
        )
    return inspect_disposition(
        image,
        report,
        platform=platform,
        now=now,
        database_age_disposition=database_age_disposition,
    )
