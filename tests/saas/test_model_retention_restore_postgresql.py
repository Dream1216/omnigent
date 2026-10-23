from __future__ import annotations

import json
import os

import pytest

from tests.saas.postgresql_retention import assert_owned_model_backup_restore
from tests.saas.test_model_run_inference_postgresql import (
    _exercise_run_inference,
)
from tests.saas.test_model_run_inference_postgresql import (
    funded_publication as funded_publication,
)
from tests.saas.test_model_run_inference_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_inference_postgresql import (
    priced_execution as priced_execution,
)
from tests.saas.test_model_run_inference_postgresql import (
    publication_protocol as publication_protocol,
)


@pytest.mark.parametrize("unknown", [False, True], ids=["known-ack-lost", "unknown-hold"])
def test_owned_model_database_backup_preserves_nonempty_facts_and_authority(
    interactive_postgresql, tmp_path, record_property, unknown
):
    if os.environ.get("OMNIGENT_SAAS_TEST_ALLOW_DISPOSABLE_RESTORE") != "true":
        pytest.skip("requires an explicitly owned local TLS PostgreSQL restore fixture")
    snapshots = {}

    def checkpoint(phase, engine):
        snapshots[phase] = assert_owned_model_backup_restore(engine, tmp_path / phase)

    _exercise_run_inference(
        interactive_postgresql,
        tmp_path,
        True,
        unknown_retention={} if unknown else None,
        retained_checkpoint=checkpoint,
    )
    assert set(snapshots) == (
        {"known_ack_lost", "unknown_hold"} if unknown else {"known_ack_lost"}
    )
    record_property("actual_model_backup_restore", json.dumps(snapshots, sort_keys=True))
