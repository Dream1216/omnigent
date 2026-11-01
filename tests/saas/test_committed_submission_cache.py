"""Private committed-input receipts remain scoped, bounded and expiring."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from omnigent.runtime import pending_inputs


@pytest.fixture(autouse=True)
def _clean_pending_inputs_index() -> Iterator[None]:
    """
    Reset the module-global pending-inputs dict between tests.

    The index is process-global; without this fixture a leaked entry
    would change the snapshot/match behavior of every later test.
    """
    pending_inputs.reset_for_tests()
    yield
    pending_inputs.reset_for_tests()


def test_committed_submission_is_scoped_bounded_and_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"t": 1000.0}
    monkeypatch.setattr(pending_inputs, "_now", lambda: clock["t"])
    stable = "c" * 32

    assert pending_inputs.committed_item_id("conv_a", stable) is None
    pending_inputs.remember_committed("conv_a", stable, "item_1")
    assert pending_inputs.committed_item_id("conv_a", stable) == "item_1"
    assert pending_inputs.committed_item_id("conv_b", stable) is None

    for number in range(pending_inputs._COMMITTED_MAX_PER_CONVERSATION):
        pending_inputs.remember_committed("conv_a", f"{number:032x}", f"item_{number}")
    assert pending_inputs.committed_item_id("conv_a", stable) is None
    assert pending_inputs.committed_item_id("conv_a", f"{255:032x}") == "item_255"

    clock["t"] += pending_inputs._COMMITTED_TTL_S + 0.1
    assert pending_inputs.committed_item_id("conv_a", f"{255:032x}") is None
