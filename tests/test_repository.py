from datetime import UTC, datetime, timedelta

import pytest

from app.repository import IdempotencyConflict, StateRepository
from tests.helpers import execution


def test_duplicate_suppression_and_payload_conflict(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    request = execution()
    assert repository.begin_execution(request, "a" * 64) == (None, False)
    assert repository.begin_execution(request, "a" * 64)[1] is True
    with pytest.raises(IdempotencyConflict):
        repository.begin_execution(request.model_copy(update={"employee_id": "other"}), "b" * 64)


def test_atomic_claim_and_restart_recovery(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    request = execution()
    repository.begin_execution(request, "a" * 64)
    claimed = repository.claim_next(request.request_id)
    assert claimed is not None
    assert repository.claim_next(request.request_id) is None
    assert repository.recover_stale(0) == 1
    assert repository.claim_next(request.request_id) is not None


def test_replay_and_rate_state_are_durable(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    expiration = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    assert repository.accept_jti("once", expiration)
    assert not repository.accept_jti("once", expiration)
    assert repository.check_rate("service", 2, 60)
    assert repository.check_rate("service", 2, 60)
    assert not repository.check_rate("service", 2, 60)


def test_callback_retries_are_bounded(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    repository.enqueue_callback("event-1", {"state": "completed"})
    for _ in range(8):
        repository.mark_callback(
            "event-1",
            False,
            "transport_error",
            datetime.now(UTC),
        )
    assert repository.due_callbacks() == []
    assert repository.counts()["failed_callbacks"] == 1
