from datetime import UTC, datetime, timedelta

import pytest

from app.contracts import Operation, StepState, TargetSystem
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


def test_expired_active_sip_session_does_not_block_replacement(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    values = {
        "session_id": "old-session",
        "employee_id": "employee-0001",
        "keycloak_subject": "subject",
        "odoo_employee_id": "employee-0001",
        "vicidial_username": "synthetic_agent",
        "endpoint": 6101,
        "campaign": "TEST_SYN",
        "role": "AGENT",
        "browser_session_binding": "binding",
        "credential_fingerprint": "fingerprint",
        "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
    }
    repository.create_sip_browser_session(values)
    assert repository.active_sip_browser_session(values["employee_id"]) is None
    assert repository.sip_browser_session(values["session_id"])["state"] == "expired"


def test_command_views_keep_canonical_binding_and_newest_verification_step(tmp_path):
    repository = StateRepository(str(tmp_path / "state.db"))
    created = execution(steps=2)
    created_steps = [
        step.model_copy(update={"payload": {"binding": "canonical"}})
        for step in created.steps
    ]
    created = created.model_copy(update={"steps": created_steps})
    repository.begin_execution(created, "a" * 64)
    for step in created_steps:
        repository.complete_step(step.step_id, StepState.SUCCEEDED, {})
    newest = repository.successful_commands(created.request_id)
    assert [step.sequence for step in newest] == [1]

    updated = execution(
        request_id="request-00000002",
        key="idempotency-key-00000002",
        target=TargetSystem.ODOO,
        operation=Operation.UPDATE,
    )
    updated = updated.model_copy(
        update={"steps": [updated.steps[0].model_copy(update={"payload": {"partial": True}})]}
    )
    repository.begin_execution(updated, "b" * 64)
    repository.complete_step(updated.steps[0].step_id, StepState.SUCCEEDED, {})
    command = repository.employee_commands(created.employee_id)[0]
    assert command.operation == Operation.CREATE_DISABLED
    assert command.payload == {"binding": "canonical"}
