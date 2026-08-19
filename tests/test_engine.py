import asyncio
import sqlite3
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet

from app.adapters import SecretStorageAdapter
from app.callbacks import CallbackDispatcher
from app.config import Settings
from app.contracts import Operation, StepState, TargetSystem
from app.engine import EngineError, ProvisioningEngine
from app.repository import StateRepository
from tests.helpers import (
    FakeAdapter,
    PermanentAdapterError,
    RetryableAdapterError,
    action,
    execution,
)


def settings(tmp_path) -> Settings:
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("x")
    return Settings(
        environment="staging",
        state_database_path=str(tmp_path / "state.db"),
        jwt_issuer="https://issuer.invalid/realms/codestra",
        jwt_audience="codestra-provisioning-service",
        jwt_public_key_file=str(placeholder),
        jwt_algorithms=("RS256",),
        jwt_allowed_clients=frozenset({"test-service"}),
        request_max_bytes=65536,
        request_max_age_seconds=300,
        rate_limit_requests=100,
        rate_limit_window_seconds=60,
        claim_timeout_seconds=0,
        retry_base_seconds=0,
        callback_url=None,
        callback_hmac_file=str(placeholder),
        encryption_key_file=str(placeholder),
        adapter_config_file=str(placeholder),
        tls_cert_file=str(placeholder),
        tls_key_file=str(placeholder),
    )


def engine(tmp_path, adapter):
    repository = StateRepository(str(tmp_path / "state.db"))
    configured = settings(tmp_path)
    callbacks = CallbackDispatcher(None, configured.callback_hmac_file, repository)
    return ProvisioningEngine(
        {TargetSystem.ODOO.value: adapter}, repository, configured, callbacks
    )


@pytest.mark.asyncio
async def test_bounded_retry_and_step_only_retry(tmp_path):
    adapter = FakeAdapter([RetryableAdapterError("timeout")])
    service = engine(tmp_path, adapter)
    request = execution()
    first = await service.submit(request.request_id, request)
    assert first.state == "retry_wait"
    retried = await service.retry(
        request.request_id, action(request.request_id, Operation.UPDATE)
    )
    assert retried.state == "completed"
    assert retried.step_results[0].attempt_count == 2
    callback_count = service.repository._connection.execute(
        "SELECT count(*) FROM callback_events"
    ).fetchone()[0]
    assert callback_count == 2
    replayed = await service.retry(
        request.request_id, action(request.request_id, Operation.UPDATE)
    )
    assert replayed.replayed
    callback_count = service.repository._connection.execute(
        "SELECT count(*) FROM callback_events"
    ).fetchone()[0]
    assert callback_count == 3


@pytest.mark.asyncio
async def test_permanent_failure_dead_letters_without_delete_compensation(tmp_path):
    adapter = FakeAdapter([PermanentAdapterError("rejected")])
    service = engine(tmp_path, adapter)
    request = execution()
    result = await service.submit(request.request_id, request)
    assert result.state == "dead_letter"
    assert result.step_results[0].state == StepState.DEAD_LETTER
    assert all(call.operation != Operation.TERMINATE for call in adapter.calls)
    assert service.repository.counts()["dead_letters"] == 1


@pytest.mark.asyncio
async def test_partial_failure_uses_suspend_not_delete(tmp_path):
    adapter = FakeAdapter([None, PermanentAdapterError("later_failed")])
    original_call = adapter.call

    async def call(command):
        if adapter.failures and adapter.failures[0] is None:
            adapter.failures.pop(0)
            adapter.calls.append(command)
            return {"state": "succeeded", "external_id": "created-disabled"}
        return await original_call(command)

    adapter.create_disabled = call
    adapter.update = call
    adapter.suspend = call
    service = engine(tmp_path, adapter)
    request = execution(steps=2)
    result = await service.submit(request.request_id, request)
    assert result.state == "dead_letter"
    assert any(
        item.operation == Operation.UPDATE
        and item.payload.get("compensation") == "remove_excess_access"
        for item in adapter.calls
    )
    assert Operation.TERMINATE not in [item.operation for item in adapter.calls]


@pytest.mark.asyncio
async def test_idempotent_execution_replays_result(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    request = execution()
    first = await service.submit(request.request_id, request)
    second = await service.submit(request.request_id, request)
    assert first.state == "completed"
    assert second.replayed
    assert len(adapter.calls) == 1


@pytest.mark.asyncio
async def test_verification_and_reconciliation_preserve_adapter_identifiers(
    tmp_path,
):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    request = execution()
    original = request.steps[0].model_copy(
        update={"payload": {"username": "synthetic-user"}}
    )
    request = request.model_copy(update={"steps": [original]})
    await service.submit(request.request_id, request)
    await service.verify(
        request.request_id, action(request.request_id, Operation.VERIFY)
    )
    await service.reconcile(
        request.employee_id,
        action(request.request_id, Operation.RECONCILE).model_copy(
            update={"employee_id": request.employee_id}
        ),
    )
    verification = next(
        item for item in adapter.calls if item.operation == Operation.VERIFY
    )
    reconciliation = next(
        item for item in adapter.calls if item.operation == Operation.RECONCILE
    )
    assert verification.payload["username"] == "synthetic-user"
    assert reconciliation.payload["username"] == "synthetic-user"


@pytest.mark.asyncio
async def test_lifecycle_carries_forward_provider_identity_payload(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    original = execution()
    original = original.model_copy(
        update={
            "steps": [
                original.steps[0].model_copy(
                    update={
                        "payload": {
                            "username": "synthetic-user",
                            "extension": 6197,
                        }
                    }
                )
            ]
        }
    )
    await service.submit(original.request_id, original)
    lifecycle = execution(
        request_id="lifecycle-suspend-0001",
        employee_id=original.employee_id,
        key="lifecycle-idempotency-0001",
        operation=Operation.SUSPEND,
    )
    await service.lifecycle(
        original.employee_id, Operation.SUSPEND, lifecycle
    )
    suspended = adapter.calls[-1]
    assert suspended.operation == Operation.SUSPEND
    assert suspended.payload == {
        "username": "synthetic-user",
        "extension": 6197,
    }


@pytest.mark.asyncio
async def test_activation_requires_durable_mandatory_verification(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    created = execution()
    await service.submit(created.request_id, created)

    activation = execution(
        request_id="activation-request-0001",
        employee_id=created.employee_id,
        key="activation-idempotency-0001",
        operation=Operation.ACTIVATE,
    )
    with pytest.raises(EngineError, match="mandatory_verification_incomplete"):
        await service.submit(activation.request_id, activation)

    verification = await service.verify(
        created.request_id,
        action(created.request_id, Operation.VERIFY),
    )
    assert verification.state == "verified"
    activated = await service.submit(activation.request_id, activation)
    assert activated.state == "completed"

    restarted = ProvisioningEngine(
        {TargetSystem.ODOO.value: adapter},
        StateRepository(str(tmp_path / "state.db")),
        service.settings,
        service.callback_dispatcher,
    )
    replay = await restarted.submit(activation.request_id, activation)
    assert replay.replayed


@pytest.mark.asyncio
async def test_activation_requires_verification_for_each_requested_target(tmp_path):
    adapter = FakeAdapter()
    repository = StateRepository(str(tmp_path / "state.db"))
    configured = settings(tmp_path)
    service = ProvisioningEngine(
        {
            TargetSystem.ODOO.value: adapter,
            TargetSystem.KEYCLOAK.value: adapter,
        },
        repository,
        configured,
        CallbackDispatcher(None, configured.callback_hmac_file, repository),
    )
    created = execution()
    await service.submit(created.request_id, created)
    await service.verify(
        created.request_id, action(created.request_id, Operation.VERIFY)
    )
    activation = execution(
        request_id="unprovisioned-target-activation-0001",
        employee_id=created.employee_id,
        key="unprovisioned-target-activation-key",
        operation=Operation.ACTIVATE,
    )
    activation = activation.model_copy(
        update={
            "steps": [
                activation.steps[0].model_copy(
                    update={"target_system": TargetSystem.KEYCLOAK}
                )
            ]
        }
    )
    calls_before = len(adapter.calls)
    with pytest.raises(EngineError) as denied:
        await service.submit(activation.request_id, activation)
    assert denied.value.code == "mandatory_verification_incomplete"
    assert len(adapter.calls) == calls_before


@pytest.mark.asyncio
async def test_activation_serializes_against_new_mandatory_employee_update(tmp_path):
    class BlockingUpdateAdapter(FakeAdapter):
        def __init__(self):
            super().__init__()
            self.update_started = asyncio.Event()
            self.release_update = asyncio.Event()

        async def update(self, command):
            self.calls.append(command)
            self.update_started.set()
            await self.release_update.wait()
            return {"state": "succeeded", "external_id": "updated"}

    adapter = BlockingUpdateAdapter()
    service = engine(tmp_path, adapter)
    created = execution()
    await service.submit(created.request_id, created)
    await service.verify(
        created.request_id, action(created.request_id, Operation.VERIFY)
    )
    update = execution(
        request_id="concurrent-update-0001",
        employee_id=created.employee_id,
        key="concurrent-update-idempotency",
        operation=Operation.UPDATE,
    )
    activation = execution(
        request_id="concurrent-activation-0001",
        employee_id=created.employee_id,
        key="concurrent-activation-idempotency",
        operation=Operation.ACTIVATE,
    )
    update_task = asyncio.create_task(service.submit(update.request_id, update))
    await adapter.update_started.wait()
    activation_task = asyncio.create_task(
        service.submit(activation.request_id, activation)
    )
    await asyncio.sleep(0)
    assert not activation_task.done()
    adapter.release_update.set()
    await update_task
    with pytest.raises(EngineError, match="mandatory_verification_incomplete"):
        await activation_task


@pytest.mark.asyncio
async def test_stale_verification_is_reported_as_conflict(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    created = execution()
    await service.submit(created.request_id, created)
    await service.verify(
        created.request_id, action(created.request_id, Operation.VERIFY)
    )
    update = execution(
        request_id="newer-update-0001",
        employee_id=created.employee_id,
        key="newer-update-idempotency",
        operation=Operation.UPDATE,
    )
    await service.submit(update.request_id, update)
    await service.verify(update.request_id, action(update.request_id, Operation.VERIFY))
    before = service.repository._connection.execute(
        "SELECT source_step_id,evidence_hash FROM verification_records"
    ).fetchone()
    with pytest.raises(EngineError) as stale:
        await service.verify(
            created.request_id, action(created.request_id, Operation.VERIFY)
        )
    assert stale.value.status_code == 409
    assert stale.value.code == "stale_verification_conflict"
    after = service.repository._connection.execute(
        "SELECT source_step_id,evidence_hash FROM verification_records"
    ).fetchone()
    assert tuple(after) == tuple(before)


@pytest.mark.asyncio
async def test_mixed_update_and_activation_execution_is_rejected(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    created = execution()
    await service.submit(created.request_id, created)
    await service.verify(
        created.request_id, action(created.request_id, Operation.VERIFY)
    )
    mixed = execution(
        request_id="mixed-activation-0001",
        employee_id=created.employee_id,
        key="mixed-activation-idempotency",
        operation=Operation.UPDATE,
        steps=2,
    )
    mixed = mixed.model_copy(
        update={
            "steps": [
                mixed.steps[0],
                mixed.steps[1].model_copy(update={"operation": Operation.ACTIVATE}),
            ]
        }
    )
    with pytest.raises(EngineError) as rejected:
        await service.submit(mixed.request_id, mixed)
    assert rejected.value.status_code == 422
    assert rejected.value.code == "mixed_activation_execution_forbidden"
    assert service.repository.request_result(mixed.request_id) is None


@pytest.mark.asyncio
async def test_optional_step_does_not_make_mandatory_verification_stale(tmp_path):
    adapter = FakeAdapter()
    repository = StateRepository(str(tmp_path / "state.db"))
    configured = settings(tmp_path)
    callbacks = CallbackDispatcher(None, configured.callback_hmac_file, repository)
    service = ProvisioningEngine(
        {
            TargetSystem.ODOO.value: adapter,
            TargetSystem.KEYCLOAK.value: adapter,
        },
        repository,
        configured,
        callbacks,
    )
    request = execution(steps=2)
    request = request.model_copy(
        update={
            "steps": [
                request.steps[0],
                request.steps[1].model_copy(
                    update={"target_system": TargetSystem.KEYCLOAK, "mandatory": False}
                ),
            ]
        }
    )
    assert (await service.submit(request.request_id, request)).state == "completed"
    result = await service.verify(
        request.request_id, action(request.request_id, Operation.VERIFY)
    )
    assert result.state == "verified"
    record = repository._connection.execute(
        "SELECT source_step_id FROM verification_records WHERE target_system='odoo'"
    ).fetchone()
    assert record["source_step_id"] == request.steps[0].step_id


@pytest.mark.asyncio
async def test_newer_optional_step_cannot_hide_mandatory_verification(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    request = execution(steps=2)
    request = request.model_copy(
        update={
            "steps": [
                request.steps[0],
                request.steps[1].model_copy(update={"mandatory": False}),
            ]
        }
    )
    assert (await service.submit(request.request_id, request)).state == "completed"
    verified = await service.verify(
        request.request_id, action(request.request_id, Operation.VERIFY)
    )
    assert verified.state == "verified"
    record = service.repository._connection.execute(
        "SELECT source_step_id FROM verification_records WHERE target_system='odoo'"
    ).fetchone()
    assert record["source_step_id"] == request.steps[0].step_id
    assert len(verified.step_results) == 2


@pytest.mark.asyncio
async def test_later_mandatory_lifecycle_step_cannot_hide_verification_target(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    request = execution(steps=2)
    request = request.model_copy(
        update={
            "steps": [
                request.steps[0],
                request.steps[1].model_copy(update={"operation": Operation.SUSPEND}),
            ]
        }
    )
    assert (await service.submit(request.request_id, request)).state == "completed"
    verified = await service.verify(
        request.request_id, action(request.request_id, Operation.VERIFY)
    )
    assert verified.state == "verified"
    assert len(verified.step_results) == 1
    record = service.repository._connection.execute(
        "SELECT source_step_id FROM verification_records WHERE target_system='odoo'"
    ).fetchone()
    assert record["source_step_id"] == request.steps[0].step_id


@pytest.mark.asyncio
async def test_activation_retry_rechecks_newer_mandatory_blockers(tmp_path):
    class RetryActivationOnceAdapter(FakeAdapter):
        def __init__(self):
            super().__init__()
            self.activation_attempts = 0

        async def activate(self, command):
            self.calls.append(command)
            self.activation_attempts += 1
            if self.activation_attempts == 1:
                raise RetryableAdapterError("activation_timeout")
            return {"state": "succeeded", "external_id": "activated"}

    adapter = RetryActivationOnceAdapter()
    service = engine(tmp_path, adapter)
    created = execution()
    await service.submit(created.request_id, created)
    await service.verify(
        created.request_id, action(created.request_id, Operation.VERIFY)
    )
    activation = execution(
        request_id="activation-retry-guard-0001",
        employee_id=created.employee_id,
        key="activation-retry-guard-idempotency",
        operation=Operation.ACTIVATE,
    )
    assert (await service.submit(activation.request_id, activation)).state == "retry_wait"
    update = execution(
        request_id="update-before-activation-retry-0001",
        employee_id=created.employee_id,
        key="update-before-activation-retry-key",
        operation=Operation.UPDATE,
    )
    await service.submit(update.request_id, update)
    calls_before_retry = len(adapter.calls)
    retried = await service.retry(
        activation.request_id, action(activation.request_id, Operation.UPDATE)
    )
    assert retried.state == "retry_wait"
    assert retried.step_results[0].error_code == "mandatory_verification_incomplete"
    assert retried.step_results[0].retry_at > datetime.now(UTC)
    assert service.repository.claim_next(activation.request_id) is None
    assert len(adapter.calls) == calls_before_retry
    replay = await service.submit(activation.request_id, activation)
    assert replay.replayed
    assert replay.step_results[0].error_code == "mandatory_verification_incomplete"
    assert replay.step_results[0].retry_at == retried.step_results[0].retry_at


@pytest.mark.asyncio
async def test_due_compensation_serializes_with_new_employee_update(tmp_path):
    class BlockingUpdateAdapter(FakeAdapter):
        def __init__(self):
            super().__init__()
            self.update_started = asyncio.Event()
            self.release_update = asyncio.Event()
            self.call_order = []

        async def update(self, command):
            self.calls.append(command)
            if command.payload.get("compensation"):
                self.call_order.append("compensation")
                return {"state": "succeeded", "external_id": "suspended"}
            self.call_order.append("update_started")
            self.update_started.set()
            await self.release_update.wait()
            self.call_order.append("update_completed")
            return {"state": "succeeded", "external_id": "updated"}

    adapter = BlockingUpdateAdapter()
    service = engine(tmp_path, adapter)
    original = execution()
    await service.submit(original.request_id, original)
    service.repository.record_compensation(
        original.request_id,
        original.steps[0].step_id,
        Operation.UPDATE.value,
        "failed",
        error_code="synthetic_retry",
        retry_delay_seconds=0,
    )
    update = execution(
        request_id="update-during-compensation-0001",
        employee_id=original.employee_id,
        key="update-during-compensation-key",
        operation=Operation.UPDATE,
    )
    update_task = asyncio.create_task(service.submit(update.request_id, update))
    await adapter.update_started.wait()
    compensation_task = asyncio.create_task(
        service._compensate_due(original.request_id)
    )
    await asyncio.sleep(0)
    assert not compensation_task.done()
    adapter.release_update.set()
    await update_task
    await compensation_task
    assert adapter.call_order[-1:] == ["update_completed"]
    compensation = service.repository._connection.execute(
        "SELECT state,error_code FROM compensation_actions WHERE request_id=?",
        (original.request_id,),
    ).fetchone()
    assert tuple(compensation) == ("superseded", "newer_employee_operation")


@pytest.mark.asyncio
async def test_cancel_compensation_serializes_with_new_employee_update(tmp_path):
    class BlockingUpdateAdapter(FakeAdapter):
        def __init__(self):
            super().__init__()
            self.update_started = asyncio.Event()
            self.release_update = asyncio.Event()

        async def update(self, command):
            self.calls.append(command)
            if command.payload.get("compensation"):
                return {"state": "succeeded", "external_id": "compensated"}
            self.update_started.set()
            await self.release_update.wait()
            return {"state": "succeeded", "external_id": "updated"}

    adapter = BlockingUpdateAdapter()
    service = engine(tmp_path, adapter)
    original = execution()
    await service.submit(original.request_id, original)
    update = execution(
        request_id="update-during-cancel-0001",
        employee_id=original.employee_id,
        key="update-during-cancel-key",
        operation=Operation.UPDATE,
    )
    update_task = asyncio.create_task(service.submit(update.request_id, update))
    await adapter.update_started.wait()
    cancel_task = asyncio.create_task(
        service.cancel(
            original.request_id,
            action(original.request_id, Operation.CANCEL),
        )
    )
    await asyncio.sleep(0)
    assert not cancel_task.done()
    adapter.release_update.set()
    await update_task
    await cancel_task
    assert not any(call.payload.get("compensation") for call in adapter.calls)
    compensation = service.repository._connection.execute(
        "SELECT state,error_code FROM compensation_actions WHERE request_id=?",
        (original.request_id,),
    ).fetchone()
    assert tuple(compensation) == ("superseded", "newer_employee_operation")


@pytest.mark.asyncio
async def test_completed_activation_replay_precedes_new_blocker_check(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    created = execution()
    await service.submit(created.request_id, created)
    await service.verify(
        created.request_id, action(created.request_id, Operation.VERIFY)
    )
    activation = execution(
        request_id="activation-replay-0001",
        employee_id=created.employee_id,
        key="activation-replay-idempotency",
        operation=Operation.ACTIVATE,
    )
    assert (await service.submit(activation.request_id, activation)).state == "completed"
    update = execution(
        request_id="pending-after-activation-0001",
        employee_id=created.employee_id,
        key="pending-after-activation-idempotency",
        operation=Operation.UPDATE,
    )
    service.repository.begin_execution(update, "pending-update-hash")
    replay = await service.submit(activation.request_id, activation)
    assert replay.replayed
    assert replay.state == "completed"


@pytest.mark.asyncio
async def test_update_cannot_substitute_for_create_disabled(tmp_path):
    adapter = FakeAdapter()
    service = engine(tmp_path, adapter)
    updated = execution(operation=Operation.UPDATE)
    await service.submit(updated.request_id, updated)
    assert (
        await service.verify(
            updated.request_id,
            action(updated.request_id, Operation.VERIFY),
        )
    ).state == "verified"
    activation = execution(
        request_id="activation-without-create-0001",
        employee_id=updated.employee_id,
        key="activation-without-create-idempotency",
        operation=Operation.ACTIVATE,
    )
    with pytest.raises(EngineError, match="mandatory_verification_incomplete"):
        await service.submit(activation.request_id, activation)


@pytest.mark.asyncio
async def test_reconciliation_drift_is_not_reported_aligned(tmp_path):
    class DriftAdapter(FakeAdapter):
        async def reconcile(self, command):
            self.calls.append(command)
            return {"state": "privilege_drift", "external_id": "synthetic"}

    adapter = DriftAdapter()
    service = engine(tmp_path, adapter)
    request = execution()
    await service.submit(request.request_id, request)
    result = await service.reconcile(
        request.employee_id,
        action(request.request_id, Operation.RECONCILE),
    )
    assert result.state == "drift_or_unavailable"
    assert result.systems[0].state == StepState.FAILED
    assert result.systems[0].error_code == "reconciliation_drift"


@pytest.mark.asyncio
async def test_failed_compensation_is_retried_after_restart(tmp_path):
    class RestartCompensationAdapter(FakeAdapter):
        def __init__(self):
            super().__init__()
            self.regular_calls = 0
            self.compensation_calls = 0

        async def call(self, command):
            self.calls.append(command)
            if command.payload.get("compensation"):
                self.compensation_calls += 1
                if self.compensation_calls == 1:
                    raise RetryableAdapterError("compensation_timeout")
                return {"state": "suspended", "external_id": "synthetic"}
            self.regular_calls += 1
            if self.regular_calls == 2:
                raise PermanentAdapterError("later_step_failed")
            return {"state": "succeeded", "external_id": "synthetic"}

        create_disabled = update = verify = activate = suspend = call
        reactivate = terminate = rotate_credentials = reconcile = call

    adapter = RestartCompensationAdapter()
    service = engine(tmp_path, adapter)
    request = execution(steps=2)
    result = await service.submit(request.request_id, request)
    assert result.state == "dead_letter"
    assert service.repository.counts()["failed_compensations"] == 1

    restarted = ProvisioningEngine(
        {TargetSystem.ODOO.value: adapter},
        StateRepository(str(tmp_path / "state.db")),
        service.settings,
        service.callback_dispatcher,
    )
    await restarted.recover()
    assert restarted.repository.counts()["failed_compensations"] == 0
    row = restarted.repository._connection.execute(
        """SELECT state,attempt_count FROM compensation_actions
           WHERE request_id=?""",
        (request.request_id,),
    ).fetchone()
    assert tuple(row) == ("succeeded", 2)


@pytest.mark.asyncio
async def test_secret_storage_never_persists_plaintext(tmp_path):
    key_file = tmp_path / "fernet"
    key_file.write_bytes(Fernet.generate_key())
    key_file.chmod(0o600)
    repository = StateRepository(str(tmp_path / "state.db"))
    adapter = SecretStorageAdapter(repository, str(key_file))
    command = execution(target=TargetSystem.SECRET_STORAGE).steps[0]
    result = await adapter.create_disabled(command)
    assert result["credential_reference"].startswith("vault:")
    connection = sqlite3.connect(repository.path)
    ciphertext = connection.execute(
        "SELECT ciphertext FROM encrypted_credentials"
    ).fetchone()[0]
    assert b"vault:" not in ciphertext
