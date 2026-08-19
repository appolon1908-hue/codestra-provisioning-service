import httpx
import pytest

from app.callbacks import CallbackDispatcher
from app.contracts import CallbackEvent, Operation, TargetSystem
from app.repository import StateRepository
from app.secrets import SecretReferenceError, read_secret_reference


def test_secret_reference_rejects_broad_permissions(tmp_path, monkeypatch):
    secret = tmp_path / "secret"
    secret.write_text("value")
    secret.chmod(0o644)
    monkeypatch.setenv("TEST_SECRET_FILE", str(secret))
    with pytest.raises(SecretReferenceError):
        read_secret_reference("TEST_SECRET_FILE")
    secret.chmod(0o600)
    assert read_secret_reference("TEST_SECRET_FILE") == "value"


@pytest.mark.asyncio
async def test_callback_is_signed_and_replay_safe(tmp_path, monkeypatch):
    secret = tmp_path / "callback-secret"
    secret.write_text("callback-key")
    secret.chmod(0o600)
    captured = []

    def handler(request):
        captured.append(request)
        return httpx.Response(202)

    repository = StateRepository(str(tmp_path / "state.db"))
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    dispatcher = CallbackDispatcher(
        "https://odoo.invalid/callback",
        str(secret),
        repository,
        client=client,
    )
    event = CallbackEvent(
        event_id="event-identity-0001",
        request_id="1",
        employee_id="synthetic-employee-0001",
        correlation_id="correlation-identity-0001",
        idempotency_key="callback-idempotency-0001",
        target_system=TargetSystem.ODOO,
        operation=Operation.UPDATE,
        state="verification",
        step_results=[],
    )
    assert await dispatcher.enqueue_and_dispatch(event)
    assert captured[0].headers["x-codestra-signature"].startswith("sha256=")
    assert b"callback-key" not in captured[0].content
    assert repository.counts()["pending_callbacks"] == 0
    await client.aclose()
