import asyncio
import base64
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ["APP_ENV"] = "test"
os.environ["AUTH_MODE"] = "test"
os.environ["CREDENTIAL_ENCRYPTION_KEY_V1"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
os.environ["AUDIT_HMAC_KEY"] = base64.urlsafe_b64encode(os.urandom(48)).decode()
os.environ["SUBJECT_HASH_KEY"] = base64.urlsafe_b64encode(os.urandom(48)).decode()
os.environ["CREDENTIAL_FINGERPRINT_KEY"] = base64.urlsafe_b64encode(os.urandom(48)).decode()

from codestra_sip_provisioning.auth.principal import Principal, PrincipalKind
from codestra_sip_provisioning.auth.provider import TestPrincipalProvider as PrincipalTestProvider
from codestra_sip_provisioning.config import Settings
from codestra_sip_provisioning.main import create_app
from codestra_sip_provisioning.models import (
    SipAuditEvent,
    SipCredentialRotation,
    SipEndpointAssignment,
    SipSession,
)
from codestra_sip_provisioning.security.redaction import redact
from codestra_sip_provisioning.services.lifecycle import DurableSessionService, LifecycleError
from codestra_sip_provisioning.state.crypto import CredentialCipher
from codestra_sip_provisioning.state.guards import ReplayGuard


def settings() -> Settings:
    key = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    secret = base64.urlsafe_b64encode(os.urandom(48)).decode()
    return Settings(
        app_env="test",
        auth_mode="test",
        database_url=os.environ["DATABASE_URL"],
        redis_url=os.environ["REDIS_URL"],
        credential_encryption_key_v1=key,
        audit_hmac_key=secret,
        subject_hash_key=secret,
        credential_fingerprint_key=secret,
    )


def service(cfg: Settings) -> DurableSessionService:
    engine = create_async_engine(cfg.database_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    redis = Redis.from_url(cfg.redis_url, decode_responses=True)
    raw_key = base64.urlsafe_b64decode(cfg.credential_encryption_key_v1 + "===")
    cipher = CredentialCipher({"v1": raw_key}, "v1", cfg.service_name)
    return DurableSessionService(sessions, redis, cfg, cipher)


@pytest.fixture
async def durable() -> DurableSessionService:
    cfg = settings()
    instance = service(cfg)
    async with instance.sessions() as db, db.begin():
        await db.execute(
            text(
                "TRUNCATE credential_rotation,idempotency_record,audit_event,"
                "sip_session,endpoint_assignment RESTART IDENTITY CASCADE"
            )
        )
    await instance.redis.flushdb()
    yield instance
    await instance.redis.aclose()
    await instance.sessions.kw["bind"].dispose()


async def create(
    instance: DurableSessionService, key: str = "create-key-0001"
) -> dict[str, object]:
    request_id = uuid.uuid4()
    return await instance.create(
        "agent@example.invalid", "browser-a", key, 600, request_id, request_id
    )


@pytest.mark.asyncio
async def test_restart_multiple_workers_and_one_time_credential(
    durable: DurableSessionService,
) -> None:
    created = await create(durable)
    password = str(created["sip_password"])
    worker_b = service(durable.settings)
    try:
        with pytest.raises(LifecycleError) as replay:
            await create(worker_b)
        assert replay.value.code == "credential_already_delivered"
        assert replay.value.reference == uuid.UUID(str(created["session_id"]))
        async with worker_b.sessions() as db:
            assert await db.scalar(select(func.count()).select_from(SipEndpointAssignment)) == 1
            assert await db.scalar(select(func.count()).select_from(SipSession)) == 1
            assert await db.scalar(select(func.count()).select_from(SipAuditEvent)) == 1
            row = (await db.execute(select(SipSession))).scalar_one()
            assert row.credential_fingerprint != password
        envelope = await worker_b.redis.get(worker_b.keys.credential(str(created["session_id"])))
        assert envelope is not None and password not in envelope
        assert json.loads(envelope)["algorithm"] == "AES-256-GCM"
    finally:
        await worker_b.redis.aclose()
        await worker_b.sessions.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_concurrent_create_one_assignment_and_session(durable: DurableSessionService) -> None:
    results = await asyncio.gather(
        create(durable, "concurrent-key-a"),
        create(durable, "concurrent-key-b"),
        return_exceptions=True,
    )
    assert sum(isinstance(item, dict) for item in results) == 1
    assert sum(isinstance(item, LifecycleError) for item in results) == 1
    async with durable.sessions() as db:
        assert await db.scalar(select(func.count()).select_from(SipEndpointAssignment)) == 1
        assert await db.scalar(select(func.count()).select_from(SipSession)) == 1


@pytest.mark.asyncio
async def test_idempotency_payload_conflict(durable: DurableSessionService) -> None:
    await create(durable, "payload-key-001")
    with pytest.raises(LifecycleError) as conflict:
        rid = uuid.uuid4()
        await durable.create("agent@example.invalid", "browser-a", "payload-key-001", 601, rid, rid)
    assert conflict.value.status == 409
    assert conflict.value.code == "idempotency_conflict"


@pytest.mark.asyncio
async def test_all_redis_keys_have_ttl_and_revoke_deletes_credential(
    durable: DurableSessionService,
) -> None:
    created = await create(durable, "ttl-create-key")
    keys = await durable.redis.keys(f"{durable.settings.redis_namespace}:*")
    assert keys
    for key in keys:
        assert await durable.redis.ttl(key) > 0
    sid = uuid.UUID(str(created["session_id"]))
    rid = uuid.uuid4()
    await durable.revoke("agent@example.invalid", sid, "revoke-key-0001", rid, rid)
    assert await durable.redis.exists(durable.keys.credential(str(sid))) == 0
    async with durable.sessions() as db:
        assert (await db.get(SipSession, sid)).state == "revoked"


@pytest.mark.asyncio
async def test_renew_rotates_once_and_never_persists_plaintext(
    durable: DurableSessionService,
) -> None:
    created = await create(durable, "renew-create-key")
    sid = uuid.UUID(str(created["session_id"]))
    original_password = str(created["sip_password"])
    request_id = uuid.uuid4()

    renewed = await durable.renew(
        "agent@example.invalid",
        sid,
        "browser-a",
        "renew-key-0001",
        600,
        request_id,
        request_id,
    )
    rotated_password = str(renewed["sip_password"])
    assert renewed["credential_rotated"] is True
    assert rotated_password != original_password

    with pytest.raises(LifecycleError) as replay:
        await durable.renew(
            "agent@example.invalid",
            sid,
            "browser-a",
            "renew-key-0001",
            600,
            uuid.uuid4(),
            uuid.uuid4(),
        )
    assert replay.value.code == "credential_already_delivered"

    async with durable.sessions() as db:
        row = await db.get(SipSession, sid)
        assert row is not None
        assert row.state == "renewed"
        assert row.renewal_count == 1
        assert row.credential_fingerprint not in {original_password, rotated_password}
        assert await db.scalar(select(func.count()).select_from(SipCredentialRotation)) == 1
        persisted = await db.scalar(
            text("SELECT row_to_json(sip_session)::text FROM sip_session WHERE id=:id"),
            {"id": sid},
        )
        assert original_password not in str(persisted)
        assert rotated_password not in str(persisted)

    envelope = await durable.redis.get(durable.keys.credential(str(sid)))
    previous = await durable.redis.get(durable.keys.old_credential(str(sid)))
    assert envelope is not None and rotated_password not in envelope
    assert previous is not None and original_password not in previous
    subject_hash = durable.digest("agent@example.invalid", "codestra:sip:subject:v1")
    assert durable.cipher.decrypt(
        envelope,
        str(sid),
        subject_hash,
        str(renewed["endpoint"]),
    ) == rotated_password
    assert await durable.redis.ttl(durable.keys.old_credential(str(sid))) > 0


@pytest.mark.asyncio
async def test_expiration_reconciliation_preserves_assignment(
    durable: DurableSessionService,
) -> None:
    created = await create(durable, "expire-key-0001")
    sid = uuid.UUID(str(created["session_id"]))
    async with durable.sessions() as db, db.begin():
        await db.execute(
            update(SipSession)
            .where(SipSession.id == sid)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    assert await durable.reconcile() == 1
    async with durable.sessions() as db:
        assert (await db.get(SipSession, sid)).state == "expired"
        assert await db.scalar(select(func.count()).select_from(SipEndpointAssignment)) == 1
        events = (
            (await db.execute(select(SipAuditEvent).order_by(SipAuditEvent.occurred_at)))
            .scalars()
            .all()
        )
        assert events[-1].action == "expire"
        for previous, current in zip(events, events[1:], strict=False):
            assert current.previous_hash == previous.event_hash


@pytest.mark.asyncio
async def test_api_contract_and_auth_gate(durable: DurableSessionService) -> None:
    app = create_app(durable.settings, durable)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/healthz")).status_code == 200
        denied = await client.post("/api/v1/sip/session", json={})
        assert denied.status_code == 422 or denied.status_code == 401
        response = await client.post(
            "/api/v1/sip/session",
            json={},
            headers={
                "Authorization": "Bearer test:api-agent",
                "Idempotency-Key": "api-create-0001",
                "X-Client-Instance-ID": "browser-api",
            },
        )
        assert response.status_code == 201
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["mock_mode"] is True
        assert durable.settings.public_session_route_enabled is False
        committed = json.loads(Path("docs/openapi.yaml").read_text(encoding="utf-8"))
        assert app.openapi() == committed

        no_scope = Principal(
            "scope-denied-agent",
            frozenset({"agent"}),
            frozenset(),
            PrincipalKind.TEST,
            "test",
        )
        denied_app = create_app(
            durable.settings,
            durable,
            PrincipalTestProvider(durable.settings, {"no-scope-token": no_scope}),
        )
        denied_transport = httpx.ASGITransport(app=denied_app)
        async with httpx.AsyncClient(
            transport=denied_transport, base_url="http://test"
        ) as denied_client:
            denied_scope = await denied_client.post(
                "/api/v1/sip/session",
                json={},
                headers={
                    "Authorization": "Bearer no-scope-token",
                    "Idempotency-Key": "scope-denial-key",
                    "X-Client-Instance-ID": "scope-denial-browser",
                },
            )
            assert denied_scope.status_code == 403
        async with durable.sessions() as db:
            decisions = (
                await db.execute(
                    select(SipAuditEvent).where(
                        SipAuditEvent.action.in_(("authentication", "authorize:create"))
                    )
                )
            ).scalars()
            assert {(event.action, event.result) for event in decisions} >= {
                ("authentication", "allowed"),
                ("authorize:create", "allowed"),
                ("authorize:create", "denied"),
            }


@pytest.mark.asyncio
async def test_readiness_config_and_request_limit_fail_closed(
    durable: DurableSessionService,
) -> None:
    app = create_app(durable.settings, durable)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ready = await client.get("/readyz")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
        assert all(ready.json()["checks"].values())

        config = await client.get("/api/v1/sip/config")
        assert config.status_code == 200
        assert config.json()["public_session_route_enabled"] is False
        assert config.json()["endpoint_6101_available"] is False
        assert config.json()["live_provisioning_enabled"] is False

        oversized = await client.post(
            "/api/v1/sip/session",
            content=b"{}",
            headers={"Content-Length": str(durable.settings.max_request_bytes + 1)},
        )
        assert oversized.status_code == 413
        assert oversized.json()["status"] == 413


@pytest.mark.asyncio
async def test_rate_limit_replay_guard_and_recursive_redaction(
    durable: DurableSessionService,
) -> None:
    await create(durable, "rate-key-0000")
    for index in range(1, 5):
        with pytest.raises(LifecycleError) as active:
            await create(durable, f"rate-key-{index:04d}")
        assert active.value.code == "active_session_exists"
    with pytest.raises(LifecycleError) as limited:
        await create(durable, "rate-key-0005")
    assert limited.value.status == 429
    assert limited.value.code == "rate_limited"

    nonce_hash = durable.digest("one-time-nonce", "codestra:sip:replay:v1")
    replay = ReplayGuard(durable.redis, durable.keys)
    assert await replay.claim(nonce_hash) is True
    assert await replay.claim(nonce_hash) is False
    assert await durable.redis.ttl(durable.keys.replay(nonce_hash)) > 0

    clean = redact(
        {
            "password": "never-log-me",
            "nested": {"authorization": "Bearer never-log-me"},
            "url": "https://example.invalid/callback?token=never-log-me",
        }
    )
    rendered = json.dumps(clean)
    assert "never-log-me" not in rendered
    assert rendered.count("[REDACTED]") == 3
