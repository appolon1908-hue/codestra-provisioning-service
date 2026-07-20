"""Application factory for the durable, mock-only SIP API."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response

from .auth.mock import Identity, mock_identity
from .config import Settings, get_settings
from .dependencies import build_service
from .services.lifecycle import DurableSessionService, LifecycleError
from .schemas.sessions import CreateSessionRequest, RenewSessionRequest, RevokeSessionRequest


def create_app(settings: Settings | None = None, service: DurableSessionService | None = None) -> FastAPI:
    configured = service
    if configured is None:
        configured, engine, redis = build_service(settings or get_settings())
    app = FastAPI(title="Codestra SIP Provisioning API", version=(settings or get_settings()).service_version)
    app.state.durable_service = configured

    @app.middleware("http")
    async def no_store(request: Request, call_next: Any) -> Response:
        result = await call_next(request)
        result.headers["Cache-Control"] = "no-store"
        result.headers["Pragma"] = "no-cache"
        return result

    def svc() -> DurableSessionService:
        return app.state.durable_service

    @app.get("/healthz")
    async def healthz() -> dict[str, str]: return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, Any]:
        s = svc().settings
        if not s.sip_provisioning_mock_mode or s.endpoint_6101_allowed or s.live_asterisk_provisioning_enabled:
            raise HTTPException(503, "mock safety gate failed")
        try:
            async with svc().sessions() as db:
                await db.execute(__import__("sqlalchemy").text("SELECT 1"))
            await svc().redis.ping()
        except Exception as exc:
            raise HTTPException(503, "durable dependencies unavailable") from exc
        return {"status": "ready", "postgres": "ok", "redis": "ok", "mock_provisioner": True,
                "live_provisioning": False, "endpoint_6101_allowed": False,
                "migration_revision": s.migration_revision}

    @app.get("/api/v1/sip/config")
    async def config() -> dict[str, Any]:
        s = svc().settings
        return {"service_version": s.service_version, "mock_mode": True,
                "ttl_limits": {"min": s.session_ttl_min_seconds, "default": s.session_ttl_default_seconds, "max": s.session_ttl_max_seconds},
                "renewal_supported": True, "one_user_one_endpoint": True,
                "supported_transports": ["WSS"], "supported_codecs": ["opus", "PCMU"],
                "wss_url": s.mock_wss_url, "realm": s.mock_realm,
                "endpoint_6101_available": False, "live_provisioning_enabled": False}

    async def call(operation: Any, *args: Any) -> Any:
        try: return await operation(*args)
        except LifecycleError as exc: raise HTTPException(exc.status, exc.detail) from exc

    @app.post("/api/v1/sip/session")
    async def create(payload: CreateSessionRequest, request: Request, identity: Identity = Depends(mock_identity), idempotency_key: str | None = Header(None, alias="Idempotency-Key"), x_client_instance_id: str | None = Header(None, alias="X-Client-Instance-ID"), x_correlation_id: str | None = Header(None, alias="X-Correlation-ID")) -> Any:
        if not idempotency_key or not x_client_instance_id: raise HTTPException(400, "Idempotency-Key and X-Client-Instance-ID are required")
        rid, corr = uuid.uuid4(), uuid.UUID(x_correlation_id) if x_correlation_id else uuid.uuid4()
        return await call(svc().create, identity.subject, x_client_instance_id, idempotency_key, payload.ttl_seconds, rid, corr)

    @app.post("/api/v1/sip/session/renew")
    async def renew(payload: RenewSessionRequest, identity: Identity = Depends(mock_identity), idempotency_key: str | None = Header(None, alias="Idempotency-Key"), x_client_instance_id: str | None = Header(None, alias="X-Client-Instance-ID"), x_correlation_id: str | None = Header(None, alias="X-Correlation-ID")) -> Any:
        if not idempotency_key or not x_client_instance_id: raise HTTPException(400, "Idempotency-Key and X-Client-Instance-ID are required")
        return await call(svc().renew, identity.subject, payload.session_id, x_client_instance_id, idempotency_key, payload.ttl_seconds, uuid.uuid4(), uuid.UUID(x_correlation_id) if x_correlation_id else uuid.uuid4())

    @app.delete("/api/v1/sip/session", status_code=204)
    async def revoke(payload: RevokeSessionRequest, identity: Identity = Depends(mock_identity), idempotency_key: str | None = Header(None, alias="Idempotency-Key"), x_client_instance_id: str | None = Header(None, alias="X-Client-Instance-ID")) -> Response:
        if not idempotency_key or not x_client_instance_id: raise HTTPException(400, "Idempotency-Key and X-Client-Instance-ID are required")
        await call(svc().revoke, identity.subject, payload.session_id, idempotency_key, uuid.uuid4(), uuid.uuid4())
        return Response(status_code=204)

    return app


try:
    app = create_app()
except Exception:
    # Import remains safe in tooling; deployment must provide validated settings.
    app = FastAPI(title="Codestra SIP Provisioning API")
