import uuid
from typing import Any, cast

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .auth.principal import Principal
from .auth.provider import PrincipalProvider
from .config import Settings, get_settings
from .dependencies import build_service
from .schemas.sessions import (
    CreateSessionRequest,
    RenewSessionRequest,
    RevokeSessionRequest,
    SessionResponse,
)
from .services.lifecycle import DurableSessionService, LifecycleError


def problem(exc: LifecycleError) -> JSONResponse:
    body: dict[str, object] = {
        "type": f"urn:codestra:sip:{exc.code}",
        "title": exc.code.replace("_", " "),
        "status": exc.status,
        "detail": exc.detail,
    }
    if exc.reference:
        body["session_id"] = str(exc.reference)
    response = JSONResponse(body, status_code=exc.status, media_type="application/problem+json")
    if exc.status == 429:
        response.headers["Retry-After"] = "60"
    return response


def create_app(
    settings: Settings | None = None, service: DurableSessionService | None = None
) -> FastAPI:
    cfg = settings or get_settings()
    configured = service or build_service(cfg)[0]
    provider = PrincipalProvider(cfg)
    api = FastAPI(
        title="Codestra SIP Provisioning API",
        version=cfg.service_version,
        openapi_version="3.1.0",
        docs_url=None,
        redoc_url=None,
    )

    @api.middleware("http")
    async def safeguards(request: Request, call_next: Any) -> Response:
        size = request.headers.get("content-length")
        if size and int(size) > cfg.max_request_bytes:
            return JSONResponse(
                {
                    "type": "urn:codestra:sip:request_too_large",
                    "title": "request too large",
                    "status": 413,
                    "detail": "request body exceeds limit",
                },
                status_code=413,
                media_type="application/problem+json",
            )
        response = cast(Response, await call_next(request))
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @api.exception_handler(LifecycleError)
    async def lifecycle_error(_: Request, exc: LifecycleError) -> JSONResponse:
        return problem(exc)

    @api.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/readyz")
    async def readyz() -> Response:
        checks = {
            "mock_provisioner": configured.provisioner.__class__.__name__ == "MockProvisioner",
            "mock_mode": cfg.sip_provisioning_mock_mode,
            "live_flags_off": not any(
                (
                    cfg.live_asterisk_provisioning_enabled,
                    cfg.live_endpoint_install_enabled,
                    cfg.live_endpoint_reload_enabled,
                    cfg.live_endpoint_delete_enabled,
                    cfg.endpoint_6101_allowed,
                )
            ),
            "encryption_key": configured.cipher.active_version
            == cfg.credential_encryption_key_version,
            "public_auth_gate": not cfg.public_session_route_enabled
            or cfg.live_authorization_enabled,
        }
        try:
            async with configured.sessions() as db:
                checks["postgres"] = bool((await db.execute(text("SELECT 1"))).scalar_one())
                revision = (
                    await db.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar_one()
                schema = (
                    await db.execute(text("SELECT schema_version FROM schema_state WHERE id=1"))
                ).scalar_one()
                checks["migrations"] = revision == cfg.migration_revision
                checks["schema_state"] = schema == cfg.schema_version
        except Exception:
            checks["postgres"] = checks["migrations"] = checks["schema_state"] = False
        try:
            checks["redis"] = bool(await configured.redis.ping())
        except Exception:
            checks["redis"] = False
        status = 200 if all(checks.values()) else 503
        return JSONResponse(
            {"status": "ready" if status == 200 else "not_ready", "checks": checks},
            status_code=status,
        )

    @api.get("/api/v1/sip/config")
    async def sip_config() -> dict[str, object]:
        return {
            "service_version": cfg.service_version,
            "mock_mode": True,
            "public_session_route_enabled": cfg.public_session_route_enabled,
            "live_provisioning_enabled": False,
            "endpoint_6101_available": False,
            "credential_storage": "memory-only",
            "one_user_one_endpoint": True,
            "ttl_limits": {
                "min": cfg.session_ttl_min_seconds,
                "default": cfg.session_ttl_default_seconds,
                "max": cfg.session_ttl_max_seconds,
            },
        }

    async def principal(authorization: str | None = Header(default=None)) -> Principal:
        return await provider.authenticate(authorization)

    def ids(correlation: str | None) -> tuple[uuid.UUID, uuid.UUID]:
        request_id = uuid.uuid4()
        try:
            return request_id, uuid.UUID(correlation) if correlation else request_id
        except ValueError as exc:
            raise LifecycleError(
                400, "invalid_correlation_id", "X-Correlation-ID must be a UUID"
            ) from exc

    @api.post("/api/v1/sip/session", response_model=SessionResponse, status_code=201)
    async def create(
        payload: CreateSessionRequest,
        identity: Principal = Depends(principal),  # noqa: B008 - FastAPI dependency
        idempotency_key: str = Header(min_length=8, alias="Idempotency-Key"),
        client_id: str = Header(min_length=1, alias="X-Client-Instance-ID"),
        correlation: str | None = Header(default=None, alias="X-Correlation-ID"),
    ) -> dict[str, Any]:
        request_id, correlation_id = ids(correlation)
        return await configured.create(
            identity.subject,
            client_id,
            idempotency_key,
            payload.ttl_seconds,
            request_id,
            correlation_id,
        )

    @api.post("/api/v1/sip/session/renew", response_model=SessionResponse)
    async def renew(
        payload: RenewSessionRequest,
        identity: Principal = Depends(principal),  # noqa: B008 - FastAPI dependency
        idempotency_key: str = Header(min_length=8, alias="Idempotency-Key"),
        client_id: str = Header(min_length=1, alias="X-Client-Instance-ID"),
        correlation: str | None = Header(default=None, alias="X-Correlation-ID"),
    ) -> dict[str, Any]:
        request_id, correlation_id = ids(correlation)
        return await configured.renew(
            identity.subject,
            payload.session_id,
            client_id,
            idempotency_key,
            payload.ttl_seconds,
            request_id,
            correlation_id,
        )

    @api.delete("/api/v1/sip/session", status_code=204)
    async def revoke(
        payload: RevokeSessionRequest,
        identity: Principal = Depends(principal),  # noqa: B008 - FastAPI dependency
        idempotency_key: str = Header(min_length=8, alias="Idempotency-Key"),
        client_id: str = Header(min_length=1, alias="X-Client-Instance-ID"),
        correlation: str | None = Header(default=None, alias="X-Correlation-ID"),
    ) -> Response:
        del client_id
        request_id, correlation_id = ids(correlation)
        await configured.revoke(
            identity.subject, payload.session_id, idempotency_key, request_id, correlation_id
        )
        return Response(status_code=204)

    return api


app = create_app()
