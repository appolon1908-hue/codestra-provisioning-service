"""Mock-only SIP provisioning API.

This module intentionally has no network or shell provisioning capability.
The default store is process-local for offline tests; production persistence
is a deployment prerequisite and is not activated by this repository.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .auth.mock import Identity, mock_identity
from .config import Settings, get_settings
from .provisioning.mock import MockProvisioner
from .schemas.sessions import CreateSessionRequest, RenewSessionRequest, RevokeSessionRequest


class SessionState(BaseModel):
    session_id: uuid.UUID
    subject: str
    endpoint: str
    username: str
    password: str
    expires_at: datetime
    revoked: bool = False


class Store:
    def __init__(self) -> None:
        self.assignments: dict[str, str] = {}
        self.sessions: dict[uuid.UUID, SessionState] = {}
        self.idempotency: dict[tuple[str, str, str], tuple[str, Any]] = {}


store = Store()
provisioner = MockProvisioner()


def _request_meta(request: Request, correlation_id: str | None) -> tuple[str, str]:
    request_id = str(uuid.uuid4())
    return request_id, correlation_id or request_id


def _key_hash(value: str, settings: Settings) -> str:
    return hmac.new(settings.fingerprint_hmac_key.encode(), value.encode(), hashlib.sha256).hexdigest()


def _endpoint(subject: str) -> str:
    digest = hashlib.sha256(subject.encode()).hexdigest()[:12]
    return f"mock-{digest}"


def _response(session: SessionState, settings: Settings, request_id: str, correlation_id: str, rotated: bool) -> dict[str, Any]:
    return {
        "session_id": str(session.session_id), "endpoint": session.endpoint,
        "sip_username": session.username, "sip_password": session.password,
        "wss_url": settings.mock_wss_url, "realm": settings.mock_realm,
        "expires_at": session.expires_at.isoformat(),
        "renew_after": (session.expires_at - timedelta(seconds=120)).isoformat(),
        "credential_rotated": rotated, "credential_delivered": True,
        "mock_mode": True, "storage_requirement": "memory-only",
        "request_id": request_id, "correlation_id": correlation_id,
    }


def _headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


app = FastAPI(title="Codestra SIP Provisioning API", version="0.1.0")


@app.middleware("http")
async def no_store(request: Request, call_next: Any) -> Response:
    response = await call_next(request)
    _headers(response)
    return response


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    if not settings.sip_provisioning_mock_mode or settings.endpoint_6101_allowed:
        raise HTTPException(status_code=503, detail="mock safety gate failed")
    return {"status": "ready", "postgres": "not-activated", "redis": "not-activated", "mock_provisioner": True, "live_provisioning": False, "endpoint_6101_allowed": False}


@app.get("/api/v1/sip/config")
async def config(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {"service_version": settings.service_version, "mock_mode": True,
            "ttl_limits": {"min": settings.min_ttl_seconds, "default": settings.default_ttl_seconds, "max": settings.max_ttl_seconds},
            "renewal_supported": True, "one_user_one_endpoint": True,
            "supported_transports": ["WSS"], "supported_codecs": ["opus", "PCMU"],
            "wss_url": settings.mock_wss_url, "realm": settings.mock_realm,
            "endpoint_6101_available": False, "live_provisioning_enabled": False,
            "credential_storage": "memory-only", "timestamp": datetime.now(UTC).isoformat()}


@app.post("/api/v1/sip/session")
async def create_session(payload: CreateSessionRequest, request: Request, response: Response,
                         identity: Identity = Depends(mock_identity),
                         idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                         x_client_instance_id: str | None = Header(default=None, alias="X-Client-Instance-ID"),
                         x_correlation_id: str | None = Header(default=None, alias="X-Correlation-ID"),
                         settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    if not idempotency_key or not x_client_instance_id:
        raise HTTPException(status_code=400, detail="Idempotency-Key and X-Client-Instance-ID are required")
    request_id, correlation_id = _request_meta(request, x_correlation_id)
    key = (identity.subject, "create", _key_hash(idempotency_key, settings))
    request_hash = _key_hash(payload.model_dump_json(), settings)
    prior = store.idempotency.get(key)
    if prior:
        if prior[0] != request_hash:
            raise HTTPException(status_code=409, detail="idempotency key conflict")
        return prior[1]
    endpoint = store.assignments.setdefault(identity.subject, _endpoint(identity.subject))
    active = next((s for s in store.sessions.values() if s.subject == identity.subject and not s.revoked and s.expires_at > datetime.now(UTC)), None)
    if active:
        raise HTTPException(status_code=409, detail="active SIP session already exists")
    issued = await provisioner.issue(endpoint)
    session = SessionState(session_id=uuid.uuid4(), subject=identity.subject, endpoint=endpoint, username=issued.username,
                           password=issued.password, expires_at=datetime.now(UTC) + timedelta(seconds=payload.ttl_seconds))
    store.sessions[session.session_id] = session
    result = _response(session, settings, request_id, correlation_id, False)
    store.idempotency[key] = (request_hash, result)
    return result


@app.post("/api/v1/sip/session/renew")
async def renew_session(payload: RenewSessionRequest, request: Request, response: Response,
                        identity: Identity = Depends(mock_identity),
                        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                        x_client_instance_id: str | None = Header(default=None, alias="X-Client-Instance-ID"),
                        x_correlation_id: str | None = Header(default=None, alias="X-Correlation-ID"),
                        settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    if not idempotency_key or not x_client_instance_id:
        raise HTTPException(status_code=400, detail="Idempotency-Key and X-Client-Instance-ID are required")
    session = store.sessions.get(payload.session_id)
    if not session or session.subject != identity.subject or session.revoked:
        raise HTTPException(status_code=404, detail="session not found")
    issued = await provisioner.rotate(session.endpoint)
    session.username, session.password = issued.username, issued.password
    session.expires_at = datetime.now(UTC) + timedelta(seconds=payload.ttl_seconds)
    request_id, correlation_id = _request_meta(request, x_correlation_id)
    return _response(session, settings, request_id, correlation_id, True)


@app.delete("/api/v1/sip/session", status_code=204)
async def revoke_session(payload: RevokeSessionRequest, identity: Identity = Depends(mock_identity)) -> Response:
    session = store.sessions.get(payload.session_id)
    if session and session.subject == identity.subject and not session.revoked:
        session.revoked = True
        session.password = secrets.token_urlsafe(32)
    return Response(status_code=204, headers={"Cache-Control": "no-store"})
