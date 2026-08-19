import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import (
    CANONICAL_ISSUER,
    CANONICAL_JWKS_URL,
    MACHINE_AUDIENCE,
    MACHINE_CLIENT_ID,
    MACHINE_SCOPES,
    MAX_TOKEN_TTL_SECONDS,
    Settings,
)
from app.contracts import TargetSystem
from app.main import create_app
from app.repository import StateRepository
from tests.helpers import FakeAdapter, execution


def material(tmp_path):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_file = tmp_path / "jwt.pem"
    public_file.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_file.chmod(0o600)
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("configured")
    placeholder.chmod(0o600)
    configured = Settings(
        environment="staging",
        state_database_path=str(tmp_path / "state.db"),
        jwt_issuer="https://auth.test/realms/codestra",
        jwt_audience="codestra-provisioning-service",
        jwt_public_key_file=str(public_file),
        jwt_algorithms=("RS256",),
        jwt_allowed_clients=frozenset({"test-service"}),
        request_max_bytes=4096,
        request_max_age_seconds=300,
        rate_limit_requests=20,
        rate_limit_window_seconds=60,
        claim_timeout_seconds=0,
        retry_base_seconds=0,
        callback_url=None,
        callback_hmac_file=str(placeholder),
        encryption_key_file=str(placeholder),
        adapter_config_file=str(placeholder),
        tls_cert_file=str(placeholder),
        tls_key_file=str(placeholder),
        jwt_expected_azp="test-service",
        jwt_required_scopes=frozenset(
            {"identity:rotate", "provisioning:execute", "provisioning:read"}
        ),
        jwt_max_token_ttl_seconds=300,
    )
    repository = StateRepository(configured.state_database_path)
    adapter = FakeAdapter()
    app = create_app(
        configured,
        repository,
        {TargetSystem.ODOO.value: adapter},
    )
    return private, configured, app, adapter


def token(private, settings, **changes):
    now = int(time.time())
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": "service-account-test",
        "azp": "test-service",
        "codestra_scopes": "identity:rotate provisioning:execute provisioning:read",
        "typ": "Bearer",
        "iat": now,
        "nbf": now - 1,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    claims.update(changes)
    claims = {key: value for key, value in claims.items() if value is not None}
    return jwt.encode(claims, private, algorithm="RS256")


def test_strict_jwt_scope_replay_and_private_tls(tmp_path):
    private, settings, app, adapter = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    with TestClient(app, base_url="https://provisioning-service") as client:
        assert client.post(url, json=request.model_dump(mode="json")).status_code == 401
        wrong_scope = token(private, settings, codestra_scopes="provisioning:read")
        assert (
            client.post(
                url,
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {wrong_scope}"},
            ).status_code
            == 401
        )
        valid = token(
            private,
            settings,
            nbf=None,
        )
        response = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {valid}"},
        )
        assert response.status_code == 200
        assert response.json()["state"] == "completed"
        assert len(adapter.calls) == 1
        replay = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {valid}"},
        )
        assert replay.status_code == 409


def test_strict_issuer_audience_and_size_limit(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    with TestClient(app, base_url="https://provisioning-service") as client:
        wrong_issuer = token(private, settings, iss="https://evil.invalid")
        response = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {wrong_issuer}"},
        )
        assert response.status_code == 401
        oversized = client.post(
            "/missing",
            content=b"x" * 5000,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert oversized.status_code == 413


def test_canonical_token_contract_negative_matrix(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    second_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    cases = (
        token(private, settings, iss="https://auth.codestra.agency/realms/codestra"),
        token(private, settings, aud="wrong-audience"),
        token(private, settings, azp="codestra-client-provisioner"),
        token(private, settings, azp="codestra-middleware-production"),
        token(private, settings, azp="codestra-n8n"),
        token(private, settings, azp=None),
        token(private, settings, iat=None),
        token(private, settings, exp=None),
        token(private, settings, iat=now, exp=now),
        token(private, settings, iat=now, exp=now + 301),
        token(private, settings, iat=now - 600, exp=now - 300),
        token(private, settings, jti=None),
        token(private, settings, codestra_scopes=None, scope="provisioning:execute"),
        token(private, settings, codestra_scopes="identity:rotate provisioning:read"),
        token(private, settings, codestra_scopes="identity:rotate provisioning:execute"),
        token(private, settings, codestra_scopes="provisioning:execute provisioning:read"),
        token(
            private,
            settings,
            codestra_scopes=(
                "identity:rotate provisioning:execute provisioning:read realm-admin"
            ),
        ),
        token(second_private, settings),
    )
    with TestClient(app, base_url="https://provisioning-service") as client:
        for candidate in cases:
            response = client.post(
                url,
                json=request.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {candidate}"},
            )
            assert response.status_code == 401


def test_maximum_300_second_token_and_replay(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution()
    url = f"/v1/provisioning/requests/{request.request_id}/execute"
    now = int(time.time())
    candidate = token(private, settings, iat=now, exp=now + 300)
    with TestClient(app, base_url="https://provisioning-service") as client:
        first = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {candidate}"},
        )
        assert first.status_code == 200
        replay = client.post(
            url,
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {candidate}"},
        )
        assert replay.status_code == 409


def test_runtime_defaults_are_the_canonical_machine_contract(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "staging")
    for name in (
        "JWT_ISSUER",
        "JWT_JWKS_URL",
        "JWT_AUDIENCE",
        "JWT_EXPECTED_AZP",
        "JWT_ALLOWED_CLIENTS",
        "JWT_REQUIRED_SCOPES",
        "JWT_MAX_TOKEN_TTL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.load()
    assert settings.jwt_issuer == CANONICAL_ISSUER
    assert settings.jwt_jwks_url == CANONICAL_JWKS_URL
    assert settings.jwt_audience == MACHINE_AUDIENCE
    assert settings.jwt_expected_azp == MACHINE_CLIENT_ID
    assert settings.jwt_allowed_clients == frozenset({MACHINE_CLIENT_ID})
    assert settings.jwt_required_scopes == MACHINE_SCOPES
    assert settings.jwt_max_token_ttl_seconds == MAX_TOKEN_TTL_SECONDS


def test_required_route_set_is_exact(tmp_path):
    _, _, app, _ = material(tmp_path)
    routes = {(method, route.path) for route in app.routes for method in route.methods or []}
    required = {
        ("POST", "/v1/provisioning/requests/{request_id}/execute"),
        ("POST", "/v1/provisioning/requests/{request_id}/retry"),
        ("POST", "/v1/provisioning/requests/{request_id}/verify"),
        ("POST", "/v1/provisioning/requests/{request_id}/cancel"),
        ("POST", "/v1/identities/{employee_id}/suspend"),
        ("POST", "/v1/identities/{employee_id}/reactivate"),
        ("POST", "/v1/identities/{employee_id}/terminate"),
        ("POST", "/v1/identities/{employee_id}/rotate"),
        ("GET", "/v1/provisioning/requests/{request_id}"),
        ("GET", "/v1/identities/{employee_id}/reconciliation"),
        ("GET", "/health"),
        ("GET", "/ready"),
        ("GET", "/metrics"),
    }
    assert required <= routes


def test_authoritative_numeric_odoo_request_id_is_accepted(tmp_path):
    private, settings, app, _ = material(tmp_path)
    request = execution().model_copy(
        update={
            "request_id": "87",
            "steps": [
                item.model_copy(update={"request_id": "87"})
                for item in execution().steps
            ],
        }
    )
    with TestClient(app, base_url="https://provisioning-service") as client:
        response = client.post(
            "/v1/provisioning/requests/87/execute",
            json=request.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {token(private, settings)}"},
        )
    assert response.status_code == 200
