import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from starlette.requests import Request

from codestra_sip_provisioning.auth.policy import AuthorizationDenied, AuthorizationPolicy
from codestra_sip_provisioning.auth.principal import Principal, PrincipalKind
from codestra_sip_provisioning.auth.provider import (
    AuthenticationError,
    JWTPrincipalProvider,
    MTLSPrincipalProvider,
)
from codestra_sip_provisioning.config import Settings


def request(ssl_object: object | None = None) -> Request:
    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
    }
    if ssl_object is not None:
        scope["ssl_object"] = ssl_object
    return Request(scope)


@pytest.fixture
def jwt_material() -> tuple[Settings, RSAPrivateKey, JWTPrincipalProvider]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    secret = base64.urlsafe_b64encode(b"a" * 48).decode()
    settings = Settings(
        app_env="preproduction",
        auth_mode="jwt",
        live_authorization_enabled=True,
        database_url="postgresql+asyncpg://invalid/invalid",
        redis_url="redis://invalid/0",
        credential_encryption_key_v1=base64.urlsafe_b64encode(b"b" * 32).decode(),
        audit_hmac_key=secret,
        subject_hash_key=secret,
        credential_fingerprint_key=secret,
        jwt_issuer="https://issuer.example.invalid/",
        jwt_audience="codestra-sip",
        jwt_pinned_public_key=public_pem,
        jwt_allowed_algorithms=frozenset({"RS256"}),
    )
    return settings, private, JWTPrincipalProvider(settings)


def token(private: RSAPrivateKey, **changes: object) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": "https://issuer.example.invalid/",
        "aud": "codestra-sip",
        "sub": "stable-user-123",
        "exp": now + timedelta(minutes=5),
        "nbf": now - timedelta(seconds=1),
        "token_type": "access",
        "roles": ["agent"],
        "scope": "sip:session:create sip:session:renew sip:session:revoke",
    }
    claims.update(changes)
    return jwt.encode(claims, private, algorithm="RS256")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"iss": "https://wrong.invalid/"}, "invalid_token"),
        ({"aud": "wrong-audience"}, "invalid_token"),
        ({"exp": datetime.now(UTC) - timedelta(minutes=1)}, "invalid_token"),
        ({"token_type": "id"}, "wrong_token_type"),
    ],
)
async def test_jwt_rejects_invalid_security_claims(
    jwt_material: tuple[Settings, RSAPrivateKey, JWTPrincipalProvider],
    changes: dict[str, object],
    code: str,
) -> None:
    _, private, provider = jwt_material
    with pytest.raises(AuthenticationError) as denied:
        await provider.authenticate(request(), f"Bearer {token(private, **changes)}")
    assert denied.value.code == code


@pytest.mark.asyncio
async def test_scope_role_service_and_ownership_policy() -> None:
    policy = AuthorizationPolicy()
    base = Principal("user", frozenset({"agent"}), frozenset(), PrincipalKind.USER, "issuer")
    with pytest.raises(AuthorizationDenied, match="scope"):
        await policy.authorize(base, "create")
    service = Principal(
        "svc",
        frozenset({"service_n8n"}),
        frozenset({"sip:session:create"}),
        PrincipalKind.SERVICE,
        "mtls",
    )
    with pytest.raises(AuthorizationDenied) as restricted:
        await policy.authorize(service, "create")
    assert restricted.value.code == "service_scope_restricted"
    auditor = Principal(
        "audit",
        frozenset({"compliance_auditor"}),
        frozenset({"sip:session:create"}),
        PrincipalKind.USER,
        "issuer",
    )
    with pytest.raises(AuthorizationDenied) as forbidden:
        await policy.authorize(auditor, "create")
    assert forbidden.value.code == "role_forbidden"
    agent = Principal(
        "user", frozenset({"agent"}), frozenset({"sip:session:renew"}), PrincipalKind.USER, "issuer"
    )

    async def not_owner() -> bool:
        return False

    with pytest.raises(AuthorizationDenied) as ownership:
        await policy.authorize(agent, "renew", owner=not_owner)
    assert ownership.value.code == "ownership_required"


def test_admin_cannot_retrieve_existing_plaintext_credential() -> None:
    admin = Principal(
        "admin",
        frozenset({"platform_admin"}),
        frozenset({"sip:session:renew"}),
        PrincipalKind.USER,
        "issuer",
    )
    assert AuthorizationPolicy.may_retrieve_existing_credential(admin) is False


def test_test_provider_is_rejected_outside_test() -> None:
    secret = base64.urlsafe_b64encode(b"a" * 48).decode()
    with pytest.raises(ValueError, match="test authentication"):
        Settings(
            app_env="preproduction",
            auth_mode="test",
            database_url="postgresql+asyncpg://invalid/invalid",
            redis_url="redis://invalid/0",
            credential_encryption_key_v1=base64.urlsafe_b64encode(b"b" * 32).decode(),
            audit_hmac_key=secret,
            subject_hash_key=secret,
            credential_fingerprint_key=secret,
        )


class FakeSSL:
    def __init__(self, certificate: bytes) -> None:
        self.certificate = certificate

    def getpeercert(self, *, binary_form: bool = False) -> bytes | dict[str, object]:
        return self.certificate if binary_form else {}


@pytest.mark.asyncio
async def test_mtls_uses_peer_certificate_not_headers() -> None:
    certificate = b"verified-der-certificate"
    fingerprint = hashlib.sha256(certificate).hexdigest()
    secret = base64.urlsafe_b64encode(b"a" * 48).decode()
    settings = Settings(
        app_env="preproduction",
        auth_mode="mtls",
        live_authorization_enabled=True,
        database_url="postgresql+asyncpg://invalid/invalid",
        redis_url="redis://invalid/0",
        credential_encryption_key_v1=base64.urlsafe_b64encode(b"b" * 32).decode(),
        audit_hmac_key=secret,
        subject_hash_key=secret,
        credential_fingerprint_key=secret,
        mtls_principals={
            fingerprint: {
                "subject": "service-sip",
                "roles": ["service_sip"],
                "scopes": ["sip:session:create"],
            }
        },
    )
    principal = await MTLSPrincipalProvider(settings).authenticate(
        request(FakeSSL(certificate)), "Basic ignored"
    )
    assert principal.subject == "service-sip"
    with pytest.raises(AuthenticationError):
        await MTLSPrincipalProvider(settings).authenticate(request(), "Bearer fake")
