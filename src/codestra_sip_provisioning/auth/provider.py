import hashlib
import json
from collections.abc import Mapping
from typing import Any, Protocol, cast

import httpx
import jwt
from fastapi import Request
from jwt import InvalidTokenError, PyJWK

from ..config import Settings
from .principal import Principal, PrincipalKind


class AuthenticationError(Exception):
    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


class PrincipalProvider(Protocol):
    async def authenticate(self, request: Request, authorization: str | None) -> Principal: ...


def _bearer(authorization: str | None) -> str:
    if not authorization:
        raise AuthenticationError(401, "authentication_required", "authentication required")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token or " " in token:
        raise AuthenticationError(401, "invalid_authorization", "invalid bearer authorization")
    return token


def _claim_set(value: object, claim: str) -> frozenset[str]:
    if isinstance(value, str):
        items = value.split()
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        items = cast(list[str], value)
    else:
        raise AuthenticationError(403, "invalid_claim", f"invalid {claim} claim")
    return frozenset(items)


class JWTPrincipalProvider:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self.client = client

    async def _verification_key(self, token: str) -> Any:
        if self.settings.jwt_pinned_public_key:
            return self.settings.jwt_pinned_public_key
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise AuthenticationError(401, "invalid_token", "token key id is required")
            client = self.client or httpx.AsyncClient(timeout=3.0, follow_redirects=False)
            try:
                response = await client.get(cast(str, self.settings.jwt_jwks_url))
                response.raise_for_status()
                document = response.json()
            finally:
                if self.client is None:
                    await client.aclose()
            keys = document.get("keys") if isinstance(document, dict) else None
            matches = [key for key in keys or [] if isinstance(key, dict) and key.get("kid") == kid]
            if len(matches) != 1:
                raise AuthenticationError(401, "invalid_token", "token signing key is unavailable")
            return PyJWK.from_dict(matches[0]).key
        except AuthenticationError:
            raise
        except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError) as exc:
            raise AuthenticationError(
                503, "identity_provider_unavailable", "identity provider unavailable"
            ) from exc

    async def authenticate(self, request: Request, authorization: str | None) -> Principal:
        if request.query_params.get("access_token") is not None:
            raise AuthenticationError(400, "token_in_url", "tokens in URLs are prohibited")
        token = _bearer(authorization)
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            if algorithm not in self.settings.jwt_allowed_algorithms or algorithm == "none":
                raise AuthenticationError(
                    401, "invalid_algorithm", "token algorithm is not allowed"
                )
            payload = jwt.decode(
                token,
                await self._verification_key(token),
                algorithms=list(self.settings.jwt_allowed_algorithms),
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                leeway=self.settings.jwt_clock_skew_seconds,
                options={"require": ["iss", "aud", "sub", "exp", "nbf"]},
            )
        except AuthenticationError:
            raise
        except InvalidTokenError as exc:
            raise AuthenticationError(401, "invalid_token", "token validation failed") from exc
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject.strip() or len(subject) > 255:
            raise AuthenticationError(401, "invalid_subject", "stable token subject is required")
        if payload.get(self.settings.jwt_token_type_claim) != self.settings.jwt_expected_token_type:
            raise AuthenticationError(401, "wrong_token_type", "access token type is required")
        roles = _claim_set(payload.get(self.settings.jwt_role_claim), self.settings.jwt_role_claim)
        scopes = _claim_set(
            payload.get(self.settings.jwt_scope_claim), self.settings.jwt_scope_claim
        )
        if not roles <= self.settings.allowed_roles or not scopes <= self.settings.allowed_scopes:
            raise AuthenticationError(
                403, "unrecognized_authority", "token authority is not recognized"
            )
        kind = (
            PrincipalKind.SERVICE
            if any(role.startswith("service_") for role in roles)
            else PrincipalKind.USER
        )
        return Principal(subject, roles, scopes, kind, cast(str, payload["iss"]))


class MTLSPrincipalProvider:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def authenticate(self, request: Request, authorization: str | None) -> Principal:
        del authorization
        ssl_object = request.scope.get("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not certificate:
            raise AuthenticationError(
                401, "client_certificate_required", "verified client certificate required"
            )
        fingerprint = hashlib.sha256(certificate).hexdigest()
        definition = self.settings.mtls_principals.get(fingerprint)
        if definition is None:
            raise AuthenticationError(
                403, "untrusted_client_certificate", "client certificate is not trusted"
            )
        roles = frozenset(definition.roles)
        if not roles or any(not role.startswith("service_") for role in roles):
            raise AuthenticationError(
                403, "invalid_service_role", "mTLS principals require service roles"
            )
        return Principal(
            definition.subject, roles, frozenset(definition.scopes), PrincipalKind.SERVICE, "mtls"
        )


class TestPrincipalProvider:
    def __init__(
        self, settings: Settings, principals: Mapping[str, Principal] | None = None
    ) -> None:
        if settings.app_env != "test" or settings.auth_mode != "test":
            raise ValueError("TestPrincipalProvider is restricted to APP_ENV=test")
        self.principals = principals

    async def authenticate(self, request: Request, authorization: str | None) -> Principal:
        del request
        token = _bearer(authorization)
        if self.principals is not None:
            principal = self.principals.get(token)
            if principal is None:
                raise AuthenticationError(401, "invalid_test_principal", "invalid test principal")
            return principal
        if not token.startswith("test:"):
            raise AuthenticationError(401, "invalid_test_principal", "invalid test principal")
        subject = token.removeprefix("test:")
        if not subject or len(subject) > 255:
            raise AuthenticationError(401, "invalid_test_principal", "invalid test principal")
        return Principal(
            subject,
            frozenset({"agent"}),
            frozenset({"sip:session:create", "sip:session:renew", "sip:session:revoke"}),
            PrincipalKind.TEST,
            "test",
        )


class DisabledTrustedProvider:
    async def authenticate(self, request: Request, authorization: str | None) -> Principal:
        del request, authorization
        raise AuthenticationError(
            503, "trusted_authentication_unconfigured", "trusted authentication is not configured"
        )


def build_principal_provider(settings: Settings) -> PrincipalProvider:
    if settings.auth_mode == "jwt":
        return JWTPrincipalProvider(settings)
    if settings.auth_mode == "mtls":
        return MTLSPrincipalProvider(settings)
    if settings.auth_mode == "test":
        return TestPrincipalProvider(settings)
    return DisabledTrustedProvider()
