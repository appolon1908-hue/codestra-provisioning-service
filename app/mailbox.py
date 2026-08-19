from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class MailboxProviderError(RuntimeError):
    code = "provider_error"


class MailboxProviderUnavailable(MailboxProviderError):
    code = "provider_timeout"


class AddressCollision(MailboxProviderError):
    code = "address_collision"


class LicenseExhausted(MailboxProviderError):
    code = "license_exhaustion"


class InvalidMailboxState(MailboxProviderError):
    code = "invalid_mailbox_state"


class MailboxProvider(ABC):
    """Provider capability contract. Implementations must never return passwords."""

    @abstractmethod
    async def check_availability(self, email_address: str) -> bool: ...

    @abstractmethod
    async def reserve_address(
        self, email_address: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def create_mailbox_disabled(
        self, email_address: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def assign_license(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def create_alias(
        self, external_mailbox_id: str, alias: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def send_activation(
        self, external_mailbox_id: str, activation_recipient: str,
        idempotency_key: str,
    ) -> dict: ...

    @abstractmethod
    async def verify_mailbox(self, external_mailbox_id: str) -> dict: ...

    @abstractmethod
    async def activate_mailbox(
        self, external_mailbox_id: str, activation_token: str,
        idempotency_key: str,
    ) -> dict: ...

    @abstractmethod
    async def suspend_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def reactivate_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def terminate_mailbox(
        self, external_mailbox_id: str, idempotency_key: str
    ) -> dict: ...

    @abstractmethod
    async def reconcile_mailbox(self, external_mailbox_id: str) -> dict: ...


class DisabledMailboxProvider(MailboxProvider):
    """Fail closed when an approved provider credential is absent."""

    async def _blocked(self, *_args, **_kwargs):
        raise MailboxProviderUnavailable("mailbox_provider_not_configured")

    check_availability = _blocked
    reserve_address = _blocked
    create_mailbox_disabled = _blocked
    assign_license = _blocked
    create_alias = _blocked
    send_activation = _blocked
    verify_mailbox = _blocked
    activate_mailbox = _blocked
    suspend_mailbox = _blocked
    reactivate_mailbox = _blocked
    terminate_mailbox = _blocked
    reconcile_mailbox = _blocked


@dataclass(frozen=True)
class MailboxRecord:
    email_address: str
    provider: str
    external_mailbox_id: str
    aliases: list[str]
    provisioning_state: str
    created_at: str
    activated_at: str | None
    suspended_at: str | None
    terminated_at: str | None
    credential_reference: str


class MailboxRepository:
    """SQLite projection containing only the approved mailbox fields."""

    COLUMNS = tuple(MailboxRecord.__dataclass_fields__)

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS mailboxes(
                email_address TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                external_mailbox_id TEXT NOT NULL UNIQUE,
                aliases TEXT NOT NULL,
                provisioning_state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                suspended_at TEXT,
                terminated_at TEXT,
                credential_reference TEXT NOT NULL)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS mailbox_requests(
                idempotency_key TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                email_address TEXT NOT NULL)"""
            )

    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def get(self, email_address: str) -> MailboxRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM mailboxes WHERE email_address=?", (email_address,)
            ).fetchone()
        if not row:
            return None
        values = dict(row)
        values["aliases"] = json.loads(values["aliases"])
        return MailboxRecord(**values)

    def request(self, idempotency_key: str, payload: dict) -> MailboxRecord | None:
        request_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT request_hash,email_address FROM mailbox_requests "
                "WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
        if not row:
            return None
        if row["request_hash"] != request_hash:
            raise AddressCollision("idempotency_conflict")
        return self.get(row["email_address"])

    def save(
        self, record: MailboxRecord, idempotency_key: str | None = None,
        request_payload: dict | None = None,
    ) -> None:
        values = asdict(record)
        values["aliases"] = json.dumps(values["aliases"], sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO mailboxes VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(email_address) DO UPDATE SET
                provider=excluded.provider,
                external_mailbox_id=excluded.external_mailbox_id,
                aliases=excluded.aliases,
                provisioning_state=excluded.provisioning_state,
                created_at=excluded.created_at,
                activated_at=excluded.activated_at,
                suspended_at=excluded.suspended_at,
                terminated_at=excluded.terminated_at,
                credential_reference=excluded.credential_reference""",
                tuple(values[column] for column in self.COLUMNS),
            )
            if idempotency_key and request_payload is not None:
                request_hash = hashlib.sha256(
                    json.dumps(
                        request_payload, sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest()
                connection.execute(
                    "INSERT OR IGNORE INTO mailbox_requests VALUES(?,?,?)",
                    (idempotency_key, request_hash, record.email_address),
                )


class MailboxProvisioningService:
    def __init__(
        self, provider_name: str, provider: MailboxProvider,
        repository: MailboxRepository, credential_reference: str,
    ):
        self.provider_name = provider_name
        self.provider = provider
        self.repository = repository
        self.credential_reference = credential_reference

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    async def provision(
        self, email_address: str, aliases: list[str], activation_recipient: str,
        idempotency_key: str,
    ) -> MailboxRecord:
        payload = {
            "email_address": email_address,
            "aliases": sorted(set(aliases)),
            "activation_recipient": activation_recipient,
        }
        replay = self.repository.request(idempotency_key, payload)
        if replay:
            return replay
        if not await self.provider.check_availability(email_address):
            raise AddressCollision("address_collision")
        await self.provider.reserve_address(email_address, idempotency_key + ":reserve")
        created = await self.provider.create_mailbox_disabled(
            email_address, idempotency_key + ":create"
        )
        external_id = created["external_mailbox_id"]
        await self.provider.assign_license(external_id, idempotency_key + ":license")
        for alias in payload["aliases"]:
            await self.provider.create_alias(
                external_id, alias, idempotency_key + ":alias:" + alias
            )
        activation = await self.provider.send_activation(
            external_id, activation_recipient, idempotency_key + ":activation"
        )
        if "password" in json.dumps(activation).lower():
            raise MailboxProviderError("provider_returned_forbidden_secret")
        record = MailboxRecord(
            email_address=email_address,
            provider=self.provider_name,
            external_mailbox_id=external_id,
            aliases=payload["aliases"],
            provisioning_state="awaiting_activation",
            created_at=self._now(),
            activated_at=None,
            suspended_at=None,
            terminated_at=None,
            credential_reference=self.credential_reference,
        )
        self.repository.save(record, idempotency_key, payload)
        return record

    async def activate(
        self, email_address: str, one_time_token: str, idempotency_key: str
    ) -> MailboxRecord:
        record = self._require(email_address)
        result = await self.provider.activate_mailbox(
            record.external_mailbox_id, one_time_token, idempotency_key
        )
        if result.get("state") != "active":
            raise InvalidMailboxState("activation_not_confirmed")
        return self._replace(
            record, provisioning_state="active", activated_at=self._now()
        )

    async def suspend(self, email_address: str, idempotency_key: str):
        record = self._require(email_address)
        await self.provider.suspend_mailbox(
            record.external_mailbox_id, idempotency_key
        )
        return self._replace(
            record, provisioning_state="suspended", suspended_at=self._now()
        )

    async def reactivate(self, email_address: str, idempotency_key: str):
        record = self._require(email_address)
        await self.provider.reactivate_mailbox(
            record.external_mailbox_id, idempotency_key
        )
        return self._replace(
            record, provisioning_state="active", suspended_at=None
        )

    async def terminate(self, email_address: str, idempotency_key: str):
        record = self._require(email_address)
        await self.provider.terminate_mailbox(
            record.external_mailbox_id, idempotency_key
        )
        return self._replace(
            record, provisioning_state="terminated", terminated_at=self._now()
        )

    async def reconcile(self, email_address: str):
        record = self._require(email_address)
        actual = await self.provider.reconcile_mailbox(
            record.external_mailbox_id
        )
        return {
            "aligned": actual.get("state") == record.provisioning_state
            and sorted(actual.get("aliases", [])) == sorted(record.aliases),
            "expected_state": record.provisioning_state,
            "actual_state": actual.get("state"),
        }

    async def verify(self, email_address: str):
        record = self._require(email_address)
        return await self.provider.verify_mailbox(record.external_mailbox_id)

    def _require(self, email_address: str) -> MailboxRecord:
        record = self.repository.get(email_address)
        if not record:
            raise InvalidMailboxState("mailbox_not_found")
        return record

    def _replace(self, record: MailboxRecord, **changes: Any) -> MailboxRecord:
        values = asdict(record)
        values.update(changes)
        updated = MailboxRecord(**values)
        self.repository.save(updated)
        return updated


def configured_mailbox_provider() -> tuple[str, MailboxProvider, str]:
    """Select only an explicitly approved provider reference."""
    provider = os.getenv("CODESTRA_MAILBOX_PROVIDER", "").strip()
    credential_reference = os.getenv(
        "CODESTRA_MAILBOX_CREDENTIAL_REFERENCE", ""
    ).strip()
    approved = {
        "google_workspace", "microsoft_365", "cpanel_whm", "hosted_mail"
    }
    if provider not in approved or not credential_reference:
        return "unconfigured", DisabledMailboxProvider(), "unconfigured"
    # Provider-specific network clients are intentionally not inferred merely
    # from a name/reference. A concrete approved implementation must replace
    # this fail-closed provider.
    return provider, DisabledMailboxProvider(), credential_reference
