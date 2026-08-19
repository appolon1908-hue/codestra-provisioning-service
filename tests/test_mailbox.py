import asyncio
import secrets

import pytest

from app.mailbox import (
    AddressCollision,
    LicenseExhausted,
    MailboxProvider,
    MailboxProviderUnavailable,
    MailboxProvisioningService,
    MailboxRepository,
    configured_mailbox_provider,
)


class SyntheticMailProvider(MailboxProvider):
    def __init__(self, licenses=2):
        self.licenses = licenses
        self.mailboxes = {}
        self.requests = {}
        self.activation_messages = {}
        self.inbox = {}
        self.timeout = False
        self.calls = 0

    async def _guard(self):
        if self.timeout:
            raise MailboxProviderUnavailable("provider_timeout")

    async def check_availability(self, email_address):
        await self._guard()
        return email_address not in self.mailboxes

    async def reserve_address(self, email_address, idempotency_key):
        await self._guard()
        return {"state": "reserved"}

    async def create_mailbox_disabled(self, email_address, idempotency_key):
        await self._guard()
        if idempotency_key in self.requests:
            return self.requests[idempotency_key]
        external_id = "synthetic-" + str(len(self.mailboxes) + 1)
        value = {
            "external_mailbox_id": external_id, "state": "disabled",
            "aliases": [], "email_address": email_address,
        }
        self.mailboxes[email_address] = value
        self.requests[idempotency_key] = value
        self.calls += 1
        return value

    def _mailbox(self, external_id):
        return next(
            value for value in self.mailboxes.values()
            if value["external_mailbox_id"] == external_id
        )

    async def assign_license(self, external_mailbox_id, idempotency_key):
        await self._guard()
        if self.licenses <= 0:
            raise LicenseExhausted("license_exhaustion")
        self.licenses -= 1
        return {"state": "licensed"}

    async def create_alias(self, external_mailbox_id, alias, idempotency_key):
        await self._guard()
        self._mailbox(external_mailbox_id)["aliases"].append(alias)
        return {"state": "created"}

    async def send_activation(
        self, external_mailbox_id, activation_recipient, idempotency_key
    ):
        await self._guard()
        token = secrets.token_urlsafe(24)
        self.activation_messages[activation_recipient] = token
        return {"state": "sent", "delivery_reference": "synthetic-mail-sink"}

    async def verify_mailbox(self, external_mailbox_id):
        await self._guard()
        return dict(self._mailbox(external_mailbox_id))

    async def activate_mailbox(
        self, external_mailbox_id, activation_token, idempotency_key
    ):
        await self._guard()
        if activation_token not in self.activation_messages.values():
            return {"state": "disabled"}
        mailbox = self._mailbox(external_mailbox_id)
        mailbox["state"] = "active"
        return {"state": "active"}

    async def suspend_mailbox(self, external_mailbox_id, idempotency_key):
        await self._guard()
        self._mailbox(external_mailbox_id)["state"] = "suspended"
        return {"state": "suspended"}

    async def reactivate_mailbox(self, external_mailbox_id, idempotency_key):
        await self._guard()
        self._mailbox(external_mailbox_id)["state"] = "active"
        return {"state": "active"}

    async def terminate_mailbox(self, external_mailbox_id, idempotency_key):
        await self._guard()
        self._mailbox(external_mailbox_id)["state"] = "terminated"
        return {"state": "terminated"}

    async def reconcile_mailbox(self, external_mailbox_id):
        await self._guard()
        return dict(self._mailbox(external_mailbox_id))

    async def send_test_message(self, external_id, body):
        mailbox = self._mailbox(external_id)
        if mailbox["state"] != "active":
            raise RuntimeError("mailbox_disabled")
        digest = __import__("hashlib").sha256(body.encode()).hexdigest()
        self.inbox[external_id] = digest
        return digest


def service(tmp_path, provider=None):
    provider = provider or SyntheticMailProvider()
    return (
        MailboxProvisioningService(
            "synthetic_mail_sink", provider,
            MailboxRepository(str(tmp_path / "mailboxes.sqlite3")),
            "protected_file:/run/secrets/synthetic-mail-test",
        ),
        provider,
    )


@pytest.mark.asyncio
async def test_available_address_duplicate_activation_send_receive_lifecycle(tmp_path):
    adapter, provider = service(tmp_path)
    record = await adapter.provision(
        "mailbox-gate-001@invalid.example",
        ["alias-gate-001@invalid.example"],
        "activation-sink@invalid.example",
        "mailbox-request-0001",
    )
    assert record.provisioning_state == "awaiting_activation"
    duplicate = await adapter.provision(
        record.email_address, record.aliases,
        "activation-sink@invalid.example", "mailbox-request-0001",
    )
    assert duplicate == record and provider.calls == 1
    token = provider.activation_messages["activation-sink@invalid.example"]
    active = await adapter.activate(record.email_address, token, "activate-0001")
    assert active.provisioning_state == "active"
    sent = await provider.send_test_message(active.external_mailbox_id, "synthetic")
    assert provider.inbox[active.external_mailbox_id] == sent
    assert (await adapter.verify(record.email_address))["state"] == "active"
    suspended = await adapter.suspend(record.email_address, "suspend-0001")
    assert suspended.provisioning_state == "suspended"
    reactivated = await adapter.reactivate(record.email_address, "reactivate-0001")
    assert reactivated.provisioning_state == "active"
    assert (await adapter.reconcile(record.email_address))["aligned"]
    terminated = await adapter.terminate(record.email_address, "terminate-0001")
    assert terminated.provisioning_state == "terminated"
    assert (await adapter.reconcile(record.email_address))["aligned"]


@pytest.mark.asyncio
async def test_collision(tmp_path):
    adapter, provider = service(tmp_path)
    provider.mailboxes["collision@invalid.example"] = {
        "external_mailbox_id": "existing", "email_address": "collision@invalid.example",
        "state": "active", "aliases": [],
    }
    with pytest.raises(AddressCollision):
        await adapter.provision(
            "collision@invalid.example", [], "sink@invalid.example",
            "mailbox-collision-0001",
        )


@pytest.mark.asyncio
async def test_provider_timeout(tmp_path):
    adapter, provider = service(tmp_path)
    provider.timeout = True
    with pytest.raises(MailboxProviderUnavailable):
        await adapter.provision(
            "timeout@invalid.example", [], "sink@invalid.example",
            "mailbox-timeout-0001",
        )


@pytest.mark.asyncio
async def test_license_exhaustion(tmp_path):
    adapter, _provider = service(tmp_path, SyntheticMailProvider(licenses=0))
    with pytest.raises(LicenseExhausted):
        await adapter.provision(
            "license@invalid.example", [], "sink@invalid.example",
            "mailbox-license-0001",
        )


def test_runtime_provider_is_disabled_without_approved_reference(monkeypatch):
    monkeypatch.delenv("CODESTRA_MAILBOX_PROVIDER", raising=False)
    monkeypatch.delenv("CODESTRA_MAILBOX_CREDENTIAL_REFERENCE", raising=False)
    name, provider, reference = configured_mailbox_provider()
    assert name == "unconfigured" and reference == "unconfigured"
    with pytest.raises(MailboxProviderUnavailable):
        asyncio.run(provider.check_availability("test@invalid.example"))


def test_repository_schema_contains_only_approved_mailbox_fields(tmp_path):
    repository = MailboxRepository(str(tmp_path / "mailboxes.sqlite3"))
    with repository._connect() as connection:
        columns = {
            row["name"] for row in connection.execute(
                "PRAGMA table_info(mailboxes)"
            ).fetchall()
        }
    assert columns == {
        "email_address", "provider", "external_mailbox_id", "aliases",
        "provisioning_state", "created_at", "activated_at", "suspended_at",
        "terminated_at", "credential_reference",
    }
    assert not {"password", "token", "secret"}.intersection(columns)
