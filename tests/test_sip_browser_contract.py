import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.adapters import TelephonyProvisioningAdapter
from app.contracts import Operation, SipBrowserSessionRequest, TargetSystem
from app.sip_browser import SipBrowserSessionError, SipBrowserSessionManager


class FakeSipAdapter(TelephonyProvisioningAdapter):
    def __init__(self):
        pass


class FakeRepository:
    def employee_results(self, employee_id):
        del employee_id
        return [
            SimpleNamespace(
                target_system=target,
                external_id=external_id,
                operation=Operation.ACTIVATE,
            )
            for target, external_id in (
                (TargetSystem.KEYCLOAK, "12345678-1234-4234-9234-123456789abc"),
                (TargetSystem.VICIDIAL, "synthetic_agent"),
                (TargetSystem.SIP, "6101"),
            )
        ]

    def employee_commands(self, employee_id):
        del employee_id
        return [
            SimpleNamespace(
                target_system=TargetSystem.KEYCLOAK,
                payload={"attributes": {"role_template": "AGENT"}},
            ),
            SimpleNamespace(
                target_system=TargetSystem.VICIDIAL,
                payload={"username": "synthetic_agent", "campaigns": ["TEST_SYN"]},
            ),
            SimpleNamespace(
                target_system=TargetSystem.SIP,
                payload={"extension": 6101},
            ),
        ]


def values(**changes):
    result = {
        "employee_id": "APP-DESKTOP-STAGE-001",
        "keycloak_subject": "12345678-1234-4234-9234-123456789abc",
        "odoo_employee_id": "APP-DESKTOP-STAGE-001",
        "vicidial_username": "synthetic_agent",
        "endpoint": 6101,
        "campaign": "TEST_SYN",
        "role": "AGENT",
        "browser_session_binding": str(uuid.uuid4()),
    }
    result.update(changes)
    return result


def manager():
    return SipBrowserSessionManager(
        FakeRepository(),
        {TargetSystem.SIP.value: FakeSipAdapter()},
        "/unused/turn-secret",
        endpoint=6101,
        campaign="TEST_SYN",
    )


def test_only_canonical_subject_test_syn_and_6101_are_authorized():
    service = manager()
    service._validated_command(SipBrowserSessionRequest(**values()))
    for change in (
        {"keycloak_subject": "00000000-0000-4000-8000-000000000000"},
        {"campaign": "OTHER"},
        {"endpoint": 6102},
    ):
        with pytest.raises(SipBrowserSessionError):
            service._validated_command(SipBrowserSessionRequest(**values(**change)))


def test_machine_request_cannot_assert_tenant_or_production_mode():
    with pytest.raises(ValidationError):
        SipBrowserSessionRequest(**values(tenant_id="OTHER"))
    with pytest.raises(ValidationError):
        SipBrowserSessionRequest(**values(production=True))
