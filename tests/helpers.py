from datetime import UTC, datetime

from app.adapters import PermanentAdapterError, ProvisioningAdapter, RetryableAdapterError
from app.contracts import (
    ActionRequest,
    Operation,
    RequestExecution,
    StepCommand,
    TargetSystem,
)


class FakeAdapter(ProvisioningAdapter):
    def __init__(self, failures: list[Exception] | None = None):
        self.failures = failures or []
        self.calls: list[StepCommand] = []

    async def call(self, command: StepCommand):
        self.calls.append(command)
        if self.failures:
            raise self.failures.pop(0)
        return {
            "state": "verified" if command.operation in {Operation.VERIFY, Operation.RECONCILE}
            else "succeeded",
            "external_id": f"{command.target_system}:{command.employee_id}",
        }

    create_disabled = update = verify = activate = suspend = reactivate = call
    terminate = rotate_credentials = reconcile = call


def execution(
    *,
    request_id: str = "request-00000001",
    employee_id: str = "employee-0001",
    key: str = "idempotency-key-00000001",
    target: TargetSystem = TargetSystem.ODOO,
    operation: Operation = Operation.CREATE_DISABLED,
    steps: int = 1,
) -> RequestExecution:
    timestamp = datetime.now(UTC)
    commands = [
        StepCommand(
            schema_version="1.0",
            request_id=request_id,
            correlation_id=f"correlation-{request_id}",
            idempotency_key=f"{key}-step-{index}",
            employee_id=employee_id,
            target_system=target,
            operation=operation,
            timestamp=timestamp,
            step_id=f"step-{request_id}-{index}",
            sequence=index,
            max_attempts=3,
            payload={},
        )
        for index in range(steps)
    ]
    return RequestExecution(
        schema_version="1.0",
        request_id=request_id,
        correlation_id=f"correlation-{request_id}",
        idempotency_key=key,
        employee_id=employee_id,
        target_system=target,
        operation=operation,
        timestamp=timestamp,
        steps=commands,
    )


def action(
    request_id: str,
    operation: Operation,
    employee_id: str = "employee-0001",
) -> ActionRequest:
    return ActionRequest(
        schema_version="1.0",
        request_id=request_id,
        correlation_id=f"action-correlation-{request_id}",
        idempotency_key=f"action-idempotency-{request_id}-{operation}",
        employee_id=employee_id,
        target_system=TargetSystem.ODOO,
        operation=operation,
        timestamp=datetime.now(UTC),
        payload={},
    )


__all__ = [
    "FakeAdapter",
    "PermanentAdapterError",
    "RetryableAdapterError",
    "action",
    "execution",
]
