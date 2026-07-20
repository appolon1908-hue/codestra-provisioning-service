import re
from collections.abc import Mapping
from typing import Any

SENSITIVE = re.compile(
    r"password|passwd|pass|secret|token|authorization|credential|cookie|private_key|api_key",
    re.IGNORECASE,
)
URL_SECRET = re.compile(r"([?&][^=]*(?:token|password|secret|credential)[^=]*=)[^&#\s]+", re.I)


def redact(value: Any, key: str = "") -> Any:
    if SENSITIVE.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, BaseException):
        return {"type": type(value).__name__, "message": "[REDACTED_EXCEPTION]"}
    if isinstance(value, str):
        return URL_SECRET.sub(r"\1[REDACTED]", value)
    return value
