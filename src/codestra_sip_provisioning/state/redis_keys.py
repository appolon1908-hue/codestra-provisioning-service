import re

SAFE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RedisKeyspace:
    def __init__(self, namespace: str = "codestra:sip:v1") -> None:
        if not SAFE.fullmatch(namespace):
            raise ValueError("invalid Redis namespace")
        self.namespace = namespace.rstrip(":")

    @staticmethod
    def _safe(value: str) -> str:
        if not SAFE.fullmatch(value) or any(ord(char) < 32 for char in value):
            raise ValueError("unsafe Redis key component")
        return value

    @staticmethod
    def _hash(value: str) -> str:
        if not HEX64.fullmatch(value):
            raise ValueError("expected keyed HMAC digest")
        return value

    def session(self, session_id: str) -> str:
        return f"{self.namespace}:sessions:{self._safe(session_id)}"

    def credential(self, session_id: str) -> str:
        return f"{self.namespace}:credentials:{self._safe(session_id)}"

    def old_credential(self, session_id: str) -> str:
        return f"{self.namespace}:credentials:{self._safe(session_id)}:previous"

    def lease(self, subject_hash: str) -> str:
        return f"{self.namespace}:leases:{self._hash(subject_hash)}"

    def lock(self, subject_hash: str, operation: str) -> str:
        return f"{self.namespace}:locks:{self._hash(subject_hash)}:{self._safe(operation)}"

    def replay(self, nonce_hash: str) -> str:
        return f"{self.namespace}:replay:{self._hash(nonce_hash)}"

    def ratelimit(self, subject_hash: str, route: str, window: str) -> str:
        return f"{self.namespace}:ratelimit:{self._hash(subject_hash)}:{self._safe(route)}:{self._safe(window)}"

    def endpoint(self, endpoint_name: str) -> str:
        if not re.fullmatch(r"mock-[0-9a-f]{12}", endpoint_name):
            raise ValueError("invalid mock endpoint")
        return f"{self.namespace}:endpoints:{endpoint_name}"
