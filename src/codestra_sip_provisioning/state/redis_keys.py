from __future__ import annotations
import hashlib

class RedisKeyspace:
    def __init__(self, namespace: str = "codestra:sip:v1") -> None:
        self.namespace = namespace.rstrip(":")
    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()
    def session(self, session_id: str) -> str: return f"{self.namespace}:sessions:{session_id}"
    def credential(self, session_id: str) -> str: return f"{self.namespace}:credentials:{session_id}"
    def lease(self, subject: str) -> str: return f"{self.namespace}:leases:{self.digest(subject)}"
    def lock(self, subject: str, operation: str) -> str: return f"{self.namespace}:locks:{self.digest(subject)}:{operation}"
    def replay(self, nonce: str) -> str: return f"{self.namespace}:replay:{self.digest(nonce)}"
    def ratelimit(self, subject: str, route: str, window: str) -> str: return f"{self.namespace}:ratelimit:{self.digest(subject)}:{route}:{window}"
    def endpoint(self, endpoint_name: str) -> str: return f"{self.namespace}:endpoints:{self.digest(endpoint_name)}"
