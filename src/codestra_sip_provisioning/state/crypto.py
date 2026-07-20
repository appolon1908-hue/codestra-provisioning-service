import base64
import hashlib
import hmac
import json
import os
from datetime import UTC, datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def keyed_hash(value: str, key: bytes, domain: str) -> str:
    return hmac.new(key, (domain + "\0" + value).encode(), hashlib.sha256).hexdigest()


def fingerprint(value: str, key: bytes) -> str:
    return keyed_hash(value, key, "codestra:sip:credential:v1")


class CredentialCipher:
    def __init__(self, keys: dict[str, bytes], active_version: str, service_name: str) -> None:
        if active_version not in keys or len(keys[active_version]) != 32:
            raise ValueError("AES-256-GCM requires an available 32-byte key")
        self._keys = keys
        self.active_version = active_version
        self.service_name = service_name

    @staticmethod
    def aad(service: str, session_id: str, subject_hash: str, endpoint: str, version: str) -> bytes:
        return f"{service}|{session_id}|{subject_hash}|{endpoint}|{version}".encode()

    def encrypt(
        self,
        credential: str,
        session_id: str,
        subject_hash: str,
        endpoint: str,
        expires_at: datetime,
    ) -> str:
        nonce = os.urandom(12)
        version = self.active_version
        ciphertext = AESGCM(self._keys[version]).encrypt(
            nonce,
            credential.encode(),
            self.aad(self.service_name, session_id, subject_hash, endpoint, version),
        )
        return json.dumps(
            {
                "algorithm": "AES-256-GCM",
                "key_version": version,
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "issued_at": datetime.now(UTC).isoformat(),
                "expires_at": expires_at.isoformat(),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def decrypt(self, envelope: str, session_id: str, subject_hash: str, endpoint: str) -> str:
        data = json.loads(envelope)
        version = data["key_version"]
        key = self._keys.get(version)
        if key is None or datetime.fromisoformat(data["expires_at"]) <= datetime.now(UTC):
            raise ValueError("credential envelope is unavailable")
        clear = AESGCM(key).decrypt(
            base64.b64decode(data["nonce"]),
            base64.b64decode(data["ciphertext"]),
            self.aad(self.service_name, session_id, subject_hash, endpoint, version),
        )
        return clear.decode()
