from __future__ import annotations
import base64, hashlib, hmac
from cryptography.fernet import Fernet

def fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()

class CredentialCipher:
    def __init__(self, key: bytes) -> None:
        self._cipher = Fernet(base64.urlsafe_b64encode(key[:32].ljust(32, b"0")))
    def encrypt(self, credential: str) -> str:
        return self._cipher.encrypt(credential.encode()).decode()
    def decrypt(self, value: str) -> str:
        return self._cipher.decrypt(value.encode()).decode()
