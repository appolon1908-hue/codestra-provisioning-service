import base64
import json
import os
from pathlib import Path

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("AUTH_MODE", "test")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://fake:fake@invalid/fake")
os.environ.setdefault("REDIS_URL", "redis://invalid:6379/15")
os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY_V1", base64.urlsafe_b64encode(b"0" * 32).decode())
os.environ.setdefault("AUDIT_HMAC_KEY", base64.urlsafe_b64encode(os.urandom(48)).decode())
os.environ.setdefault("SUBJECT_HASH_KEY", base64.urlsafe_b64encode(os.urandom(48)).decode())
os.environ.setdefault(
    "CREDENTIAL_FINGERPRINT_KEY", base64.urlsafe_b64encode(os.urandom(48)).decode()
)

from codestra_sip_provisioning.main import app  # noqa: E402

Path("docs/openapi.yaml").write_text(
    json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
