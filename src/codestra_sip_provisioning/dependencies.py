import base64

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import Settings
from .services.lifecycle import DurableSessionService
from .state.crypto import CredentialCipher


def build_service(settings: Settings) -> tuple[DurableSessionService, object, Redis]:
    engine = create_async_engine(settings.database_url, pool_pre_ping=True,
                                 connect_args={"server_settings": {"application_name": settings.service_name,
                                                "statement_timeout": "10000"}})
    sessions = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        key = base64.urlsafe_b64decode(settings.credential_encryption_key_v1 + "===")
    except Exception as exc:
        raise ValueError("invalid credential encryption key") from exc
    cipher = CredentialCipher({"v1": key}, settings.credential_encryption_key_version,
                              settings.service_name)
    return DurableSessionService(sessions, redis, settings, cipher), engine, redis
