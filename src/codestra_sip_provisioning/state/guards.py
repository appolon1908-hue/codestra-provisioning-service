from __future__ import annotations
import time, uuid
from typing import Any, Protocol
from .redis_keys import RedisKeyspace

class RedisLike(Protocol):
    async def set(self, name: str, value: str, ex: int | None = None, nx: bool = False) -> Any: ...
    async def delete(self, *names: str) -> Any: ...
    async def incr(self, name: str) -> int: ...
    async def expire(self, name: str, time: int) -> Any: ...

class LockManager:
    def __init__(self, redis: RedisLike, keys: RedisKeyspace, ttl: int = 15) -> None:
        self.redis, self.keys, self.ttl = redis, keys, ttl
    async def acquire(self, subject: str, operation: str) -> str:
        token = str(uuid.uuid4())
        if not await self.redis.set(self.keys.lock(subject, operation), token, ex=self.ttl, nx=True):
            raise RuntimeError("state lock unavailable")
        return token
    async def release(self, subject: str, operation: str, token: str) -> None:
        await self.redis.delete(self.keys.lock(subject, operation))

class ReplayGuard:
    def __init__(self, redis: RedisLike, keys: RedisKeyspace, ttl: int = 900) -> None:
        self.redis, self.keys, self.ttl = redis, keys, ttl
    async def claim(self, nonce: str) -> bool:
        return bool(await self.redis.set(self.keys.replay(nonce), "1", ex=self.ttl, nx=True))

class RateLimitService:
    def __init__(self, redis: RedisLike, keys: RedisKeyspace) -> None:
        self.redis, self.keys = redis, keys
    async def check(self, subject: str, route: str, limit: int, window_seconds: int) -> bool:
        window = str(int(time.time()) // window_seconds)
        key = self.keys.ratelimit(subject, route, window)
        count = await self.redis.incr(key)
        if count == 1: await self.redis.expire(key, window_seconds)
        return count <= limit
