import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Protocol

from .redis_keys import RedisKeyspace


class RedisLike(Protocol):
    async def set(self, name: str, value: str, *, ex: int | None = None,
                  px: int | None = None, nx: bool = False) -> object: ...
    async def eval(self, script: str, numkeys: int, *args: str) -> object: ...
    async def incr(self, name: str) -> int: ...
    async def expire(self, name: str, seconds: int) -> object: ...
    async def ttl(self, name: str) -> int: ...


RELEASE = "if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end"
EXTEND = "if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('pexpire',KEYS[1],ARGV[2]) else return 0 end"
INCR_TTL = "local n=redis.call('incr',KEYS[1]); if n==1 then redis.call('expire',KEYS[1],ARGV[1]) end; return {n,redis.call('ttl',KEYS[1])}"


@dataclass(frozen=True)
class LockToken:
    key: str
    owner: str


class LockManager:
    def __init__(self, redis: RedisLike, keys: RedisKeyspace, ttl_seconds: int = 20) -> None:
        self.redis, self.keys, self.ttl_seconds = redis, keys, ttl_seconds

    async def acquire(self, subject_hash: str, operation: str, wait_seconds: float = 2.0) -> LockToken:
        key, owner = self.keys.lock(subject_hash, operation), str(uuid.uuid4())
        deadline = asyncio.get_running_loop().time() + wait_seconds
        while not await self.redis.set(key, owner, px=self.ttl_seconds * 1000, nx=True):
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("distributed lock unavailable")
            await asyncio.sleep(0.025)
        return LockToken(key, owner)

    async def release(self, token: LockToken) -> bool:
        return bool(await self.redis.eval(RELEASE, 1, token.key, token.owner))

    async def extend(self, token: LockToken) -> bool:
        return bool(await self.redis.eval(EXTEND, 1, token.key, token.owner, str(self.ttl_seconds * 1000)))


class ReplayGuard:
    def __init__(self, redis: RedisLike, keys: RedisKeyspace, ttl_seconds: int = 900) -> None:
        self.redis, self.keys, self.ttl_seconds = redis, keys, ttl_seconds

    async def claim(self, nonce_hash: str) -> bool:
        return bool(await self.redis.set(self.keys.replay(nonce_hash), "1", ex=self.ttl_seconds, nx=True))


class RateLimitService:
    def __init__(self, redis: RedisLike, keys: RedisKeyspace) -> None:
        self.redis, self.keys = redis, keys

    async def check(self, subject_hash: str, route: str, limit: int, window_seconds: int) -> int:
        window = str(int(time.time()) // window_seconds)
        key = self.keys.ratelimit(subject_hash, route, window)
        result = await self.redis.eval(INCR_TTL, 1, key, str(window_seconds + 1))
        count, ttl = int(result[0]), int(result[1])  # type: ignore[index]
        if ttl <= 0:
            raise RuntimeError("rate-limit key lacks TTL")
        if count > limit:
            raise PermissionError(str(ttl))
        return ttl
