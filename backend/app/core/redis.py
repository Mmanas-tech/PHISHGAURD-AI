import time
from typing import Optional

from app.core.config import get_settings

settings = get_settings()

_redis_client = None
_memory_cache: dict[str, tuple[str, float]] = {}
_rate_limits: dict[str, tuple[int, float]] = {}


async def _get_redis_client():
    """Try to get Redis client, return None if unavailable."""
    global _redis_client
    if not settings.USE_REDIS:
        return None
    try:
        import redis.asyncio as aioredis

        if _redis_client is None:
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
            )
        return _redis_client
    except Exception:
        return None


async def close_redis() -> None:
    """Close Redis connection pool."""
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.close()
        except Exception:
            pass
        _redis_client = None


async def cache_get(key: str) -> Optional[str]:
    """Get a cached value (Redis or in-memory)."""
    client = await _get_redis_client()
    if client:
        try:
            return await client.get(key)
        except Exception:
            pass

    entry = _memory_cache.get(key)
    if entry:
        value, expires = entry
        if time.time() < expires:
            return value
        del _memory_cache[key]
    return None


async def cache_set(key: str, value: str, ttl: Optional[int] = None) -> None:
    """Set a cached value (Redis or in-memory)."""
    ttl = ttl or settings.REDIS_CACHE_TTL
    client = await _get_redis_client()
    if client:
        try:
            await client.setex(key, ttl, value)
            return
        except Exception:
            pass

    _memory_cache[key] = (value, time.time() + ttl)


async def cache_delete(key: str) -> None:
    """Delete a cached value."""
    client = await _get_redis_client()
    if client:
        try:
            await client.delete(key)
        except Exception:
            pass
    _memory_cache.pop(key, None)


async def incr_rate_limit(key: str, window: int = 60) -> int:
    """Increment rate limit counter."""
    client = await _get_redis_client()
    if client:
        try:
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window)
            results = await pipe.execute()
            return results[0]
        except Exception:
            pass

    now = time.time()
    count, expires = _rate_limits.get(key, (0, now + window))
    if now > expires:
        count = 0
        expires = now + window
    count += 1
    _rate_limits[key] = (count, expires)
    return count
