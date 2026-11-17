"""Redis storage, every value encrypted with Fernet. Token keys are stored as sha256 digests."""

import hashlib
from collections.abc import Iterable
from types import TracebackType
from typing import Any, TypeVar

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel
from redis.asyncio import Redis
from redis.asyncio.lock import Lock
from redis.exceptions import RedisError

M = TypeVar("M", bound=BaseModel)

PREFIX = "lightdash-mcp"
REDIS_TIMEOUT = 5  # seconds: a Redis that stops answering fails a request instead of hanging it
# One retry, on a new connection, covers a pooled connection that Redis closed (a restart, an idle
# timeout). More retries only make a Redis that stopped answering fail later, REDIS_TIMEOUT per
# attempt, and run again a command whose answer was lost (docs/architecture.md).
REDIS_RETRIES = 1
REDIS_ATTEMPTS = REDIS_RETRIES + 1
REDIS_COMMAND_TIMEOUT = REDIS_ATTEMPTS * REDIS_TIMEOUT  # about the longest a command takes to fail
# Long enough for the work under a grant's lock to end before it expires, even when Redis stalls:
# a refresh's Lightdash call, and its four Redis commands (provider.REFRESH_TIMEOUT).
LOCK_TIMEOUT = 60
LOCK_WAIT = 30  # how long a request waits for a busy lock
MIN_TTL = 1  # second: Redis refuses an expiry of zero or less
KEY_SEPARATOR = b"\n"  # between the key a ciphertext names and its value


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, redis: Redis, fernet_key: str) -> None:
        self._redis = redis
        self._fernet = Fernet(fernet_key)

    async def put(self, kind: str, key: str, value: BaseModel, ttl: int | None = None) -> None:
        redis_key = self._key(kind, key)
        await self._redis.set(redis_key, self._encrypt(kind, key, value), ex=_ttl(ttl))

    async def write(
        self,
        put: Iterable[tuple[str, str, BaseModel, int]] = (),
        delete: Iterable[tuple[str, str]] = (),
    ) -> list[Any]:
        """Deletes, then puts, in one MULTI/EXEC: a crash or a cancellation leaves all of them or
        none. Returns the commands' results in that order: for each delete, the number of keys it
        removed."""
        async with self._redis.pipeline(transaction=True) as pipe:
            for kind, key in delete:
                pipe.delete(self._key(kind, key))

            for kind, key, value, ttl in put:
                redis_key = self._key(kind, key)
                pipe.set(redis_key, self._encrypt(kind, key, value), ex=_ttl(ttl))

            return await pipe.execute()

    async def get(self, kind: str, key: str, model: type[M]) -> M | None:
        data = await self._redis.get(self._key(kind, key))
        return self._load(kind, key, data, model)

    async def pop(self, kind: str, key: str, model: type[M]) -> M | None:
        """Get and delete in one step, so a single-use value can't be used twice."""
        data = await self._redis.getdel(self._key(kind, key))
        return self._load(kind, key, data, model)

    async def touch(self, kind: str, key: str, ttl: int) -> None:
        await self._redis.expire(self._key(kind, key), ttl)

    async def delete(self, kind: str, key: str) -> None:
        await self._redis.delete(self._key(kind, key))

    async def ping(self) -> None:
        await self._redis.ping()

    async def close(self) -> None:
        await self._redis.aclose()

    def lock(self, kind: str, key: str) -> Lock:
        """Raises LockError when it stays busy for LOCK_WAIT. Not when it expired before its
        release, or when Redis fails the release: the work under it is done by then, and an error
        would hide it, such as tokens that were already rotated. A lock left behind expires after
        LOCK_TIMEOUT."""
        return self._redis.lock(
            self._key(f"lock:{kind}", key),
            timeout=LOCK_TIMEOUT,
            blocking_timeout=LOCK_WAIT,
            lock_class=_ReleasedOrExpiring,
            raise_on_release_error=False,
        )

    def _key(self, kind: str, key: str) -> str:
        return f"{PREFIX}:{kind}:{key}"

    def _encrypt(self, kind: str, key: str, value: BaseModel) -> bytes:
        # The ciphertext names its own key, so a value copied under another key in Redis doesn't
        # load.
        name = self._key(kind, key).encode()
        plaintext = name + KEY_SEPARATOR + value.model_dump_json().encode()

        return self._fernet.encrypt(plaintext)

    def _load(self, kind: str, key: str, data: bytes | None, model: type[M]) -> M | None:
        """Missing, too, when the value was encrypted with another FERNET_KEY, stored under another
        key, or written by a version of the server whose records no longer parse: the client signs
        in again."""
        if data is None:
            return None

        try:
            plaintext = self._fernet.decrypt(data)
        except InvalidToken:
            return None

        name, _, value = plaintext.partition(KEY_SEPARATOR)

        if name != self._key(kind, key).encode():
            return None

        try:
            return model.model_validate_json(value)
        except ValueError:  # pydantic's ValidationError is a ValueError
            return None


class _ReleasedOrExpiring(Lock):
    """A lock whose release, when Redis fails it, is left to expire. The error of the work under it
    still comes through."""

    async def do_acquire(self, token: str | bytes) -> bool:
        # A SET NX retried after its answer was lost finds this lock's own token: it was taken. The
        # token is unique.
        was_acquired = await super().do_acquire(token)

        if was_acquired:
            return True

        current_token = await self.redis.get(self.name)
        return current_token == token

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            await super().__aexit__(exc_type, exc_value, traceback)
        except RedisError:
            pass


def _ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None

    return max(int(ttl), MIN_TTL)
