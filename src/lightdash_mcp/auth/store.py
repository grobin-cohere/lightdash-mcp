"""Redis storage, every value encrypted with Fernet. Token keys are stored as sha256 digests."""

import hashlib
from collections.abc import Callable, Iterable
from typing import TypeVar

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel
from redis.asyncio import Redis
from redis.asyncio.lock import Lock
from redis.exceptions import WatchError

M = TypeVar("M", bound=BaseModel)

PREFIX = "lightdash-mcp"
LOCK_TIMEOUT = 30


class Missing(Exception):
    """A write found the record it expects gone: nothing was written."""


class Changed(Exception):
    """A write found the record it expects changed by another request: nothing was written."""


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, redis: Redis, fernet_key: str) -> None:
        self._redis = redis
        self._fernet = Fernet(fernet_key)

    def _key(self, kind: str, key: str) -> str:
        return f"{PREFIX}:{kind}:{key}"

    def _encrypt(self, kind: str, key: str, value: BaseModel) -> bytes:
        # The ciphertext names its own key, so a value copied under another key in Redis doesn't load.
        return self._fernet.encrypt(self._key(kind, key).encode() + b"\n" + value.model_dump_json().encode())

    def _load(self, kind: str, key: str, data: bytes | None, model: type[M]) -> M | None:
        """Missing, too, when the value was encrypted with another FERNET_KEY, stored under another key, or written
        by a version of the server whose records no longer parse: the client signs in again."""
        if data is None:
            return None
        try:
            name, _, value = self._fernet.decrypt(data).partition(b"\n")
            if name != self._key(kind, key).encode():
                return None
            return model.model_validate_json(value)
        except InvalidToken, ValueError:  # pydantic's ValidationError is a ValueError
            return None

    async def put(self, kind: str, key: str, value: BaseModel, ttl: int | None = None) -> None:
        await self._redis.set(self._key(kind, key), self._encrypt(kind, key, value), ex=_ttl(ttl))

    async def write(
        self,
        put: Iterable[tuple[str, str, BaseModel, int]] = (),
        delete: Iterable[tuple[str, str]] = (),
        expect: tuple[str, str, type[M], Callable[[M], bool]] | None = None,
    ) -> None:
        """Deletes, then puts, in one MULTI/EXEC: a crash or a cancellation leaves all of them or none.

        With `expect` (kind, key, model, check), only while that record is there and passes the check, in the same
        transaction: otherwise Missing or Changed, and nothing is written.
        """
        put, delete = list(put), list(delete)
        async with self._redis.pipeline(transaction=True) as pipe:
            while True:
                if expect:
                    kind, key, model, check = expect
                    await pipe.watch(self._key(kind, key))
                    current = self._load(kind, key, await pipe.get(self._key(kind, key)), model)
                    if current is None:
                        raise Missing
                    if not check(current):
                        raise Changed
                    pipe.multi()
                for kind, key in delete:
                    pipe.delete(self._key(kind, key))
                for kind, key, value, ttl in put:
                    pipe.set(self._key(kind, key), self._encrypt(kind, key, value), ex=_ttl(ttl))
                try:
                    await pipe.execute()
                    return
                except WatchError:
                    continue  # the record changed after the check: check it again

    async def get(self, kind: str, key: str, model: type[M]) -> M | None:
        return self._load(kind, key, await self._redis.get(self._key(kind, key)), model)

    async def pop(self, kind: str, key: str, model: type[M]) -> M | None:
        """Get and delete in one step, so a single-use value can't be used twice."""
        return self._load(kind, key, await self._redis.getdel(self._key(kind, key)), model)

    async def touch(self, kind: str, key: str, ttl: int) -> None:
        await self._redis.expire(self._key(kind, key), ttl)

    async def delete(self, kind: str, key: str) -> None:
        await self._redis.delete(self._key(kind, key))

    async def ping(self) -> None:
        await self._redis.ping()

    async def close(self) -> None:
        await self._redis.aclose()

    def lock(self, kind: str, key: str) -> Lock:
        """Raises LockError when it stays busy for LOCK_TIMEOUT. Not when it expired before its release: the work under
        it is done by then, and an error would hide it, such as tokens that were already rotated. A write that needs the
        lock still held checks what it relies on instead, with `write`'s `expect`."""
        return self._redis.lock(
            self._key(f"lock:{kind}", key), timeout=LOCK_TIMEOUT, blocking_timeout=LOCK_TIMEOUT, raise_on_release_error=False
        )


def _ttl(ttl: int | None) -> int | None:
    return max(int(ttl), 1) if ttl is not None else None
