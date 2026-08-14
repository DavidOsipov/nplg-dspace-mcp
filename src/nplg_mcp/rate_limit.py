from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class RateLimiter(Protocol):
    async def acquire(self) -> None: ...


@dataclass(slots=True)
class AsyncRateLimiter:
    """Serialize upstream starts at a fixed maximum rate.

    The limiter spaces request *starts*. It intentionally does not hold a
    permit until a response finishes, so a slow upstream response cannot make
    the process deadlock. A single instance must be shared by all NPLG clients
    in one process.
    """

    rate_per_second: float
    clock: Clock = time.monotonic
    sleeper: Sleeper = asyncio.sleep
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _next_allowed: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        rate = self.rate_per_second
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0:
            raise ValueError("rate_per_second must be a finite positive number")
        self.rate_per_second = float(rate)

    async def acquire(self) -> None:
        interval = 1.0 / self.rate_per_second
        async with self._lock:
            now = self.clock()
            scheduled = max(now, self._next_allowed)
            delay = scheduled - now
            if delay > 0:
                await self.sleeper(delay)
            observed = self.clock()
            self._next_allowed = max(scheduled, observed) + interval
