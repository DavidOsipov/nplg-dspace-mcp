from __future__ import annotations

import asyncio

import pytest

from nplg_mcp.rate_limit import AsyncRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_spaces_sequential_acquisitions_without_delaying_first() -> None:
    current = 10.0
    delays: list[float] = []

    def clock() -> float:
        return current

    async def sleeper(delay: float) -> None:
        nonlocal current
        delays.append(delay)
        current += delay

    limiter = AsyncRateLimiter(rate_per_second=2.0, clock=clock, sleeper=sleeper)

    await limiter.acquire()
    await limiter.acquire()
    await limiter.acquire()

    assert delays == [0.5, 0.5]


@pytest.mark.asyncio
async def test_rate_limiter_serializes_concurrent_callers() -> None:
    current = 0.0
    delays: list[float] = []

    def clock() -> float:
        return current

    async def sleeper(delay: float) -> None:
        nonlocal current
        await asyncio.sleep(0)
        delays.append(delay)
        current += delay

    limiter = AsyncRateLimiter(rate_per_second=1.0, clock=clock, sleeper=sleeper)

    await asyncio.gather(*(limiter.acquire() for _ in range(3)))

    assert delays == [1.0, 1.0]


@pytest.mark.parametrize("rate", [0, -1, True, float("inf"), float("nan")])
def test_rate_limiter_rejects_invalid_rates(rate: float) -> None:
    with pytest.raises(ValueError):
        AsyncRateLimiter(rate_per_second=rate)
