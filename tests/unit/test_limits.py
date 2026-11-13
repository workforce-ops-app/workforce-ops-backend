"""The lockout schedule and the rate limiter on their own (app/auth/limits.py)."""

from datetime import timedelta

import pytest

from app.auth.limits import MAX_LOCK, RateLimit, TooManyRequests, lock_for


@pytest.mark.parametrize(
    ("failures", "locked"),
    [
        (1, None),
        (4, None),
        (5, timedelta(minutes=15)),
        (6, None),  # between the steps: counted, not locked again
        (9, None),
        (10, timedelta(minutes=30)),
        (14, None),
        (15, timedelta(hours=1)),
        (16, timedelta(hours=1)),  # from the 15th on: every failure, an hour each time
        (500, timedelta(hours=1)),
    ],
)
def test_the_lockout_schedule(failures: int, locked: timedelta | None) -> None:
    assert lock_for(failures) == locked


def test_no_lock_is_ever_longer_than_an_hour() -> None:
    # Threat D1: an attacker can delay a person, never lock them out for good.
    assert (
        max(lock_for(n) or timedelta(0) for n in range(1, 1000)) == MAX_LOCK == timedelta(hours=1)
    )


class Clock:
    """A clock the test moves by hand (seconds)."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_the_limit_allows_its_count_then_answers_429_with_retry_after() -> None:
    clock = Clock(600.0 + 15)  # 15 seconds into a minute
    limit = RateLimit(limit=3, clock=clock)
    for _ in range(3):
        limit.hit("a")
    with pytest.raises(TooManyRequests) as refused:
        limit.hit("a")
    assert refused.value.status_code == 429
    # 45 seconds are left in this minute.
    assert refused.value.headers == {"Retry-After": "45"}
    # Another key has its own count.
    limit.hit("b")
    # A new minute starts every count again.
    clock.now = 660.0
    limit.hit("a")


def test_retry_after_is_never_zero() -> None:
    clock = Clock(659.9)  # a tenth of a second before the minute ends
    limit = RateLimit(limit=0, clock=clock)
    with pytest.raises(TooManyRequests) as refused:
        limit.hit("a")
    assert refused.value.headers == {"Retry-After": "1"}


def test_a_flood_of_new_keys_shares_one_count_and_memory_stays_bounded() -> None:
    clock = Clock(0.0)
    limit = RateLimit(limit=2, max_keys=3, clock=clock)
    for key in ("a", "b", "c"):
        limit.hit(key)
    # Past max_keys, every new key counts under one shared key.
    limit.hit("d")
    limit.hit("e")
    with pytest.raises(TooManyRequests):
        limit.hit("f")
    assert len(limit._counts) == 4  # a, b, c, and the overflow
    # The keys already known keep their own counts.
    limit.hit("a")
