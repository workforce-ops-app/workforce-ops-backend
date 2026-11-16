"""The lockout schedule and the rate limiter on their own (app/auth/limits.py)."""

import threading
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


def test_a_longer_window_counts_for_its_whole_length() -> None:
    # An hour window, as company sign-up uses for its 5 per hour per address.
    clock = Clock(3600.0 + 600)  # 10 minutes into an hour
    limit = RateLimit(limit=5, window=3600, clock=clock)
    for _ in range(5):
        limit.hit("a")
    # A new minute is not a new window: the 6th is still refused.
    clock.now += 120
    with pytest.raises(TooManyRequests) as refused:
        limit.hit("a")
    # 48 minutes are left in this hour.
    assert refused.value.headers == {"Retry-After": str(48 * 60)}
    # The next hour starts every count again.
    clock.now = 7200.0
    limit.hit("a")


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


class DelayedClock:
    """A clock for the window boundary race. The thread named "late" reads a time just
    before the minute ends, then is held up (as a busy server could hold it) until the
    other thread is done or a short wait runs out. Every other thread reads a time just
    after the new minute started."""

    def __init__(self) -> None:
        # Set once the late thread has read its time.
        self.late_has_read = threading.Event()
        # Set once the other thread's requests are done.
        self.others_done = threading.Event()

    def __call__(self) -> float:
        if threading.current_thread().name == "late":
            self.late_has_read.set()
            # Held up after reading the clock. If the limiter reads the clock while holding
            # its lock (as it must), the other thread cannot run now, so this wait just
            # runs out.
            self.others_done.wait(timeout=0.3)
            return 59.9
        return 60.5


def test_a_delayed_request_cannot_turn_the_window_back() -> None:
    # Review of #144: a request that read the clock in the old minute but reached the
    # counts after the new minute began used to reset them to the old minute, dropping the
    # new minute's counts and letting more requests through than the limit allows.
    clock = DelayedClock()
    limit = RateLimit(limit=2, clock=clock)
    # 1. The late request reads the clock (the old minute) and is held up.
    late = threading.Thread(target=limit.hit, args=("a",), name="late")
    late.start()
    assert clock.late_has_read.wait(timeout=5)
    # 2. Meanwhile two requests arrive in the new minute: the limit's full count.
    limit.hit("a")
    limit.hit("a")
    clock.others_done.set()
    late.join(timeout=5)
    assert not late.is_alive()
    # 3. The new minute's two requests are still counted, so a third is refused.
    with pytest.raises(TooManyRequests):
        limit.hit("a")


def test_a_clock_that_steps_back_keeps_the_current_window() -> None:
    # The system time can be corrected backward. Windows only move forward, so the
    # counts are kept, and Retry-After is never longer than one window.
    clock = Clock(660.0 + 10)
    limit = RateLimit(limit=1, clock=clock)
    limit.hit("a")
    clock.now = 600.0 + 10  # a minute back
    with pytest.raises(TooManyRequests) as refused:
        limit.hit("a")
    assert refused.value.headers == {"Retry-After": "60"}
