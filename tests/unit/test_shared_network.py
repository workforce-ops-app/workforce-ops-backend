"""The start-up check that refuses a second API on the shared Docker network (#213,
app/core/shared_network.py).

The lookups (Docker's DNS, this container's addresses) are replaced with fixed answers,
so these run anywhere. The real thing was tried with two complete Compose stacks, each
with its own database network, sharing one frontend network (the pull request says how).
"""

import sys

import pytest

from app.core import shared_network

# This container: its address on its private database network, on the shared network,
# and the loopback.
OWN = {"172.18.0.3", "172.30.250.130", "127.0.0.1"}
# "api.workforce-ops" when this is the only API there: its own shared-network address.
ALONE = {"172.30.250.130"}
# A second stack's API on the shared network: one more address for the same name.
SECOND = "172.30.250.131"


def check(resolved: set[str], *, tries: int = 5) -> tuple[str | None, list[str], list[float]]:
    """problem() with fixed lookups: its answer, the names looked up, and the waits."""
    looked_up: list[str] = []
    waits: list[float] = []

    def resolver(name: str) -> set[str]:
        looked_up.append(name)
        return resolved

    message = shared_network.problem(
        "api",
        "workforce-ops",
        resolver=resolver,
        own=lambda: OWN,
        namer=lambda address: f"other-api-1.workforce-ops ({address})",
        sleep=waits.append,
        tries=tries,
    )
    return message, looked_up, waits


def test_the_only_api_starts() -> None:
    message, looked_up, waits = check(ALONE)
    assert message is None
    assert waits == []


def test_the_name_is_looked_up_on_the_shared_network() -> None:
    """A plain "api" can be answered from the private database network, where only this
    container has the name, and the other API would be missed (review of #214)."""
    answers = {
        "api": {"172.18.0.3"},  # the database network: only this container
        "api.workforce-ops": ALONE | {SECOND},  # the shared network: both APIs
    }
    message = shared_network.problem(
        "api",
        "workforce-ops",
        resolver=lambda name: answers[name],
        own=lambda: OWN,
        namer=str,
        sleep=lambda seconds: None,
    )
    assert message is not None and SECOND in message


def test_a_second_api_is_refused_with_who_and_what_to_do() -> None:
    message, looked_up, _ = check(ALONE | {SECOND})
    assert message is not None
    assert looked_up == ["api.workforce-ops"]
    assert "other-api-1.workforce-ops (172.30.250.131)" in message
    assert "'workforce-ops'" in message
    assert "docker ps" in message
    assert "SHARED_NETWORK" in message


def test_every_other_address_is_named_in_order() -> None:
    message, _, _ = check(ALONE | {"172.30.250.140", SECOND})
    assert message is not None
    assert message.index("172.30.250.131") < message.index("172.30.250.140")


def test_a_failing_lookup_is_tried_again_then_refused() -> None:
    """No answer (a DNS failure) must not let the API start unchecked (review of #214)."""
    message, looked_up, waits = check(set(), tries=5)
    assert message is not None
    assert message.startswith("Could not check")
    assert "no answer" in message
    assert "docker network inspect workforce-ops" in message
    assert len(looked_up) == 5
    assert waits == [shared_network.WAIT_SECONDS] * 4  # between tries, not after the last


def test_an_answer_without_this_container_is_not_trusted() -> None:
    # Only the other API: the lookup cannot have seen this container's network yet.
    message, looked_up, _ = check({SECOND}, tries=3)
    assert message is not None and message.startswith("Could not check")
    assert len(looked_up) == 3


def test_a_lookup_that_recovers_lets_the_only_api_start() -> None:
    answers = iter([set(), set(), ALONE])
    waits: list[float] = []
    message = shared_network.problem(
        "api",
        "workforce-ops",
        resolver=lambda name: next(answers),
        own=lambda: OWN,
        sleep=waits.append,
    )
    assert message is None
    assert len(waits) == 2


def test_without_the_compose_setting_nothing_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    # Running uvicorn directly, the tests, and CI: no SHARED_API_NAME, no lookups at all.
    monkeypatch.delenv("SHARED_API_NAME", raising=False)

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("looked something up")

    monkeypatch.setattr(shared_network, "problem", fail)
    assert shared_network.main() == 0


def test_main_refuses_with_the_message_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SHARED_API_NAME", "api")
    monkeypatch.setenv("SHARED_NETWORK_NAME", "workforce-ops")
    monkeypatch.setattr(
        shared_network, "problem", lambda name, network: f"two answer as {name} on {network}"
    )
    assert shared_network.main() == 1
    assert capsys.readouterr().err.strip() == "two answer as api on workforce-ops"


def test_main_lets_the_only_api_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHARED_API_NAME", "api")
    monkeypatch.setenv("SHARED_NETWORK_NAME", "workforce-ops")
    monkeypatch.setattr(shared_network, "problem", lambda name, network: None)
    assert shared_network.main() == 0


def test_main_refuses_without_the_network_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SHARED_API_NAME", "api")
    monkeypatch.delenv("SHARED_NETWORK_NAME", raising=False)
    assert shared_network.main() == 1
    assert "SHARED_NETWORK_NAME" in capsys.readouterr().err


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads Linux interfaces")
def test_own_addresses_include_the_loopback() -> None:
    assert "127.0.0.1" in shared_network.own_addresses()
