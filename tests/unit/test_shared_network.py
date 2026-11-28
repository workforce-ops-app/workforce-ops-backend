"""The start-up check that refuses a second API on the shared Docker network (#213,
app/core/shared_network.py).

The lookups (Docker's DNS, this container's addresses) are replaced with fixed answers,
so these run anywhere. The real thing was tried with two Compose stacks on one network
(the pull request says how).
"""

import sys

import pytest

from app.core import shared_network

# This container: its address on its private database network, on the shared network,
# and the loopback. Docker's DNS answers "api" with its own addresses on both networks.
OWN = {"172.18.0.3", "172.30.250.130", "127.0.0.1"}
ALONE = {"172.18.0.3", "172.30.250.130"}
# A second stack's API on the shared network: one more address for the same name.
SECOND = "172.30.250.131"


def check(resolved: set[str]) -> str | None:
    return shared_network.problem(
        "api",
        resolver=lambda name: resolved,
        own=lambda: OWN,
        namer=lambda address: f"other-api-1.workforce-ops ({address})",
    )


def test_the_only_api_starts() -> None:
    assert check(ALONE) is None


def test_a_name_nobody_answers_to_yet_starts() -> None:
    # Docker's DNS may not answer at all in a moment of start-up: nothing to compare.
    assert check(set()) is None


def test_a_second_api_is_refused_with_who_and_what_to_do() -> None:
    message = check(ALONE | {SECOND})
    assert message is not None
    assert "other-api-1.workforce-ops (172.30.250.131)" in message
    assert "docker ps" in message
    assert "SHARED_NETWORK" in message


def test_every_other_address_is_named_in_order() -> None:
    message = check(ALONE | {"172.30.250.140", SECOND})
    assert message is not None
    assert message.index("172.30.250.131") < message.index("172.30.250.140")


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
    monkeypatch.setattr(shared_network, "problem", lambda name: f"two answer as {name}")
    assert shared_network.main() == 1
    assert capsys.readouterr().err.strip() == "two answer as api"


def test_main_lets_the_only_api_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHARED_API_NAME", "api")
    monkeypatch.setattr(shared_network, "problem", lambda name: None)
    assert shared_network.main() == 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads Linux interfaces")
def test_own_addresses_include_the_loopback() -> None:
    assert "127.0.0.1" in shared_network.own_addresses()
