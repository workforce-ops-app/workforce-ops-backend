"""Refuse to start a second API on the shared Docker network (#213).

The frontend's nginx finds the API by its name, `api`, on the shared `workforce-ops`
network (docker-compose.yml). If two backend stacks run there at once (say the usual one
and a second with its own database, for testing), both answer to that name, and nginx
sends requests to them in turns. Then things fail at random: a setup or reset link made
through one API is refused as "This link does not work" by the other, whose database has
never seen it, and a signed-in person is sometimes treated as signed out (the review of
frontend #92 lost a round to exactly this).

So before the API starts (the Dockerfile's CMD runs `python -m app.core.shared_network`
first), this looks the name up and compares the answers with this container's own
addresses. Any other address means another API is already there: it prints what to do
and exits, so the problem shows at once instead of as random 400s and 401s.

It runs only when SHARED_API_NAME is set (Docker Compose sets it to "api"), so running the
API with uvicorn on your own computer, the tests, and CI are unaffected. The frontend's
nginx makes the same check from its side (frontend #119), for a second API that started
first.
"""

import os
import socket
import struct
import sys
from collections.abc import Callable, Iterable

# The ioctl that asks Linux for an interface's IPv4 address (SIOCGIFADDR in <linux/sockios.h>).
_GET_ADDRESS = 0x8915


def own_addresses() -> set[str]:
    """This container's own IPv4 addresses, one per network interface it has (one for each
    Docker network it joined, plus 127.0.0.1). Linux only, as in the image."""
    if sys.platform != "linux":  # the image is Linux; elsewhere (tests on Windows) none
        return set()
    import fcntl  # Linux only: imported here, so the module still imports on Windows (tests)

    found = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in socket.if_nameindex():
            # The request is the interface's name, padded to the size Linux expects; the
            # answer holds the address at bytes 20 to 24.
            request = struct.pack("256s", name.encode()[:15])
            try:
                answer = fcntl.ioctl(probe.fileno(), _GET_ADDRESS, request)
            except OSError:  # an interface with no IPv4 address
                continue
            found.add(socket.inet_ntoa(answer[20:24]))
    return found


def resolve(name: str) -> set[str]:
    """Every IPv4 address Docker's DNS gives for the name (empty if it gives none)."""
    try:
        answers = socket.getaddrinfo(name, None, socket.AF_INET)
    except socket.gaierror:
        return set()
    return {str(address[4][0]) for address in answers}


def describe(address: str) -> str:
    """The container behind an address, as Docker's DNS names it ("<container>.<network>"),
    or just the address if it does not say."""
    try:
        return f"{socket.gethostbyaddr(address)[0]} ({address})"
    except OSError:
        return address


def others(name: str, resolved: Iterable[str], own: Iterable[str]) -> list[str]:
    """The addresses answering to the name that are not this container's own, sorted."""
    return sorted(set(resolved) - set(own))


def problem(
    name: str,
    *,
    resolver: Callable[[str], set[str]] = resolve,
    own: Callable[[], set[str]] = own_addresses,
    namer: Callable[[str], str] = describe,
) -> str | None:
    """What is wrong, as a message for the person starting the stack; None if this is the
    only API answering to the name. The lookups are parameters so tests can supply them."""
    extra = others(name, resolver(name), own())
    if not extra:
        return None
    who = ", ".join(namer(address) for address in extra)
    return (
        f"Another API already answers as '{name}' on this Docker network: {who}.\n"
        "With two, the frontend's nginx sends requests to each in turn, so links, sign-ins, "
        "and changes fail at random.\n"
        "Stop the other backend stack (see `docker ps`), or give this one a network of its "
        "own by setting SHARED_NETWORK (and SHARED_SUBNET) in .env."
    )


def main() -> int:
    """Exit 0 to let the API start, or 1 (with the message on stderr) to refuse."""
    name = os.environ.get("SHARED_API_NAME", "")
    if not name:  # not started by Docker Compose: nothing to check
        return 0
    found = problem(name)
    if found is None:
        return 0
    print(found, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
