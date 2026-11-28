"""Refuse to start a second API on the shared Docker network (#213).

The frontend's nginx finds the API by its name, `api`, on the shared `workforce-ops`
network (docker-compose.yml). If two backend stacks run there at once (say the usual one
and a second with its own database, for testing), both answer to that name, and nginx
sends requests to them in turns. Then things fail at random: a setup or reset link made
through one API is refused as "This link does not work" by the other, whose database has
never seen it, and a signed-in person is sometimes treated as signed out. This was
reproduced locally (two stacks on one network: links alternated 204 and 400).

It is not what broke the links in the review of frontend #92: there, nginx redirected
the browser to localhost:8080 instead of the isolated stack's own port, so the links
were redeemed by the other stack (frontend #121). Both causes look the same in the
browser ("This link does not work"), which is why the message below names the container.

So before the API starts (the Dockerfile's CMD runs `python -m app.core.shared_network`
first), this looks the name up on the shared network and compares the answers with this
container's own addresses. Any other address means another API is already there: it
prints what to do and exits, so the problem shows at once instead of as random 400s and
401s.

The lookup names the network ("api.workforce-ops"). The API is on two networks, its
private database network and the shared one, and Docker's DNS answers a plain "api" from
the first network that has the name: that can be the private one, where only this
container is "api", and the other API on the shared network would be missed (review of
#214). With the network in the name, Docker answers from that network only.

A lookup that fails, or that does not include this container itself (so it cannot have
been answered from the shared network), is tried again a few times; if it still cannot
be checked, the API refuses to start with a message saying so, rather than starting
unchecked (review of #214).

It runs only when SHARED_API_NAME is set (Docker Compose sets it to "api", and
SHARED_NETWORK_NAME to the shared network's name), so running the API with uvicorn on
your own computer, the tests, and CI are unaffected. The frontend's nginx makes the same
check from its side (frontend #119), for a second API that started first.
"""

import os
import socket
import struct
import sys
import time
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
    """Every IPv4 address Docker's DNS gives for the name (empty if it gives none, or the
    lookup fails: problem() then tries again and, failing that, refuses)."""
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


# How often an unclear lookup is tried, and the wait between tries: about 10 seconds in
# all, long enough for Docker's DNS to catch up at start-up, short enough to notice.
TRIES = 5
WAIT_SECONDS = 2.0


def problem(
    name: str,
    network: str,
    *,
    resolver: Callable[[str], set[str]] = resolve,
    own: Callable[[], set[str]] = own_addresses,
    namer: Callable[[str], str] = describe,
    sleep: Callable[[float], None] = time.sleep,
    tries: int = TRIES,
) -> str | None:
    """What is wrong, as a message for the person starting the stack; None if this is the
    only API answering to the name on the network. The lookups and the wait are
    parameters so tests can supply them."""
    qualified = f"{name}.{network}"  # answered from that network only
    mine = own()
    resolved: set[str] = set()
    for attempt in range(tries):
        resolved = resolver(qualified)
        # This container must be among the answers: then the lookup really was answered
        # from the shared network, and anything else in it is another container.
        if resolved & mine:
            break
        if attempt < tries - 1:
            sleep(WAIT_SECONDS)
    else:
        seen = ", ".join(sorted(resolved)) or "no answer"
        return (
            f"Could not check that this is the only API answering as '{name}' on the "
            f"Docker network '{network}': looking up '{qualified}' gave {seen}, "
            f"not this container, after {tries} tries.\n"
            "Starting anyway could leave two APIs behind the frontend, where links, "
            "sign-ins, and changes fail at random.\n"
            "Check that the container joined that network (`docker network inspect "
            f"{network}`) and that SHARED_NETWORK in .env names it, then start again."
        )
    extra = others(name, resolved, mine)
    if not extra:
        return None
    who = ", ".join(namer(address) for address in extra)
    return (
        f"Another API already answers as '{name}' on the Docker network '{network}': {who}.\n"
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
    network = os.environ.get("SHARED_NETWORK_NAME", "")
    if not network:
        print(
            "SHARED_API_NAME is set but SHARED_NETWORK_NAME is not: the shared network's "
            "name is needed to check for a second API (docker-compose.yml sets both).",
            file=sys.stderr,
        )
        return 1
    found = problem(name, network)
    if found is None:
        return 0
    print(found, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
