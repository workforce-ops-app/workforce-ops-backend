"""The detector: which attack patterns a request's values match (docs/features/detection.md).

Two entry points:
- inspect(values) for a request: a list of (field, value) pairs, with the caps applied
  (rule DE4), giving one Finding per pattern matched per value. The detection layer (DT4,
  workforce-ops-app/workforce-ops-backend#130) calls this in its worker thread.
- matches(value) for one value, without the request caps (one value is still cut to
  2,000 characters). The detection study scores the detector through this.

Detection only RECORDS what it saw; it never blocks anything (rule DE1). Plain Python with
no FastAPI or database code (rule DE10), so the study scores exactly this code.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from app.detection.normalize import normalize
from app.detection.patterns import PATTERNS, Pattern

# Rule DE4 (threat D4): bounds on the work and memory one request can cause. Bodies are
# already size-limited before they get here (#94); these bound what is inspected.
MAX_VALUE_CHARS = 2_000  # each value is cut to its first 2,000 characters
MAX_VALUES = 200  # at most 200 values from one request
MAX_TOTAL_CHARS = 100_000  # and at most 100,000 characters in total
# Rule DE7: the stored excerpt is at most this long (shown as plain text, threat T7).
MAX_EXCERPT_CHARS = 200


@dataclass(frozen=True)
class Finding:
    """One pattern matched in one value of a request."""

    field: str  # where the value was, for example "body.note" or "query.search"
    pattern_id: str  # for example "SQLI-02"
    kind: str  # the attack type, for example "sql_injection"
    excerpt: str  # at most 200 characters of the ORIGINAL text around the match


def matches(value: str) -> list[tuple[Pattern, int]]:
    """Every pattern this value matches, with where the first match starts.

    The position is in the normalized text (see excerpt() for how it is used).
    """
    # Cut the value first (DE4), so normalizing and matching never see more than 2,000
    # characters, however long the original was.
    found, _ = _search(value[:MAX_VALUE_CHARS])
    return found


def _search(value: str) -> tuple[list[tuple[Pattern, int]], int]:
    """Every pattern the value matches, with where the first match starts, and the length
    of the normalized text those positions are in (for excerpt())."""
    # 1. Two normalized forms: the full one, and one without URL decoding, since decoding
    #    can destroy an attack as well as reveal one (see normalize). They differ only for
    #    values that contain "%" or "+", so the second is usually the same text.
    decoded = normalize(value)
    undecoded = normalize(value, url_decode=False)
    # 2. Try every pattern on the decoded form, then on the other. search() looks anywhere
    #    in the text; one match per pattern is enough, since the question is whether the
    #    value looks like this attack at all.
    found = []
    for pattern in PATTERNS:
        match = pattern.regex.search(decoded)
        if match is None and undecoded != decoded:
            match = pattern.regex.search(undecoded)
        if match is not None:
            found.append((pattern, match.start()))
    return found, len(decoded)


def kinds(value: str) -> set[str]:
    """The attack types this value looks like (empty: it looks harmless)."""
    return {pattern.kind for pattern, _ in matches(value)}


def excerpt(original: str, position: int, normalized_length: int) -> str:
    """At most 200 characters of the original text, around where the match was.

    The match was found in the NORMALIZED text, whose positions do not line up with the
    original once anything was decoded (%27 is three characters, the quote it stands for
    is one). So the excerpt is centred on the same RELATIVE position in the original: a
    match halfway through the normalized text gives a window halfway through the original.
    A short value (200 characters or fewer) is returned whole, so most excerpts are exact.
    """
    if len(original) <= MAX_EXCERPT_CHARS:
        return original
    # Where the match is, as a share of the normalized text, applied to the original.
    share = position / normalized_length if normalized_length else 0.0
    centre = int(share * len(original))
    # A window of 200 characters around that point, kept inside the original.
    start = max(0, min(centre - MAX_EXCERPT_CHARS // 2, len(original) - MAX_EXCERPT_CHARS))
    return original[start : start + MAX_EXCERPT_CHARS]


def inspect(values: Iterable[tuple[str, str]]) -> list[Finding]:
    """Findings for one request's values, with the request caps applied (DE4).

    `values` are (field, text) pairs, already collected by the detection layer's rules
    (no headers, no credential routes, no secret-named fields: DE3). Values past the caps
    are not inspected at all.
    """
    findings = []
    total = 0
    for count, (field, value) in enumerate(values):
        # 1. The request caps: at most 200 values, and 100,000 characters in total
        #    (counting each value after it is cut to 2,000).
        if count >= MAX_VALUES:
            break
        value = value[:MAX_VALUE_CHARS]
        total += len(value)
        if total > MAX_TOTAL_CHARS:
            break
        # 2. Match, and turn each match into a finding with an excerpt of the original.
        found, normalized_length = _search(value)
        for pattern, position in found:
            findings.append(
                Finding(
                    field=field,
                    pattern_id=pattern.id,
                    kind=pattern.kind,
                    excerpt=excerpt(value, position, normalized_length),
                )
            )
    return findings
