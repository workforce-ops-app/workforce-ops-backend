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
# How far apart the windows excerpt() tries are (see _Windows). Each window overlaps the
# next by 150 characters, so any matched part of up to 150 characters lies wholly inside
# at least one window.
WINDOW_STEP = 50


@dataclass(frozen=True)
class Finding:
    """One pattern matched in one value of a request."""

    field: str  # where the value was, for example "body.note" or "query.search"
    pattern_id: str  # for example "SQLI-02"
    kind: str  # the attack type, for example "sql_injection"
    excerpt: str  # at most 200 characters of the ORIGINAL text around the match


@dataclass(frozen=True)
class _Hit:
    """Where one pattern first matched one value, and in which normalized form.

    url_decode says which form that was (see _search). start is a position in that
    normalized text, NOT in the original value, and length is that text's length.
    """

    pattern: Pattern
    url_decode: bool
    start: int
    length: int


def matches(value: str) -> list[tuple[Pattern, int]]:
    """Every pattern this value matches, with where the first match starts.

    The position is in the normalized text the pattern matched in (see _search).
    """
    # Cut the value first (DE4), so normalizing and matching never see more than 2,000
    # characters, however long the original was.
    return [(hit.pattern, hit.start) for hit in _search(value[:MAX_VALUE_CHARS])]


def _search(value: str) -> list[_Hit]:
    """Every pattern the value matches, with where its first match is and in which
    normalized form (for excerpt())."""
    # 1. Two normalized forms: the full one, and one without URL decoding, since decoding
    #    can destroy an attack as well as reveal one (see normalize). They differ only for
    #    values that contain "%" or "+", so the second is usually the same text.
    decoded = normalize(value)
    undecoded = normalize(value, url_decode=False)
    # 2. Try every pattern on the decoded form, then on the other. search() looks anywhere
    #    in the text; one match per pattern is enough, since the question is whether the
    #    value looks like this attack at all. The form is remembered with the match, since
    #    the two forms have different lengths and the excerpt must use the right one.
    found = []
    for pattern in PATTERNS:
        match, url_decode = pattern.regex.search(decoded), True
        if match is None and undecoded != decoded:
            match, url_decode = pattern.regex.search(undecoded), False
        if match is not None:
            length = len(decoded if url_decode else undecoded)
            found.append(_Hit(pattern, url_decode, match.start(), length))
    return found


def kinds(value: str) -> set[str]:
    """The attack types this value looks like (empty: it looks harmless)."""
    return {pattern.kind for pattern, _ in matches(value)}


class _Windows:
    """The 200-character windows of one long value, normalized, for excerpt().

    Window n starts at n * 50 characters of the ORIGINAL value and is up to 200 characters
    long: the last few are shorter, since the value ends inside them. (Shorter ones keep
    the steps even all the way to the end, so a match near the end is located as exactly
    as one in the middle.) Each is normalized at most once per form, the first time any finding
    asks for it, and kept, since one value can match several patterns and every one of
    them looks through the same windows. Normalizing all of them costs about four times
    normalizing the value itself; the value is at most 2,000 characters (DE4).
    """

    def __init__(self, original: str) -> None:
        self.original = original
        # Where each window starts: every 50 characters, to the end of the value.
        self.starts = list(range(0, len(original), WINDOW_STEP))
        self._normalized: dict[tuple[bool, int], str] = {}

    def shows(self, hit: _Hit, start: int) -> bool:
        """Whether the window at `start`, normalized the way the match was, still shows
        the attack (the same pattern matches it)."""
        key = (hit.url_decode, start)
        if key not in self._normalized:
            piece = self.original[start : start + MAX_EXCERPT_CHARS]
            self._normalized[key] = normalize(piece, url_decode=hit.url_decode)
        return hit.pattern.regex.search(self._normalized[key]) is not None


def excerpt(original: str, hit: _Hit, windows: _Windows | None = None) -> str:
    """At most 200 characters of the original text, around where the match was (DE7).

    The security page shows this as the evidence for a finding, so it must contain the
    suspicious part of what was sent, not only text near it. A position in the normalized
    text cannot be copied across to the original: they stop lining up as soon as anything
    was decoded (%27 is three characters, the quote it stands for is one). So instead of
    translating positions, this looks at the original itself, 200 characters at a time:
    1. A short value (200 characters or fewer) is returned whole.
    2. Try the windows from the start of the value, 50 characters apart, and find the
       first run of windows next to each other that each still show the attack.
    3. The matched part is inside every window of that run, so it is inside the stretch
       they all share. The excerpt is the 200 characters centred on that stretch (moved
       back inside the value at its ends), which contain the matched part and some text
       on each side of it.
    4. If no window shows it (the attack is spread over more than 200 characters of the
       original, for example by heavy encoding), the excerpt falls back to the same
       relative position in the original as in the normalized text that matched.
    """
    # 1. Short values are the common case: the whole value is the excerpt.
    if len(original) <= MAX_EXCERPT_CHARS:
        return original
    windows = windows or _Windows(original)

    # 2. The first run of neighbouring windows that show the attack.
    run: list[int] = []
    for start in windows.starts:
        if windows.shows(hit, start):
            run.append(start)
        elif run:
            break  # the run has ended: later windows are another part of the value

    # 3. Every window in the run holds the matched part, so it lies in the stretch they
    #    share: from the last window's start to the first window's end (or the value's
    #    end, if that comes first). Centre 200 characters on that stretch, kept inside
    #    the value.
    if run:
        shared_start = run[-1]
        shared_end = min(run[0] + MAX_EXCERPT_CHARS, len(original))
        centre = (shared_start + shared_end) // 2
        start = max(0, min(centre - MAX_EXCERPT_CHARS // 2, len(original) - MAX_EXCERPT_CHARS))
        return original[start : start + MAX_EXCERPT_CHARS]

    # 4. Nothing 200 characters long shows it alone: use the relative position, measured
    #    in the form that matched (its length, not the other form's).
    share = hit.start / hit.length if hit.length else 0.0
    centre = int(share * len(original))
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
        #    The value's windows are shared by all its findings (see _Windows).
        windows = _Windows(value) if len(value) > MAX_EXCERPT_CHARS else None
        for hit in _search(value):
            findings.append(
                Finding(
                    field=field,
                    pattern_id=hit.pattern.id,
                    kind=hit.pattern.kind,
                    excerpt=excerpt(value, hit, windows),
                )
            )
    return findings
