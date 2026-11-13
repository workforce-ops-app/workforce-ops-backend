"""The attack patterns: what each attack type looks like after normalization.

Each pattern has a stable ID (for example SQLI-03) that events, tests, and the detection
study's results refer to, so an ID is never reused for a different pattern. A pattern that
is changed in a way that changes what it matches gets a new ID; the old one is retired.

The patterns run on NORMALIZED text (normalize.py): lowercase, decoded, with whitespace
collapsed to single spaces and SQL comments turned into spaces. So " " in a pattern below
stands for any run of whitespace in the original.

Rule DE5 (threat D4, ReDoS): Python's regular expressions try alternatives one by one
and go back when a try fails ("backtracking"). A pattern with a repetition inside a
repetition, such as (a+)+, can make that take exponentially long on a crafted string,
freezing the worker. So every repetition here has an upper bound ({0,40}, not *), and none
is nested inside another; tests/unit/test_detection.py checks both, and times every
pattern on crafted worst-case input.

Course topics: SQL injection, cross-site scripting, code injection, format string
vulnerabilities. Detection only records what it sees; the real protection is how the
application is built (bound parameters, textContent, never using user text as a format).
"""

import re
from dataclasses import dataclass

# The attack types and the codes stored in security events (detection.<code>).
SQL_INJECTION = "sql_injection"
XSS = "xss"
PATH_TRAVERSAL = "path_traversal"
COMMAND_INJECTION = "command_injection"
FORMAT_STRING = "format_string"
KINDS = (SQL_INJECTION, XSS, PATH_TRAVERSAL, COMMAND_INJECTION, FORMAT_STRING)


@dataclass(frozen=True)
class Pattern:
    """One pattern: its stable ID, its attack type, what it looks for, and the regex."""

    id: str
    kind: str
    description: str
    regex: re.Pattern[str]


def _pattern(id: str, kind: str, description: str, regex: str) -> Pattern:
    """Compile one pattern. Patterns are written for normalized (lowercase) text."""
    return Pattern(id=id, kind=kind, description=description, regex=re.compile(regex))


# Commands an attacker typically runs first to see whether injection worked.
# Everyday words that are also commands ("type", "dir", "env") are left out on purpose:
# "closed; type your name" is a normal note. The study measures what that costs.
_COMMANDS = (
    r"(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|python3?|perl"
    r"|php|ruby|ping|nslookup|rm|chmod|echo|sleep|powershell|cmd|ifconfig|ipconfig"
    r"|printenv)"
)

PATTERNS: tuple[Pattern, ...] = (
    # --- SQL injection: the attacker's text tries to become part of the SQL itself. ----
    _pattern(
        "SQLI-01",
        SQL_INJECTION,
        "a quote closing the string, then an always-true test: ' or 1=1, ' or 'a'='a",
        # The closing quote (or bracket), the joining word, then "x = y" or "x like y".
        r"['\"\)] ?(?:or|and|\|\||&&) ?"
        r"['\"]?[\w.]{1,20}['\"]? ?(?:=|<>|!=|like|>|<) ?['\"]?[\w.]{1,20}",
    ),
    _pattern(
        "SQLI-02",
        SQL_INJECTION,
        "union select: reading another table's rows through this query",
        r"\bunion (?:all |distinct )?\(?select\b",
    ),
    _pattern(
        "SQLI-03",
        SQL_INJECTION,
        "a second statement after a semicolon (stacked queries): ; drop table",
        r";\s?(?:drop (?:table|database|user)\b|truncate (?:table )?\w|alter (?:table|user)\b"
        r"|create (?:table|user)\b|delete from\b|insert into\b|update [\w.]{1,40} set\b"
        r"|select .{0,40}\bfrom\b|exec(?:ute)?\b|shutdown\b)",
    ),
    _pattern(
        "SQLI-04",
        SQL_INJECTION,
        "a quote, then a comment that cuts off the rest of the query: admin'--",
        r"['\"] ?\)? ?(?:--|#|/\*)",
    ),
    _pattern(
        "SQLI-05",
        SQL_INJECTION,
        "time delays used for blind injection: sleep(5), benchmark(...), waitfor delay",
        r"\b(?:sleep|benchmark|pg_sleep) ?\(|\bwaitfor delay\b",
    ),
    _pattern(
        "SQLI-06",
        SQL_INJECTION,
        "the database's own catalog tables, used to list tables and columns",
        r"\binformation_schema\b|\b(?:sysobjects|syscolumns|pg_catalog|sqlite_master|mysql\.user)\b",
    ),
    # --- Cross-site scripting: text that a browser would run as script. ---------------
    _pattern(
        "XSS-01",
        XSS,
        "a script tag: <script",
        r"< ?/? ?script\b",
    ),
    _pattern(
        "XSS-02",
        XSS,
        "a tag with an event handler attribute: <img src=x onerror=",
        r"<[a-z][^>]{0,200}\bon[a-z]{3,30} ?=",
    ),
    _pattern(
        "XSS-03",
        XSS,
        "a script URL: javascript: or vbscript:",
        r"\b(?:java|vb) ?script ?:",
    ),
    _pattern(
        "XSS-04",
        XSS,
        "tags that load or embed other content: <iframe, <object, <embed, <base, <meta",
        r"< ?(?:iframe|frame|object|embed|base|meta|applet)\b",
    ),
    _pattern(
        "XSS-05",
        XSS,
        "HTML hidden in a URL or attribute: data:text/html, srcdoc=",
        r"\bdata ?: ?text/html\b|\bsrcdoc ?=",
    ),
    # --- Path traversal: reaching files outside the folder the app means to read. -------
    _pattern(
        "PATH-01",
        PATH_TRAVERSAL,
        "two or more steps up the folder tree: ../../",
        r"(?:\.\.[/\\]){2,50}",
    ),
    _pattern(
        "PATH-02",
        PATH_TRAVERSAL,
        "a well-known system file or folder: /etc/passwd, c:\\windows\\",
        r"/etc/(?:passwd|shadow|hosts|group)\b|/proc/self/|\bc:[/\\]windows[/\\]"
        r"|[/\\]windows[/\\]system32\b|\b(?:boot|win)\.ini\b",
    ),
    _pattern(
        "PATH-03",
        PATH_TRAVERSAL,
        "one step up, then a null byte that cuts off the rest of the file name",
        r"\.\.[/\\].{0,200}\x00",
    ),
    # --- Command injection: text that the shell would run as a command. ----------------
    _pattern(
        "CMD-01",
        COMMAND_INJECTION,
        "a shell separator, then a command: ; cat, && whoami, | id, `ls`, $(id)",
        r"(?:;|&&|\|\|?|`|\$\() ?" + _COMMANDS + r"\b",
    ),
    _pattern(
        "CMD-02",
        COMMAND_INJECTION,
        "a shell called by its full path or a Windows shell switch: /bin/sh, cmd /c",
        r"/bin/(?:ba|z|da)?sh\b|/usr/bin/(?:env|python3?|perl)\b|\bcmd(?:\.exe)? /c\b"
        r"|\bpowershell(?:\.exe)? -",
    ),
    _pattern(
        "CMD-03",
        COMMAND_INJECTION,
        "the shell's field separator used in place of spaces: ${ifs}",
        r"\$\{?ifs\}?",
    ),
    # --- Format strings and template injection: text used as a template. --------------
    _pattern(
        "FMT-01",
        FORMAT_STRING,
        "Python format fields reaching into objects: {0.__class__}, {.__globals__}",
        r"\{\w{0,20}(?:\.|\[) ?_{1,2}[a-z]{1,40}",
    ),
    _pattern(
        "FMT-02",
        FORMAT_STRING,
        "printf writes and leaks: %n, or a run of %x / %p / %s",
        # Three conversions in a row are written out, not repeated with {3,}: a repeat
        # inside a repeat is exactly what rule DE5 forbids.
        r"%(?:\d{1,3}\$)?h{0,2}n(?![a-z])"
        r"|%[\d.$]{0,8}[xps][.,: ]?%[\d.$]{0,8}[xps][.,: ]?%[\d.$]{0,8}[xps]",
    ),
    _pattern(
        "FMT-03",
        FORMAT_STRING,
        "template expressions and tags: {{ 7*7 }}, {% ... %}",
        r"\{\{[^{}]{1,100}\}\}|\{%[^%]{1,100}%\}",
    ),
    _pattern(
        "FMT-04",
        FORMAT_STRING,
        "expression templates: ${...}, #{...}, <%= ... %>",
        r"\$\{[^{}]{1,100}\}|#\{[^{}]{1,100}\}|<%=",
    ),
)

# Every ID is unique (checked once, when the module loads).
if len({pattern.id for pattern in PATTERNS}) != len(PATTERNS):
    raise RuntimeError("two detection patterns share an ID")
