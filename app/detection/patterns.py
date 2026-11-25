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

Tuning (backend #199): the patterns were tuned only on the detection study's tuning
split (research repository, datasets/detection/tuning.jsonl); the test split was never
opened. Each pattern added in tuning describes how a kind of attack is built, not one
payload. Patterns whose matches were narrowed were retired and replaced by a new ID
(RETIRED below), so a stored event always means what its ID meant when it was recorded.

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
    _pattern(
        "SQLI-07",
        SQL_INJECTION,
        "a test between two literals with no quote before it: or 1=1, and 1=0, where 'a'='a'",
        # Numeric injection needs no quote: the value is already inside the SQL. The test
        # compares two LITERALS (numbers or short quoted strings), which ordinary text does
        # not do after "or", "and", "where", or "having". Not right after a closing quote
        # or bracket: SQLI-01 already reports that case, and one attack is one event.
        r"(?<!['\"\)])(?<!['\"\)] )\b(?:or|and|where|having) "
        r"\(?(?:\d{1,10}|'[^']{0,10}'|\"[^\"]{0,10}\") ?"
        r"(?:=|<>|!=|>|<|like\b) ?\(?(?:\d|'|\")",
    ),
    _pattern(
        "SQLI-08",
        SQL_INJECTION,
        "a quote closing the string, then a clause that changes the query: "
        "' having 1=1, ' order by 3",
        # Or, with no quote, "order by <number>" cut off by a comment: counting the
        # query's columns before a union select.
        r"['\"\)] ?(?:having \d|group by \w|order by \d|procedure analyse\b|limit \d)"
        r"|\border by \d{1,3} ?(?:--|#|/\*)",
    ),
    _pattern(
        "SQLI-09",
        SQL_INJECTION,
        "a subquery, a function selected on its own, or a full CASE: (select count(*) ...), "
        "select version(), select * from, case when ... then ... else ... end",
        # "(select" right after a bracket, followed by what only SQL puts there; or
        # "select name(" with no space before the bracket, as a function call is written.
        r"\(select (?:\(|\*|case\b|count\b|concat\b|char\b|@@|'|[\w.@]{1,40} from\b)"
        r"|\bselect [a-z_@]{1,40}\(|\bselect \* from\b"
        # A CASE expression written out in full, as blind injection asks yes-or-no.
        r"|\bcase when .{1,60} then .{1,60} else .{1,60} end\b",
    ),
    _pattern(
        "SQLI-11",
        SQL_INJECTION,
        "a quote closing the string, then or/and a constant, then a comment: \")or true#, ')or 2--",
        # The login-bypass family: whatever is constant makes the test true or false, and
        # the comment removes the rest of the query (the password check).
        r"['\"\)] ?(?:or|and|\|\|) ?\(?(?:true|false|\d{1,10}|'\d{0,10}'|\"\d{0,10}\")\)? ?"
        r"(?:--|#|/\*)|\b(?:or|and) (?:true|false) ?(?:--|#|/\*)",
    ),
    _pattern(
        "SQLI-10",
        SQL_INJECTION,
        "server variables, procedures, and functions used to read data through errors: "
        "@@version, xp_cmdshell, extractvalue(, convert(int, syscat.",
        r"@@[a-z_]{3,30}|\bxp_cmdshell\b|\b(?:extractvalue|updatexml|make_set|elt|json_keys"
        r"|dbms_[a-z_]{1,30}|utl_inaddr\.[a-z_]{1,30}|ctxsys\.[a-z_]{1,30}) ?\("
        # SQL Server's error-based conversion, and DB2's catalogs (SQLI-06 has the others).
        r"|\bconvert ?\( ?int ?,|\b(?:syscat|sysibm)\.[a-z_]{1,30}",
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
    _pattern(
        "XSS-06",
        XSS,
        'a quote ending an attribute, then an event handler: " autofocus onfocus=alert(1)',
        # The value lands inside an HTML attribute, so no "<" is needed: the quote ends it.
        r"['\"`][^'\"<>=]{0,60}\bon[a-z]{3,30} ?= ?[^ ]",
    ),
    _pattern(
        "XSS-07",
        XSS,
        "a script call right after a character that ends a string or statement: '-alert(1)-'",
        # The value lands inside a script: a quote, ";", "}", or an operator ends what was
        # there, then a call that shows the attack worked (or runs any code: eval).
        r"[;'\"`}\-+)(] ?(?:alert|confirm|prompt|eval|settimeout|setinterval) ?[(`]",
    ),
    _pattern(
        "XSS-08",
        XSS,
        "script run from CSS: width:expression(...), behavior:url(...), -moz-binding:url(...)",
        r": ?expression ?\(|\b(?:behavior|-moz-binding) ?: ?url\b",
    ),
    _pattern(
        "XSS-09",
        XSS,
        "script or markup in another namespace or XML: <html:script, <?xml-stylesheet, <vmlframe",
        r"< ?/? ?[a-z]{1,20}:script\b|<\?xml-stylesheet\b|< ?(?:xml|vmlframe)\b",
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
    _pattern(
        "PATH-04",
        PATH_TRAVERSAL,
        "steps up the folder tree with the slash disguised: ..0x5c.., ..%u2216.., ..2f.., "
        "/./.././../",
        # Two runs of dots with a separator between them that is a slash, a hex or %u
        # escape (with or without its "0x" or "%"), a broken (%) escape, or the replacement
        # character an overlong UTF-8 slash decodes to (U+FFFD).
        r"\.{2,4}(?:[/\\\ufffd]|(?:0x)?(?:5c|2f)|%u[0-9a-f][0-9a-f][0-9a-f][0-9a-f]|%\w?\w?){1,8}\.{2,4}"
        r"|0x2e0x2e(?:[/\\]|0x(?:5c|2f))"
        # Four or more "/." or "/.." steps in a row: /./.././../ means the same as ../../
        r"|(?:[/\\]\.\.?){4,50}[/\\]",
    ),
    _pattern(
        "PATH-05",
        PATH_TRAVERSAL,
        "a full path to a system folder or file: /etc/..., /var/log/..., c:\\windows, ~/.ssh",
        # A field of this application (a name, a note, a reason) has no reason to hold an
        # absolute path into the operating system's own folders. On Windows: a drive, then
        # a folder of the system or of a server program (not c:\users\..., where people
        # keep their own files).
        r"(?<![\w.])/(?:etc|proc|sys|root|boot|var/(?:log|lib|www|db|mail|spool)"
        r"|usr/(?:local|lib|share|s?bin))/[\w.~-]"
        r"|\b[a-z]:[/\\](?:windows|winnt|program files|programdata|documents and settings"
        r"|inetpub|xampp|wamp|apache|php|mysql|logs|boot\.ini|users[/\\]all users)"
        r"|~/\.[a-z]",
    ),
    _pattern(
        "PATH-06",
        PATH_TRAVERSAL,
        "a well-known system file with its slash disguised: etc0x2fpasswd, etc∕issue",
        # Tools try every encoding of "/" in front of the same few files; whatever the
        # slash became (a hex escape, a look-alike, a broken byte), the names around it
        # stay. The separator excludes spaces and punctuation, so "etc, hosts" is not it.
        r"(?:\b|0x2f|0x5c|2f|5c)etc(?:[^\w\s,.;:!?'\"()-]{1,6}|0x2f|0x5c|2f|5c)"
        r"(?:passwd|shadow|issue|hosts|group)\b"
        r"|system32(?:[^\w\s,.;:!?'\"()-]{1,6}|0x2f|0x5c|2f|5c)drivers\b|[^\w\s]oot\.ini\b",
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
    _pattern(
        "CMD-04",
        COMMAND_INJECTION,
        "a shell separator, then a Windows or network command: & dir, ; netstat, | netsh",
        # A single "&" also runs a command in the background (or after another on Windows);
        # only commands that are not everyday words follow it here ("dog & cat" is a note).
        r"(?:;|&|\||`) ?(?:dir|netstat|netsh|net (?:user|view|localgroup|share)|systeminfo"
        r"|tasklist|ipconfig|ifconfig)\b|& ?(?:ls|whoami|uname|ping|nslookup|wget|curl|bash)\b",
    ),
    _pattern(
        "CMD-05",
        COMMAND_INJECTION,
        "a program called by its full path, a server-side include, or a PHP call that runs a "
        "command: /usr/bin/id, <!--#exec, system('...')",
        r"(?<![\w.])/(?:usr/(?:local/)?)?s?bin/[a-z]{2,20}\b|<!-- ?#exec\b"
        # A bare function call only: a method such as os.system("id") reached from a
        # template is template injection (FMT-05 to FMT-07).
        r"|(?<![\w.])(?:system|shell_exec|passthru|popen|proc_open) ?\( ?['\"`]",
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
        "FMT-05",
        FORMAT_STRING,
        "an expression template that computes something: ${7*7}, #{t(java.lang...)}, <%= %>",
        # Replaces FMT-04 (retired): a bare field such as ${price} or the shell's ${str1}
        # is not an attack, so the braces must hold an operator, a call, a dot, a quote,
        # or a bracket.
        r"[$#]\{[^{}]{0,100}[*+(.'\"\[:][^{}]{0,100}\}|<%=",
    ),
    _pattern(
        "FMT-06",
        FORMAT_STRING,
        "a template expression or tag that computes something: {{ 7*7 }}, {% for ... %}",
        # Replaces FMT-03 (retired) for the same reason: {{customer}} is a mail-merge field.
        r"\{\{[^{}]{0,100}[*+(.'\"\[|][^{}]{0,100}\}\}|\{%[^%]{1,100}%\}",
    ),
    _pattern(
        "FMT-07",
        FORMAT_STRING,
        "a template reaching into the server's objects: {{''.__class__}}, {{request|attr(...)}}, "
        "{$smarty.version}, {php}",
        # Long payloads (over FMT-06's 100 characters, or with braces inside) still start
        # this way.
        r"\{\{[^{}]{0,60}?(?:__|\|attr ?\(|\.getclass ?\(|\bself\b|\brequest\.|\bconfig\b"
        r"|\bapp\.)|\{\$?smarty\.|\{/?php\}",
    ),
    _pattern(
        "FMT-08",
        FORMAT_STRING,
        "a run of printf number conversions reading the stack: %d%d%d, %u%u%u",
        r"%[\d.$]{0,8}[du][.,: ]?%[\d.$]{0,8}[du][.,: ]?%[\d.$]{0,8}[du]",
    ),
)

# Retired IDs: never used again for a different pattern (stored events may still name
# them). FMT-03 and FMT-04 matched plain fields ({{customer}}, ${price}, ${str1});
# replaced by FMT-06 and FMT-05 in tuning (backend #199).
RETIRED = ("FMT-03", "FMT-04")

# Every ID is unique (checked once, when the module loads).
if len({pattern.id for pattern in PATTERNS}) != len(PATTERNS):
    raise RuntimeError("two detection patterns share an ID")
if {pattern.id for pattern in PATTERNS} & set(RETIRED):
    raise RuntimeError("a retired detection pattern ID is in use again")
