"""Threats I7 and R3: user text is never a format template or a log message (#106).

In Python, `user_text.format(obj)` lets whoever wrote the text read the program's
internals: `{0.__class__.__init__.__globals__}` reaches module globals, secrets included.
`"%s" % ...` and `string.Template` work the same way when the template is the user's. And
text written as a log MESSAGE (not as a field) can carry a line break and a forged log line
after it.

So every template in the code is written in the code: these tests read the source of the
application and its scripts and refuse

1. `.format(...)` or `.format_map(...)` on anything but a string literal (and
   `str.format(template, ...)` with a template that is not a literal);
2. `%` formatting whose template is not a string literal (`%` between numbers is fine);
3. `string.Template` at all;
4. a logging call whose message is not a string literal; values go in as extra fields
   (app/core/logging.py), where the JSON formatter escapes them.

ruff's G rules (pyproject.toml) also refuse log messages built with f-strings, `.format`,
`%`, or `+`; these tests add the cases a linter does not see (a message held in a
variable, a template that is not a literal).
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCES = sorted([*(ROOT / "app").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")])
LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical", "log"}


def _is_text(node: ast.AST | None) -> bool:
    """A string literal written in the code."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_number(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) in (int, float)


def problems_in(source: str) -> list[str]:
    """What breaks the four rules above in one file's source, with line numbers."""
    found = []
    for node in ast.walk(ast.parse(source)):
        # 1. .format / .format_map on something other than a literal.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method, owner = node.func.attr, node.func.value
            if method in ("format", "format_map"):
                if isinstance(owner, ast.Name) and owner.id == "str":
                    template = node.args[0] if node.args else None
                    if not _is_text(template):
                        found.append(f"line {node.lineno}: str.{method} with a template")
                elif not _is_text(owner):
                    found.append(f"line {node.lineno}: .{method}() on a value, not a literal")
            # 4. A logging call whose message is not a literal. Loggers are named for
            #    what they are (logger, log, _log, LOGGER), so the owner's name says so.
            if method in LOG_METHODS and "log" in ast.unparse(owner).lower():
                message = node.args[1 if method == "log" else 0] if node.args else None
                if method == "log" and len(node.args) < 2:
                    message = None
                if not _is_text(message):
                    found.append(f"line {node.lineno}: a log message that is not a literal")
        # 2. % formatting with a template that is not a literal.
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and not _is_text(node.left)
            and not _is_number(node.right)
        ):
            found.append(f"line {node.lineno}: % with a template that is not a literal")
        # 3. string.Template.
        imported = isinstance(node, ast.ImportFrom) and node.module == "string"
        if imported and any(alias.name == "Template" for alias in node.names):  # type: ignore[union-attr]
            found.append(f"line {node.lineno}: string.Template")
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "Template"
            and isinstance(node.value, ast.Name)
            and node.value.id == "string"
        ):
            found.append(f"line {node.lineno}: string.Template")
    return found


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_template_or_log_message_comes_from_a_value(path: Path) -> None:
    assert problems_in(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "source",
    [
        "note.format(user=user)",
        "note.format_map(values)",
        "str.format(note, user)",
        "note % values",
        "from string import Template",
        "string.Template(note)",
        "logger.info(note)",
        "logger.warning(f'saved {note}')",
        "log.log(20, note)",
    ],
)
def test_the_scan_finds_each_kind_of_mistake(source: str) -> None:
    """The scan is only worth something if it fails on what it looks for."""
    assert problems_in(source), source


@pytest.mark.parametrize(
    "source",
    [
        "'Hello {name}'.format(name=note)",  # the template is the code's; the value is data
        "'%s saved' % note",
        "str.format('{0}', note)",
        "-len(cursor) % 4",  # arithmetic
        "logger.info('shift saved', extra={'fields': {'note': note}})",
        "log.log(20, 'shift saved')",
    ],
)
def test_the_scan_allows_templates_written_in_the_code(source: str) -> None:
    assert problems_in(source) == [], source
