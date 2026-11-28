"""Threats I7 and R3: user text is never a format template or a log message (#106).

In Python, `user_text.format(obj)` lets whoever wrote the text read the program's
internals: `{0.__class__.__init__.__globals__}` reaches module globals, secrets included.
`"%s" % ...`, `string.Template`, and `string.Formatter` work the same way when the
template is the user's. And text written as a log MESSAGE (not as a field) can carry a
line break and a forged log line after it.

So every template in the code is written in the code: these tests read the source of the
application and its scripts and refuse

1. `.format(...)` or `.format_map(...)` on anything but a string literal (and
   `str.format(template, ...)` with a template that is not a literal);
2. `%` whose left side is not a string literal, unless it is plainly a number: a number
   literal, arithmetic on numbers, `len()`, `int()` and the like, or a name that its
   function only ever binds to a number (`for n in range(...)`, `enumerate`'s counter, a
   parameter typed `int`, `n = 0`). Anything else, `user_text % 42` included, is refused:
   a number the scan cannot see is one is written `int(x) % 4`;
3. `string.Template` and `string.Formatter` at all, under any name (`import string as s`);
4. a logging call whose message is not a string literal; values go in as extra fields
   (app/core/logging.py), where the JSON formatter escapes them. A logger is recognised
   by what made it (`logging.getLogger`, `getChild`, `LoggerAdapter`, whatever its
   variable is called, such as `refusals`), by `logging.info(...)` and the functions
   imported from `logging` (under any alias), or by a name containing "log" (a logger
   passed in as a parameter).

This is a reading of the source, not a taint analysis; what it cannot see is listed in
docs/security/threat-model.md (I7): a logger reached through a container or `getattr`,
or under a name without "log" that came from another module.

ruff's G rules (pyproject.toml) also refuse log messages built with f-strings, `.format`,
`%`, or `+`; these tests add the cases a linter does not see (a message held in a
variable, a template that is not a literal).
"""

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCES = sorted([*(ROOT / "app").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")])
LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical", "log"}
# What makes a logger: logging.getLogger("x"), logger.getChild("y"), LoggerAdapter(...).
LOGGER_MAKERS = {"getLogger", "getChild", "LoggerAdapter"}
# Builtins whose answer is always a number, so `len(cursor) % 4` is arithmetic.
NUMBER_FUNCTIONS = {"len", "int", "float", "abs", "round", "ord", "hash", "sum"}
NUMBER_TYPES = {"int", "float"}
ARITHMETIC = (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow, ast.Div)
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)
STRING_TEMPLATES = {"Template", "Formatter"}


def _is_text(node: ast.AST | None) -> bool:
    """A string literal written in the code."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_number_type(annotation: ast.AST | None) -> bool:
    """An annotation that says int or float."""
    return isinstance(annotation, ast.Name) and annotation.id in NUMBER_TYPES


def _is_number(node: ast.AST, numbers: set[str]) -> bool:
    """Whether the expression is plainly a number. `numbers` are the names its function
    only ever binds to numbers."""
    if isinstance(node, ast.Constant):
        return type(node.value) in (int, float, bool)
    if isinstance(node, ast.UnaryOp):
        return _is_number(node.operand, numbers)
    if isinstance(node, ast.NamedExpr):  # (n := 7) % 3
        return _is_number(node.value, numbers)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ARITHMETIC):
        # Both sides: "a" + "b" is text, and so is "%s" * 2.
        return _is_number(node.left, numbers) and _is_number(node.right, numbers)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in NUMBER_FUNCTIONS
    if isinstance(node, ast.Name):
        return node.id in numbers
    return False


def _bindings(scope: ast.AST) -> Iterator[tuple[str, bool]]:
    """Each name the scope binds, and whether that binding is plainly a number. Nested
    functions are scopes of their own and are left out."""
    if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
        arguments = scope.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *filter(None, [arguments.vararg, arguments.kwarg]),
        ]:
            yield argument.arg, _is_number_type(argument.annotation)
    for node in _own_nodes(scope):
        if isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            loop = node.iter
            called = (
                loop.func.id
                if isinstance(loop, ast.Call) and isinstance(loop.func, ast.Name)
                else ""
            )
            target = node.target
            if called == "range" and isinstance(target, ast.Name):
                yield target.id, True
            elif called == "enumerate" and isinstance(target, ast.Tuple) and target.elts:
                first, *rest = target.elts
                if isinstance(first, ast.Name):
                    yield first.id, True
                for other in rest:
                    for name in ast.walk(other):
                        if isinstance(name, ast.Name):
                            yield name.id, False
            else:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        yield name.id, False
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Only names bound so far count: an assignment from a name is not
                    # followed, which keeps the scan simple and errs towards refusing.
                    yield target.id, _is_number(node.value, set())
                else:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name):
                            yield name.id, False
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            yield node.target.id, _is_number_type(node.annotation)
        elif isinstance(node, ast.NamedExpr):
            yield node.target.id, _is_number(node.value, set())
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    for name in ast.walk(item.optional_vars):
                        if isinstance(name, ast.Name):
                            yield name.id, False
        elif isinstance(node, ast.ExceptHandler) and node.name:
            yield node.name, False
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                yield (alias.asname or alias.name).split(".")[0], False


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """The nodes of a scope, without those of the functions nested in it."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _numbers_in(scope: ast.AST) -> set[str]:
    """The names a scope binds only ever to numbers."""
    number, other = set(), set()
    for name, is_number in _bindings(scope):
        (number if is_number else other).add(name)
    return number - other


def _logging(tree: ast.Module) -> tuple[set[str], set[str], set[str]]:
    """What logs in this file: the names of the logging module (`import logging as lg`),
    the logging functions imported by name (`from logging import info`), and the loggers
    assigned (as written: "logger", "refusals", "self.audit")."""
    modules, functions, makers = set(), set(), set(LOGGER_MAKERS)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {
                alias.asname or alias.name for alias in node.names if alias.name == "logging"
            }
        elif isinstance(node, ast.ImportFrom) and node.module == "logging":
            for alias in node.names:
                if alias.name in LOG_METHODS:
                    functions.add(alias.asname or alias.name)
                if alias.name in LOGGER_MAKERS:
                    makers.add(alias.asname or alias.name)
    loggers = set()
    for node in ast.walk(tree):
        value = getattr(node, "value", None)
        if isinstance(node, ast.Assign | ast.AnnAssign) and isinstance(value, ast.Call):
            func = value.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in makers:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                loggers |= {ast.unparse(target) for target in targets}
    return modules, functions, loggers


def _is_logger(owner: ast.AST, modules: set[str], loggers: set[str]) -> bool:
    """Whether a method's owner is a logger, or the logging module."""
    written = ast.unparse(owner)
    if written in modules or written in loggers or "log" in written.lower():
        return True
    # logging.getLogger("x").info(...): made and used at once.
    if isinstance(owner, ast.Call):
        func = owner.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        return name in LOGGER_MAKERS
    return False


def problems_in(source: str) -> list[str]:
    """What breaks the four rules above in one file's source, with line numbers."""
    tree = ast.parse(source)
    found = []
    modules, log_functions, loggers = _logging(tree)
    # The names of the string module here: "string" itself, and any alias
    # (`import string as s`).
    strings = {"string"} | {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "string"
    }
    # The scope of every node, for the names its function binds to numbers.
    numbers: dict[int, set[str]] = {}
    scope_of: dict[int, ast.AST] = {}
    for scope in ast.walk(tree):
        if isinstance(scope, SCOPES):
            for node in _own_nodes(scope):
                scope_of[id(node)] = scope

    def numbers_for(node: ast.AST) -> set[str]:
        scope = scope_of.get(id(node), tree)
        if id(scope) not in numbers:
            numbers[id(scope)] = _numbers_in(scope)
        return numbers[id(scope)]

    for node in ast.walk(tree):
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
            # 4. A logging call whose message is not a literal.
            if method in LOG_METHODS and _is_logger(owner, modules, loggers):
                found += _log_message_problem(node, method)
        # 4. The same, through a function imported from logging (`from logging import info`).
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in log_functions
        ):
            found += _log_message_problem(node, node.func.id)
        # 2. % formatting with a template that is not a literal, and not plainly a number.
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and not _is_text(node.left)
            and not _is_number(node.left, numbers_for(node))
        ):
            found.append(f"line {node.lineno}: % with a template that is not a literal")
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.op, ast.Mod)
            and not _is_number(node.target, numbers_for(node))
        ):
            found.append(f"line {node.lineno}: %= with a template that is not a literal")
        # 3. string.Template and string.Formatter, imported by name or used through the
        #    module under any name.
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "string"
            and any(alias.name in STRING_TEMPLATES for alias in node.names)
        ):
            found.append(f"line {node.lineno}: string.Template or string.Formatter")
        if (
            isinstance(node, ast.Attribute)
            and node.attr in STRING_TEMPLATES
            and isinstance(node.value, ast.Name)
            and node.value.id in strings
        ):
            found.append(f"line {node.lineno}: string.{node.attr}")
    return found


def _log_message_problem(node: ast.Call, method: str) -> list[str]:
    """The problem with a logging call's message, if it is not a literal. `log` takes
    the level first, the message second."""
    position = 1 if method == "log" else 0
    message = node.args[position] if len(node.args) > position else None
    if _is_text(message):
        return []
    return [f"line {node.lineno}: a log message that is not a literal"]


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
        # A number on the right does not make it arithmetic (review of #203).
        "user_text % 42",
        "user_text % -1",
        "def f(note):\n    return note % 4",
        "def f(note: str):\n    return note % 4",
        "for note in notes:\n    note % 4",
        "for number, note in enumerate(notes):\n    note % 4",
        "note = text\nnote % 4",
        "n = 0\nn = note\nn % 4",  # once a number, then text: not plainly a number
        "('%s' * 2) % note",
        "note %= values",
        "from string import Template",
        "from string import Formatter",
        "string.Template(note)",
        # Aliases (review of #203).
        "import string as strings\nstrings.Template(note)",
        "import string as s\ns.Formatter().format(note)",
        "from string import Template as T",
        "logger.info(note)",
        "logger.warning(f'saved {note}')",
        "log.log(20, note)",
        "log.log(20)",
        # A logger whose name does not say "log" (review of #203).
        "audit = logging.getLogger('app.audit')\naudit.info(note)",
        "refusals = logging.getLogger('app.refusals')\nrefusals.warning(note)",
        "import logging as lg\nevents = lg.getLogger()\nevents.error(note)",
        "from logging import getLogger as get\nevents = get('x')\nevents.info(note)",
        "child = parent_logger.getChild('x')\nchild.info(note)",
        "self.audit = logging.LoggerAdapter(base, {})\nself.audit.info(note)",
        "logging.getLogger('x').info(note)",
        "import logging as lg\nlg.info(note)",
        "logging.warning(note)",
        "from logging import info\ninfo(note)",
        "from logging import warning as warn\nwarn(note)",
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
        # Arithmetic.
        "-len(cursor) % 4",
        "7 % 3",
        "(a_number := 7) % 3",
        "for number in range(10):\n    number % 2",
        "for number, attack in enumerate(attacks):\n    number % 2",
        "def f(number: int):\n    return number % 1000",
        "count = 0\ncount % 2",
        "int(value) % 4",
        "(len(a) + 1) % 4",
        "total = 0\ntotal %= 7",
        "logger.info('shift saved', extra={'fields': {'note': note}})",
        "log.log(20, 'shift saved')",
        "audit = logging.getLogger('app.audit')\naudit.info('saved', extra={'fields': {}})",
        "from logging import info\ninfo('saved')",
        "import string\nstring.ascii_letters",  # the module itself is fine
        # A name that is a number in one function and text in another.
        "def a(n: int):\n    return n % 2\ndef b(n: str):\n    return len(n)",
    ],
)
def test_the_scan_allows_templates_written_in_the_code(source: str) -> None:
    assert problems_in(source) == [], source


def test_a_name_is_a_number_only_in_its_own_function() -> None:
    """The same name as text in another function does not let it through here."""
    source = "def a(n: int):\n    return n % 2\ndef b(n: str):\n    return n % 2"
    assert problems_in(source) == ["line 4: % with a template that is not a literal"]
