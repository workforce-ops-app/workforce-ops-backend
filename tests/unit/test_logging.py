"""Log lines are JSON objects with extra fields and, for errors, the stack trace."""

import json
import logging
import sys

from app.core.logging import JsonFormatter, configure_logging


def make_record(**kwargs: object) -> logging.LogRecord:
    return logging.LogRecord(
        name="app.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="shift created",
        args=(),
        exc_info=kwargs.pop("exc_info", None),  # type: ignore[arg-type]
    )


def test_log_line_is_json_with_extra_fields() -> None:
    record = make_record()
    record.fields = {"shift_id": "0192-abc", "action": "shift.created"}

    entry = json.loads(JsonFormatter().format(record))

    assert entry["message"] == "shift created"
    assert entry["level"] == "INFO"
    assert entry["shift_id"] == "0192-abc"
    assert entry["action"] == "shift.created"


def test_error_log_line_includes_the_stack_trace() -> None:
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        record = make_record(exc_info=sys.exc_info())

    entry = json.loads(JsonFormatter().format(record))

    assert "RuntimeError: boom" in entry["exception"]


def test_configure_logging_sets_level_and_json_output() -> None:
    configure_logging("WARNING")

    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
