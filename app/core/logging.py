"""Structured logging: one JSON object per line (decision 0031).

Log lines carry IDs, actions, and errors only, never personal details, passwords, tokens,
or the contents of records. A line written during a request also carries the request's ID,
the address that sent it, and, once the session is checked, the person's and company's IDs
(#92, app/core/request_context.py).
"""

import json
import logging
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Who sent the request this line was written for, and from where (#92): attached
        # when the line was written (app/core/request_context.py, the record factory), so
        # a line formatted later still names its own request.
        context = getattr(record, "request_context", None)
        if isinstance(context, dict):
            entry.update(context)
        # Extra fields passed as logger.info("...", extra={"fields": {...}}).
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry.update(fields)
        if record.exc_info:
            # The stack trace goes to the log (for developers), never into a response.
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
