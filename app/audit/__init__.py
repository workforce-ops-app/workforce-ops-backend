"""The signed audit log: record() writes an entry in the same transaction as the action.

See docs/architecture/audit-log.md and decision 0018.
"""

from app.audit.record import Actor, AuditError, record

__all__ = ["Actor", "AuditError", "record"]
