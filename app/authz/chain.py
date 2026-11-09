"""The reporting chain: who is above whom (authorization.md, the reporting chain; 0024).

A reporting_lines row says one person reports to another. Following the current lines
upwards from a person gives everyone above them; following them downwards from a person
gives everyone below them. Being above someone grants nothing by itself: it decides WHOM
a person permission may act on (app/authz/check.py), while permissions decide WHAT.

Both walks are recursive queries (WITH RECURSIVE), built with SQLAlchemy and never as SQL
text (decision 0022). In SQL, the walk upwards from person B is:

    WITH RECURSIVE above (person_id) AS (
        SELECT manager_id FROM reporting_lines              -- B's direct managers
         WHERE employee_id = :b AND ended_at IS NULL
        UNION                                               -- drop repeats, so a loop ends
        SELECT r.manager_id FROM reporting_lines r          -- their managers, and so on
          JOIN above a ON r.employee_id = a.person_id
         WHERE r.ended_at IS NULL
    )
    ...

The company filter (app/tenancy/filter.py) adds "company_id = <the session's company>" to
every one of those SELECTs, so a chain never leaves the company. It only accepts a query
whose OUTER select reads the ReportingLine model, which is why each function below ends
with a select on ReportingLine rather than on the recursive part alone.

Deactivated people stay in the chain: deactivating a manager removes what they may do
(they hold no permissions), but the people above them stay above the people below them.
Ended lines do not count.
"""

import uuid

from sqlalchemy import CTE, ColumnElement, or_, select
from sqlalchemy.orm import Session, aliased

from app.audit import Actor, record
from app.authz.models import ReportingLine


class ReportingLineError(ValueError):
    """A reporting line the data rules do not allow (data-model.md, reporting_lines)."""


def _current() -> ColumnElement[bool]:
    """Only lines that have not ended count."""
    return ReportingLine.ended_at.is_(None)


def _managers_above(person_id: uuid.UUID) -> CTE:
    """Everyone above the person: their managers, their managers' managers, and so on."""
    # Start: the person's direct managers.
    start = (
        select(ReportingLine.manager_id.label("person_id"))
        .where(ReportingLine.employee_id == person_id, _current())
        .cte("above", recursive=True)
    )
    # Repeat: the managers of everyone found so far. A second name (alias) for the table,
    # because the query reads reporting_lines twice: once for the start, once per step.
    line = aliased(ReportingLine)
    step = (
        select(line.manager_id)
        .join(start, line.employee_id == start.c.person_id)
        .where(line.ended_at.is_(None))
    )
    # UNION, not UNION ALL: a person already found is not added again, so even a loop that
    # slipped past add_reporting_line() would end the walk instead of running forever.
    return start.union(step)


def _employees_below(person_id: uuid.UUID) -> CTE:
    """Everyone below the person: the same walk as _managers_above(), downwards."""
    start = (
        select(ReportingLine.employee_id.label("person_id"))
        .where(ReportingLine.manager_id == person_id, _current())
        .cte("below", recursive=True)
    )
    line = aliased(ReportingLine)
    step = (
        select(line.employee_id)
        .join(start, line.manager_id == start.c.person_id)
        .where(line.ended_at.is_(None))
    )
    return start.union(step)


def is_above_in_chain(db: Session, user_id: uuid.UUID, person_id: uuid.UUID) -> bool:
    """Whether the user is above the person through reporting lines.

    The Owner's place above everyone is checked by the caller (check.is_above), not here.
    Nobody is above themselves.
    """
    if user_id == person_id:
        return False
    above = _managers_above(person_id)
    # The user is above the person when the user manages the person directly, or manages
    # someone above the person.
    found = db.scalar(
        select(ReportingLine.id)
        .where(
            ReportingLine.manager_id == user_id,
            _current(),
            or_(
                ReportingLine.employee_id == person_id,
                ReportingLine.employee_id.in_(select(above.c.person_id)),
            ),
        )
        .limit(1)
    )
    return found is not None


def people_below(db: Session, user_id: uuid.UUID) -> set[uuid.UUID]:
    """The IDs of everyone below the user through reporting lines (never the user).

    Used by the list filter (check.scope_filter). It runs as a query of its own, and the
    list then filters on the IDs it returns: the company filter does not accept a
    recursive query nested inside a query on another table, such as users.
    """
    below = _employees_below(user_id)
    # Everyone reporting to the user, or to someone below the user.
    ids = db.scalars(
        select(ReportingLine.employee_id).where(
            _current(),
            or_(
                ReportingLine.manager_id == user_id,
                ReportingLine.manager_id.in_(select(below.c.person_id)),
            ),
        )
    )
    # A loop that slipped in could lead back to the user; nobody is below themselves.
    return set(ids) - {user_id}


def add_reporting_line(
    db: Session, actor: Actor, *, manager_id: uuid.UUID, employee_id: uuid.UUID
) -> ReportingLine:
    """Record that the employee reports to the manager; audited. The caller commits.

    Applies the data rules (data-model.md, reporting_lines): nobody reports to
    themselves, one current line per pair, and no loops. Who may add a line (someone above
    both people, with reporting_line.manage, never one of the two) is checked by the
    endpoint that calls this (slice Z5, workforce-ops-app/workforce-ops-backend#56); the
    seed script calls it as the system.
    """
    if manager_id == employee_id:
        raise ReportingLineError("nobody reports to themselves")
    duplicate = db.scalar(
        select(ReportingLine.id).where(
            ReportingLine.manager_id == manager_id,
            ReportingLine.employee_id == employee_id,
            _current(),
        )
    )
    if duplicate is not None:
        raise ReportingLineError("this person already reports to this manager")
    # A loop: the employee is already above the new manager, so the manager would end up
    # above themselves (A reports to B, who reports, directly or not, to A).
    if is_above_in_chain(db, employee_id, manager_id):
        raise ReportingLineError("this line would make a loop in the reporting chain")

    line = ReportingLine(manager_id=manager_id, employee_id=employee_id)
    db.add(line)
    db.flush()  # gives the line its ID for the audit entry
    record(
        db,
        actor=actor,
        action="reporting_line.added",
        target_type="reporting_line",
        target_id=line.id,
        details={"manager_id": str(manager_id), "employee_id": str(employee_id)},
    )
    return line
