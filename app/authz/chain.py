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

Changing lines is safe when two requests run at once: each change first locks the
company (lock_reporting_lines), then checks with reads that see the newest committed
lines (_is_above_fresh explains why ordinary reads are not enough).
"""

import uuid

from sqlalchemy import CTE, ColumnElement, or_, select
from sqlalchemy.orm import Session, aliased

from app.audit import Actor, record
from app.authz.models import ReportingLine
from app.modules.org.models import Company
from app.tenancy.context import get_company


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


def lock_reporting_lines(db: Session) -> None:
    """Make changes to this company's reporting lines take turns, until the caller commits.

    Locks the company's own row (SELECT ... FOR UPDATE). Every function that adds or ends a
    line calls this first, so a second change in the same company waits here until the
    first one commits or rolls back. Without it, two requests at the same moment could
    both pass the checks below and together add a duplicate or a loop: "A reports to B"
    and "B reports to A" each look fine on their own. Other companies are not blocked.

    Take this lock before writing any audit entry in the same transaction: the audit log
    locks its chain head too, and two transactions taking the two locks in opposite orders
    would wait for each other until MySQL gives up on one of them.
    """
    company_id = get_company(db)
    # A loop is a property of one company's whole chain, so there must be one company.
    if company_id is None:
        raise RuntimeError("reporting lines are changed in a session for their company")
    # The company filter lets this session see only its own company's row, so this can
    # only ever lock that one row.
    db.get(Company, company_id, with_for_update=True)


def _current_line_exists(db: Session, manager_id: uuid.UUID, employee_id: uuid.UUID) -> bool:
    """Whether a current line for this pair exists, read fresh (see _is_above_fresh)."""
    found = db.scalar(
        select(ReportingLine.id)
        .where(
            ReportingLine.manager_id == manager_id,
            ReportingLine.employee_id == employee_id,
            _current(),
        )
        .with_for_update(read=True)  # FOR SHARE: the newest committed rows
    )
    return found is not None


def _is_above_fresh(db: Session, user_id: uuid.UUID, person_id: uuid.UUID) -> bool:
    """Whether the user is above the person, reading the newest committed lines.

    The same question as is_above_in_chain(), asked step by step with locking reads, for
    the checks in add_reporting_line(). Why not just reuse is_above_in_chain(): MySQL's
    default isolation (REPEATABLE READ) lets an ordinary SELECT see the database as it was
    at the transaction's FIRST read, even after we waited for the lock above. A request
    that had already read something (its permission check does) would then miss a line
    that another request committed while it waited, and the race would be back. A locking
    read (FOR SHARE) always sees the newest committed rows.

    A recursive query cannot be used here: in MySQL a lock on the outer SELECT does not
    make the reads inside a WITH RECURSIVE part fresh. So this walks up one level per
    query. Chains are a few levels deep, so that is a handful of small queries.
    """
    if user_id == person_id:
        return False
    # Walk upwards from the person: first their direct managers, then those managers'
    # managers, and so on, until the user is found or nobody new turns up.
    seen: set[uuid.UUID] = set()
    level = {person_id}
    while level:
        managers = set(
            db.scalars(
                select(ReportingLine.manager_id)
                .where(ReportingLine.employee_id.in_(level), _current())
                .with_for_update(read=True)
            )
        )
        if user_id in managers:
            return True
        # Only people not met before go on to the next level, so even a loop that slipped
        # in some other way ends the walk instead of running forever.
        seen |= level
        level = managers - seen
    return False


def add_reporting_line(
    db: Session, actor: Actor, *, manager_id: uuid.UUID, employee_id: uuid.UUID
) -> ReportingLine:
    """Record that the employee reports to the manager; audited. The caller commits.

    Applies the data rules (data-model.md, reporting_lines): nobody reports to
    themselves, one current line per pair, and no loops. Safe when two requests run at
    once (lock_reporting_lines). Who may add a line (someone above both people, with
    reporting_line.manage, never one of the two) is checked by the endpoint that calls
    this (slice Z5, workforce-ops-app/workforce-ops-backend#56); the seed script calls it
    as the system.
    """
    if manager_id == employee_id:
        raise ReportingLineError("nobody reports to themselves")
    # 1. Take turns with any other change to this company's lines, before checking.
    lock_reporting_lines(db)
    # 2. One current line per pair. The database also refuses a second one (the
    #    current_line unique key), in case a write ever goes around this function.
    if _current_line_exists(db, manager_id, employee_id):
        raise ReportingLineError("this person already reports to this manager")
    # 3. A loop: the employee is already above the new manager, so the manager would end
    #    up above themselves (A reports to B, who reports, directly or not, to A).
    if _is_above_fresh(db, employee_id, manager_id):
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
