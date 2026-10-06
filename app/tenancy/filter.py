"""The automatic company filter: layer 1 of the four tenancy layers (tenancy.md).

Every model that belongs to a company inherits CompanyOwned. From then on, for any
session (app/db/session.py, background jobs, tests):

- Reading: every SELECT, single-record lookup (session.get), count, UPDATE, and DELETE
  on a company-owned model gets "AND company_id = <the session's company>" added. Rows
  of other companies are never loaded, so they look exactly like rows that do not exist
  (the API then answers 404, layer 4).
- Saving: a new row gets the session's company filled in; a row for another company, a
  change that moves a row to another company, or deleting another company's row, is
  refused before anything is written.
- No company set: any query or save on a company-owned model raises an error instead of
  silently returning everything.
- The companies table itself (models marked CompanyRecord): each row is a company, so a
  session working for a company sees and changes only its own row, and cannot create or
  delete companies. Only sessions with no company (platform code, the seed script) manage
  companies.
- Refused, because the filter cannot make them safe (UnsafeQueryError):
  - statements on a company table itself (TenantNote.__table__) instead of the model;
  - bulk inserts (session.execute(insert(Model)...)), which skip the save check: add
    rows with session.add() or session.add_all();
  - bulk updates or deletes given a list of rows by primary key, which run without the
    company condition: load the rows and change them, or update with a where clause.
  A bulk update that sets company_id itself is refused as WrongCompanyError.
  - in a session working for a company, a bulk delete of companies (UnsafeQueryError) or
    a bulk update that sets a company's id (WrongCompanyError): both skip the save check
    that enforces the companies-table rules above.
- Last guard, at the database connection: any read or write of a company table that
  reaches the database without passing the checks above is refused. That covers
  SQLAlchemy's older bulk methods (bulk_insert_mappings, bulk_update_mappings,
  bulk_save_objects), statements run on session.connection() directly, and any other
  path that skips the ORM hooks. Only migrations, marked with trust_connection(), may
  touch company tables directly.

Feature code never filters by company itself and never turns this off. Queries written
as raw SQL text (session.execute(text(...))) name no tables SQLAlchemy can see, so they
are NOT filtered or refused: repositories build every query with SQLAlchemy and never
as SQL text (decision 0022). Models without CompanyOwned (for example companies
itself) are not filtered.
"""

import uuid
from collections.abc import Mapping
from typing import Any, cast

from sqlalchemy import Connection, Engine, event
from sqlalchemy.orm import Mapped, ORMExecuteState, Session, mapped_column, with_loader_criteria
from sqlalchemy.sql.elements import ClauseElement
from sqlalchemy.sql.util import find_tables

from app.db.base import Base
from app.db.types import UUIDBinary
from app.tenancy.context import get_company


class TenancyError(RuntimeError):
    """Something tried to read or write company data in a way that could cross companies."""


class MissingCompanyError(TenancyError):
    """A company-owned model was queried or saved in a session with no company set."""


class WrongCompanyError(TenancyError):
    """A save would put a row into, or move a row to, a company other than the session's."""


class UnsafeQueryError(TenancyError):
    """A statement on company data that the filter cannot make safe, so it is refused."""


class CompanyOwned:
    """The company_id column, and the marker that turns the company filter on.

    Use it together with the other bases:  class Shift(IdAndTimestamps, CompanyOwned, Base)
    """

    # Which company the row belongs to: required, and indexed because every query on the
    # table filters by it. Composite keys that include it are added per table (layer 2).
    company_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, nullable=False, index=True)


class CompanyRecord:
    """Marker for the companies table itself: each row is a company, and its id is the
    company's ID.

    In a session that works for a company, queries see only that company's row, and only
    that row can be changed; creating or deleting companies is refused. Sessions with no
    company (platform code, the seed script) manage companies.

    Use it on the Company model only:  class Company(IdAndTimestamps, CompanyRecord, Base)
    """


# Markers for the last guard (_guard_connection below). They are execution options:
# CHECKED on a single statement that passed the query hook, SAVING and TRUSTED on one
# connection handle. Execution options belong to that handle only, never to the pooled
# database connection underneath, so a marker cannot carry over into another request.
_CHECKED = "tenancy_checked"
_SAVING = "tenancy_saving"
_TRUSTED = "tenancy_trusted"


def trust_connection(connection: Connection) -> None:
    """Let this connection read and write company tables directly, for every company.

    Only for migrations (migrations/env.py): operator-run code that no request can
    reach, where a data fix may legitimately span companies. Never used by the app.
    """
    connection.execution_options(**{_TRUSTED: True})


def _is_company_owned(mapped_class: type) -> bool:
    """Whether a model class belongs to a company (inherits CompanyOwned)."""
    return issubclass(mapped_class, CompanyOwned)


def _is_company_record(mapped_class: type) -> bool:
    """Whether a model class is the companies table itself (marked CompanyRecord)."""
    return issubclass(mapped_class, CompanyRecord)


def _table_names(mappers: Any, kind: Any) -> set[str]:
    """The table names of the given mappers whose model passes the check `kind`."""
    return {
        str(getattr(mapper.local_table, "name", "")) for mapper in mappers if kind(mapper.class_)
    }


def _company_table_names() -> set[str]:
    """Every table the filter protects: company-owned tables and the companies table."""
    mappers = Base.registry.mappers
    return _table_names(mappers, _is_company_owned) | _table_names(mappers, _is_company_record)


def _sets_column(state: ORMExecuteState, column: str) -> bool:
    """Whether an UPDATE statement assigns a value to the given column (by name)."""
    names: set[str] = set()

    # The values written with .values(...): SQLAlchemy keeps them on the statement as
    # _values (a dict) or _ordered_values (a list of pairs). It has no public way to read
    # them; the security tests fail if a SQLAlchemy update changes this.
    statement = state.statement
    values = getattr(statement, "_values", None) or {}
    ordered = getattr(statement, "_ordered_values", None) or []
    for key in [*values.keys(), *(pair[0] for pair in ordered)]:
        # A key is a column (use its name) or already a plain name.
        names.add(str(getattr(key, "key", key)))

    # The values passed separately as one dict: session.execute(statement, {...}). (A list
    # of dicts, one per row, never gets here: bulk updates by primary key are refused
    # before this check.)
    parameters = state.parameters
    if isinstance(parameters, Mapping):
        names.update(parameters.keys())

    return column in names


@event.listens_for(Session, "do_orm_execute")
def _add_company_filter(state: ORMExecuteState) -> None:
    """Called by SQLAlchemy just before every statement any session runs.

    Adds the company condition to SELECT, UPDATE, and DELETE statements on company-owned
    models, and refuses statements on company data that it cannot make safe.
    """
    # Loading one more column or a related row of an object that was already loaded
    # through a filtered query: the filter below is carried into those loads
    # automatically, so there is nothing to add.
    if state.is_column_load or state.is_relationship_load:
        state.update_execution_options(**{_CHECKED: True})
        return

    # Which company tables does the statement touch, in any form: through a model
    # (select(Shift)) or through the table itself (select(Shift.__table__)). check_columns
    # also finds tables named only through their columns; include_crud looks inside
    # INSERT, UPDATE, and DELETE. Nothing touched: nothing to do (for example a query on
    # the companies table, or select(1)).
    # (Every statement a session runs is a ClauseElement; the cast only tells the type
    # checker so.)
    statement = cast(ClauseElement, state.statement)
    company_tables = _company_table_names()
    touched = {
        str(getattr(table, "name", ""))
        for table in find_tables(statement, check_columns=True, include_crud=True)
    } & company_tables
    if not touched:
        return

    # The tables reached through a model the filter knows (company-owned, or the companies
    # table). Only those get the conditions below; a table reached any other way (its raw
    # Table object) would go unfiltered.
    owned = _table_names(state.all_mappers, _is_company_owned)
    records = _table_names(state.all_mappers, _is_company_record)
    if touched - (owned | records):
        raise UnsafeQueryError("use the model, not its table, for company data")

    # Bulk inserts go straight to the database, past the save check that fills in and
    # checks company_id, so company data is only ever added with session.add().
    if state.is_insert:
        raise UnsafeQueryError("add company data with session.add(), not a bulk insert")

    # From here on the statement involves company data, so the session must know its
    # company. Without one, refuse loudly instead of reading or changing every company's
    # rows. The one exception: a statement on the companies table alone, from a session
    # with no company, is platform code (the seed script) managing companies.
    company_id = get_company(state.session)
    if company_id is None:
        if owned:
            raise MissingCompanyError("query on company data without a company set on the session")
        state.update_execution_options(**{_CHECKED: True})
        return

    # A bulk update or delete given a list of rows by primary key runs without the
    # company condition, so it could reach another company's rows by their IDs.
    if state.is_executemany and (state.is_update or state.is_delete):
        raise UnsafeQueryError("update company data by loading rows or with a where clause")

    # Setting company_id in a bulk update would move rows into another company (the
    # condition below only limits WHICH rows change, not what they change to).
    if state.is_update and _sets_column(state, "company_id"):
        raise WrongCompanyError("company_id cannot be changed")

    # The companies table as the target of a bulk update or delete. These statements go
    # straight to the database without the save check (_check_saved_rows), so its rules for
    # companies are repeated here. bind_mapper is the model the statement changes (for
    # delete(Department).where(...Company...) that is Department, so this stays narrow).
    target = state.bind_mapper
    if target is not None and _is_company_record(target.class_):
        # Deleting companies is platform work, even the session's own company.
        if state.is_delete:
            raise UnsafeQueryError("companies are created and deleted by platform code only")
        # A company's id is the value this filter uses to tell companies apart. Changing it
        # would re-key the company, so it is refused like changing company_id above.
        if state.is_update and _sets_column(state, "id"):
            raise WrongCompanyError("a company's id cannot be changed")

    # Add "company_id = <company>" for every CompanyOwned model in the statement, wherever
    # it appears: the main table, joins, aliases (include_aliases), and later loads of
    # related rows. SQLAlchemy sends company_id as a bound parameter, never as SQL text.
    criteria = [
        with_loader_criteria(
            CompanyOwned,
            lambda cls: cls.company_id == company_id,
            include_aliases=True,
        )
    ]
    # On the companies table the company is the row itself, so the condition there is
    # "id = <company>": a session working for one company never sees another company. It
    # is added for each company model in the statement (the marker class has no id column
    # of its own to build the condition from).
    for mapper in state.all_mappers:
        if _is_company_record(mapper.class_):
            criteria.append(
                with_loader_criteria(
                    mapper.class_, lambda cls: cls.id == company_id, include_aliases=True
                )
            )
    state.statement = state.statement.options(*criteria)

    # Tell the last guard (_guard_connection) this statement passed the checks above.
    state.update_execution_options(**{_CHECKED: True})


@event.listens_for(Session, "before_flush")
def _check_saved_rows(session: Session, flush_context: Any, instances: Any) -> None:
    """Called by SQLAlchemy just before it writes pending changes to the database.

    Fills in or checks company_id on every new, changed, or deleted company-owned row,
    then lets the last guard know these writes were checked.
    """
    # session.new holds rows about to be inserted, session.dirty loaded rows with changed
    # attributes, and session.deleted rows about to be deleted. Company-owned rows and
    # rows of the companies table matter here.
    pending = (*session.new, *session.dirty, *session.deleted)
    rows = [row for row in pending if _is_company_owned(type(row))]
    companies = [row for row in pending if _is_company_record(type(row))]
    if not rows and not companies:
        return

    # Saving company data needs a company on the session, exactly as reading does.
    company_id = get_company(session)
    if company_id is None and rows:
        raise MissingCompanyError("save of company data without a company set on the session")

    # Companies themselves: with no company on the session (platform code, the seed
    # script) they may be managed freely. A session working for a company may only change
    # its own company's row; creating or deleting companies is platform work.
    if company_id is not None:
        for company in companies:
            if company in session.new or company in session.deleted:
                raise UnsafeQueryError("companies are created and deleted by platform code only")
            if company.id != company_id:
                raise WrongCompanyError("a session may only change its own company")

    for row in rows:
        # A new row with no company yet belongs to the session's company.
        if row.company_id is None:
            row.company_id = company_id
        # Any other company is refused: this blocks creating a row for another company,
        # moving an existing row to another company (its company_id was changed), and
        # deleting another company's row (one attached to this session from elsewhere).
        # Nothing is written; the whole save fails.
        elif row.company_id != company_id:
            raise WrongCompanyError("a row may only be saved for the session's own company")

    # Every row passed. Mark the session's connection as "saving checked rows" while the
    # save runs, so the last guard lets these writes through.
    session.connection().execution_options(**{_SAVING: True})


@event.listens_for(Session, "after_flush_postexec")
def _end_checked_save(session: Session, flush_context: Any) -> None:
    """Called by SQLAlchemy when a save has finished: remove the "saving" mark again.

    If a save fails instead, the session's transaction is rolled back and its connection
    handle is closed, so the mark disappears with it.
    """
    # A save always runs inside the session's transaction, so its connection is still open.
    session.connection().execution_options(**{_SAVING: False})


@event.listens_for(Engine, "before_execute")
def _guard_connection(
    connection: Connection,
    clauseelement: Any,
    multiparams: Any,
    params: Any,
    execution_options: Any,
) -> None:
    """Called by SQLAlchemy just before any statement reaches the database, from anywhere.

    The last guard: a read or write of a company table that did not pass the checks
    above is refused, whichever way it was sent.
    """
    # Only reads (SELECT) and writes (INSERT, UPDATE, DELETE) matter. Table creation in
    # migrations and tests, and raw SQL text, are not looked at here.
    if not (getattr(clauseelement, "is_select", False) or getattr(clauseelement, "is_dml", False)):
        return

    # Allowed: a statement the query hook checked, a write during a checked save, or a
    # connection marked as trusted (migrations).
    connection_options = connection.get_execution_options()
    if (
        execution_options.get(_CHECKED)
        or connection_options.get(_SAVING)
        or connection_options.get(_TRUSTED)
    ):
        return

    # Anything else that touches a company table went around the checks.
    touched = {
        str(getattr(table, "name", ""))
        for table in find_tables(clauseelement, check_columns=True, include_crud=True)
    } & _company_table_names()
    if touched:
        raise UnsafeQueryError("company data must go through the session's checked queries")
