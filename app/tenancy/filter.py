"""The automatic company filter: layer 1 of the four tenancy layers (tenancy.md).

Every model that belongs to a company inherits CompanyOwned. From then on, for any
session (app/db/session.py, background jobs, tests):

- Reading: every SELECT, single-record lookup (session.get), count, UPDATE, and DELETE
  on a company-owned model gets "AND company_id = <the session's company>" added. Rows
  of other companies are never loaded, so they look exactly like rows that do not exist
  (the API then answers 404, layer 4).
- Saving: a new row gets the session's company filled in; a row for another company, or
  a change that moves a row to another company, is refused before anything is written.
- No company set: any query or save on a company-owned model raises an error instead of
  silently returning everything.

Feature code never filters by company itself and never turns this off. Queries written
as raw SQL text (session.execute(text(...))) are not ORM queries and are NOT filtered,
which is one reason repositories must use SQLAlchemy's query building only (decision
0022). Models without CompanyOwned (for example companies itself) are not filtered.
"""

import uuid
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Mapped, ORMExecuteState, Session, mapped_column, with_loader_criteria

from app.db.types import UUIDBinary
from app.tenancy.context import get_company


class MissingCompanyError(RuntimeError):
    """A company-owned model was queried or saved in a session with no company set."""


class WrongCompanyError(RuntimeError):
    """A save would put a row into, or move a row to, a company other than the session's."""


class CompanyOwned:
    """The company_id column, and the marker that turns the company filter on.

    Use it together with the other bases:  class Shift(IdAndTimestamps, CompanyOwned, Base)
    """

    # Which company the row belongs to: required, and indexed because every query on the
    # table filters by it. Composite keys that include it are added per table (layer 2).
    company_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, nullable=False, index=True)


def _is_company_owned(mapped_class: type) -> bool:
    """Whether a model class belongs to a company (inherits CompanyOwned)."""
    return issubclass(mapped_class, CompanyOwned)


@event.listens_for(Session, "do_orm_execute")
def _add_company_filter(state: ORMExecuteState) -> None:
    """Called by SQLAlchemy just before every ORM query any session runs.

    Adds the company condition to SELECT, UPDATE, and DELETE statements that involve a
    company-owned model.
    """
    # Inserts are checked at save time (_check_saved_rows below), so only reads,
    # updates, and deletes are handled here.
    if not (state.is_select or state.is_update or state.is_delete):
        return

    # Loading one more column or a related row of an object that was already loaded
    # through a filtered query: the filter below is carried into those loads
    # automatically, so there is nothing to add.
    if state.is_column_load or state.is_relationship_load:
        return

    # Which models does this statement read or change? If none of them belongs to a
    # company (for example a query on the companies table), there is nothing to filter.
    if not any(_is_company_owned(mapper.class_) for mapper in state.all_mappers):
        return

    # The statement involves company data, so the session must know its company. Without
    # one, refuse loudly instead of returning every company's rows.
    company_id = get_company(state.session)
    if company_id is None:
        raise MissingCompanyError("query on company data without a company set on the session")

    # Add "company_id = <company>" for every CompanyOwned model in the statement, wherever
    # it appears: the main table, joins, aliases (include_aliases), and later loads of
    # related rows. SQLAlchemy sends company_id as a bound parameter, never as SQL text.
    state.statement = state.statement.options(
        with_loader_criteria(
            CompanyOwned,
            lambda cls: cls.company_id == company_id,
            include_aliases=True,
        )
    )


@event.listens_for(Session, "before_flush")
def _check_saved_rows(session: Session, flush_context: Any, instances: Any) -> None:
    """Called by SQLAlchemy just before it writes pending changes to the database.

    Fills in or checks company_id on every new or changed company-owned row.
    """
    # session.new holds rows about to be inserted; session.dirty holds loaded rows with
    # changed attributes. Only company-owned ones matter here.
    rows = [row for row in (*session.new, *session.dirty) if _is_company_owned(type(row))]
    if not rows:
        return

    # Saving company data needs a company on the session, exactly as reading does.
    company_id = get_company(session)
    if company_id is None:
        raise MissingCompanyError("save of company data without a company set on the session")

    for row in rows:
        # A new row with no company yet belongs to the session's company.
        if row.company_id is None:
            row.company_id = company_id
        # Any other company is refused: this blocks creating a row for another company
        # and moving an existing row to another company (its company_id was changed).
        # Nothing is written; the whole save fails.
        elif row.company_id != company_id:
            raise WrongCompanyError("a row may only be saved for the session's own company")
