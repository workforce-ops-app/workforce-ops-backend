"""Every company-owned table follows the company-aware key convention (data-model.md).

Tenancy layer 2 only works if every table keeps it, so this checks all models at once,
including the ones later features add:
- a company-owned table has a unique key on (company_id, id), so others can link to it;
- every link to a company-owned table goes through (company_id, <x>_id), so the database
  refuses a link into another company;
- every company-owned table links company_id to companies.
"""

import pytest
from sqlalchemy import ForeignKeyConstraint, Table, UniqueConstraint

from app.db.base import Base
from app.db.registry import import_all_models
from app.tenancy.filter import CompanyOwned

# Load every feature's models, as Alembic does.
import_all_models()


def company_owned_tables() -> list[Table]:
    """The tables of all company-owned models, except test-only ones."""
    return [
        mapper.local_table
        for mapper in Base.registry.mappers
        if issubclass(mapper.class_, CompanyOwned)
        and isinstance(mapper.local_table, Table)
        and not mapper.local_table.name.endswith("_test_only")
    ]


COMPANY_OWNED = {table.name for table in company_owned_tables()}


def test_the_org_tables_are_company_owned() -> None:
    # Companies itself is the one org table that is not.
    assert {"departments", "teams", "users", "team_members"} <= COMPANY_OWNED
    assert "companies" not in COMPANY_OWNED


@pytest.mark.parametrize("table", company_owned_tables(), ids=lambda table: table.name)
def test_company_owned_table_follows_the_key_convention(table: Table) -> None:
    unique_keys = {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    foreign_keys = [c for c in table.constraints if isinstance(c, ForeignKeyConstraint)]

    # Others can link to a row through (company_id, id) (team_members, keyed by its two
    # links, is never linked to).
    if "id" in table.columns:
        assert ("company_id", "id") in unique_keys

    # company_id itself points at companies.
    assert any(
        [column.name for column in fk.columns] == ["company_id"]
        and fk.referred_table.name == "companies"
        for fk in foreign_keys
    )

    # Every link to another company-owned table includes company_id on both sides.
    for fk in foreign_keys:
        if fk.referred_table.name in COMPANY_OWNED:
            assert [column.name for column in fk.columns][0] == "company_id"
            assert [element.column.name for element in fk.elements][0] == "company_id"
