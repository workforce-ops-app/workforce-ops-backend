"""The company_settings and department_settings tables (data-model.md, company_settings;
docs/features/coverage.md for department_settings).

One row per setting a company has changed; a missing row means the platform default
(app/settings/registry.py). Company-owned like every other company table, so the company
filter protects it (tenancy layers 1 to 3): a company only ever reads and writes its own
rows. Only app/settings/service.py reads and writes it, always through the registry.
"""

import uuid
from typing import Any

from sqlalchemy import JSON, ForeignKeyConstraint, PrimaryKeyConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned


class CompanySetting(Timestamps, CompanyOwned, Base):
    """A company's chosen value for one setting."""

    __tablename__ = "company_settings"
    __table_args__ = (
        # Together the key: each company holds at most one value per setting. company_id
        # leads, so a company's settings sit together and are read with one index.
        PrimaryKeyConstraint("company_id", "module", "setting_key"),
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
    )

    # The module that declares the setting, and the setting's name within it, for
    # example "auth" and "password_min_length".
    module: Mapped[str] = mapped_column(String(50))
    setting_key: Mapped[str] = mapped_column(String(80))
    # The value, checked against the setting's declaration on every write and read.
    value: Mapped[Any] = mapped_column(JSON, nullable=False)


class DepartmentSetting(Timestamps, CompanyOwned, Base):
    """A department's own, stricter value for a setting declared per_department.

    Company-owned with a company-aware key to the department (tenancy layer 2), so a row
    can never belong to another company's department. A value is only ever stricter than
    the company's when written (app/modules/department_settings/service.py), and read as
    the stricter of the two anyway (app/settings/service.py, department_value), so a
    company that later raises its own value is never undercut.
    """

    __tablename__ = "department_settings"
    __table_args__ = (
        # One value per department and setting; company_id and department_id lead, so the
        # key also serves the department's company-aware key below.
        PrimaryKeyConstraint("company_id", "department_id", "module", "setting_key"),
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
    )

    department_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    module: Mapped[str] = mapped_column(String(50))
    setting_key: Mapped[str] = mapped_column(String(80))
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
