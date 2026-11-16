"""The company_settings table (data-model.md, company_settings).

One row per setting a company has changed; a missing row means the platform default
(app/settings/registry.py). Company-owned like every other company table, so the company
filter protects it (tenancy layers 1 to 3): a company only ever reads and writes its own
rows. Only app/settings/service.py reads and writes it, always through the registry.
"""

from typing import Any

from sqlalchemy import JSON, ForeignKeyConstraint, PrimaryKeyConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps
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
