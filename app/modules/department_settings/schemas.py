"""Request and response shapes for a department's own settings (docs/features/coverage.md).

The change body forbids unknown fields (Strict), so it can only carry a value: never a
department, a company, or who confirms (threat T2).
"""

import uuid

from pydantic import BaseModel, StrictInt

from app.modules.org.schemas import Strict


class SettingChange(Strict):
    """A department's new value. Checked against the setting's rules by the service."""

    value: StrictInt  # a whole number as sent, never a string turned into one


class PendingChange(BaseModel):
    """A change waiting for the department's other managers."""

    approval_request_id: uuid.UUID
    value: int
    requested_by: uuid.UUID
    waiting_for: list[str]  # the managers who have not confirmed yet, by name


class DepartmentSettingOut(BaseModel):
    setting: str  # the full name, for example "time_off.offers_close_days"
    key: str  # its name within the module, used in the PUT path
    description: str
    company_value: int  # the company's value (or the platform default)
    department_value: int | None  # the department's own, if it chose one
    value: int  # in force: the stricter of the two
    limit: int  # the furthest the platform allows
    pending: PendingChange | None


class DepartmentSettings(BaseModel):
    items: list[DepartmentSettingOut]


class SettingChanged(BaseModel):
    """The new value (200), or the approval request the other managers decide (202)."""

    value: int | None
    approval_request_id: uuid.UUID | None
