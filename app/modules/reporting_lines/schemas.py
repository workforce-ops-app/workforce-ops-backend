"""Request and response shapes for reporting lines (data-model.md, reporting_lines)."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.modules.org.schemas import Strict


class LineCreate(Strict):
    """The employee will report to the manager."""

    manager_id: uuid.UUID
    employee_id: uuid.UUID


class LineOut(BaseModel):
    id: uuid.UUID
    manager_id: uuid.UUID
    employee_id: uuid.UUID
    created_at: datetime
    ended_at: datetime | None  # null while the line is current


class LineList(BaseModel):
    items: list[LineOut]
