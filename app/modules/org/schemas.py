"""Public response shapes for organization endpoints."""

import uuid

from pydantic import BaseModel


class DepartmentOut(BaseModel):
    """The department fields available to any signed-in person."""

    id: uuid.UUID
    name: str


class DepartmentPage(BaseModel):
    """A page of departments; next_cursor is null after the last page."""

    items: list[DepartmentOut]
    next_cursor: str | None
