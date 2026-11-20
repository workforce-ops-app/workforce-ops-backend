"""Request and response shapes for owner changes."""

import uuid

from pydantic import BaseModel

from app.modules.org.schemas import Strict


class OwnerAdd(Strict):
    user_id: uuid.UUID


class OwnerOut(BaseModel):
    id: uuid.UUID
    display_name: str


class OwnerList(BaseModel):
    items: list[OwnerOut]
