"""A department's own settings over HTTP (docs/features/coverage.md, the send-up minimum).
HTTP only: the rules are in service.py.

    GET /api/departments/{id}/settings              200  the department's settings
    PUT /api/departments/{id}/settings/{key} {value} 200  changed now
                                                     202  waiting for the other managers

Errors: 401 not signed in, 403 not one of the department's managers (nor company-wide),
404 unknown department or setting (or another company's), 409 a change already waiting,
422 a value outside the platform's bounds or weaker than the company's. Every change also
needs the CSRF token. Other managers confirm through /api/approval-requests/{id}.
"""

import uuid

from fastapi import APIRouter, Response

# Registers what a department_setting approval request does.
import app.modules.department_settings.approval  # noqa: F401
from app.auth.dependencies import Database, SignedInPerson
from app.modules.department_settings import service
from app.modules.department_settings.schemas import (
    DepartmentSettingOut,
    DepartmentSettings,
    PendingChange,
    SettingChange,
    SettingChanged,
)
from app.modules.org.models import User
from app.modules.org.service import NotFound
from app.settings.registry import all_settings

router = APIRouter(prefix="/api/departments", tags=["department settings"])


def _name(key: str) -> str:
    """The full name of a per-department setting from its key ("offers_close_days")."""
    for setting in all_settings().values():
        if setting.per_department and setting.key == key:
            return setting.name
    raise NotFound()


@router.get("/{department_id}/settings")
def show(department_id: uuid.UUID, current: SignedInPerson, db: Database) -> DepartmentSettings:
    found = service.show(db, current.user, department_id)
    # Names of everyone a pending change waits for, in one lookup.
    ids = {person for item in found if item.pending for person in item.pending.waiting_for}
    names = {u.id: u.display_name for u in (db.get(User, i) for i in ids) if u is not None}
    return DepartmentSettings(
        items=[
            DepartmentSettingOut(
                setting=item.setting.name,
                key=item.setting.key,
                description=item.setting.description,
                company_value=item.company_value,
                department_value=item.department_value,
                value=item.value,
                limit=item.setting.limit,
                pending=PendingChange(
                    approval_request_id=item.pending.approval.id,
                    value=item.pending.value,
                    requested_by=item.pending.approval.requested_by,
                    waiting_for=[names.get(i, "Unknown") for i in item.pending.waiting_for],
                )
                if item.pending
                else None,
            )
            for item in found
        ]
    )


@router.put("/{department_id}/settings/{key}")
def change(
    department_id: uuid.UUID,
    key: str,
    body: SettingChange,
    current: SignedInPerson,
    db: Database,
    response: Response,
) -> SettingChanged:
    changed = service.change(db, current.user, department_id, _name(key), body.value)
    if changed.pending is not None:
        response.status_code = 202  # the other managers must confirm first
        return SettingChanged(value=None, approval_request_id=changed.pending.id)
    return SettingChanged(value=changed.value, approval_request_id=None)
