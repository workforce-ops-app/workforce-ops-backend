"""Reading and changing a company's settings (data-model.md, company_settings; rule AZ10).

    setting_value(db, "time_off.required_approvals")   # the company's value, or the default
    change_setting(db, "auth.password_min_length", 20, actor=actor)

Both work only in a session for one company (set_company), so a company's settings are
only ever its own. Every value goes through the setting's declaration (registry.py) on the
way in AND on the way out: a value that would make a rule weaker than the platform's is
refused when chosen, and ignored (the default is used) if it is ever found in the table.

Changing settings through the API is next tier. When that endpoint arrives it must check
`settings.manage` and the password re-entry (decision 0025) before calling change_setting;
this module only keeps the values within the rules and records each change.
"""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.settings.models import CompanySetting
from app.settings.registry import SettingDef, SettingRejected, get_setting_def
from app.tenancy.context import get_company

logger = logging.getLogger(__name__)

# The settings other code reads by name.
PASSWORD_MIN_LENGTH = "auth.password_min_length"  # noqa: S105  (a setting's name, not a password)
TIME_OFF_REQUIRED_APPROVALS = "time_off.required_approvals"


def _company(db: Session) -> uuid.UUID:
    """The session's company. Platform code has none, and there the company filter is
    off, so reading "the" setting would mean reading some company's: refused instead."""
    company_id = get_company(db)
    if company_id is None:
        raise RuntimeError("company settings are read in a session for one company")
    return company_id


def _row(db: Session, setting: SettingDef, *, lock: bool = False) -> CompanySetting | None:
    """The company's row for one setting, if it has one. The company filter already limits
    the query to the session's company; the explicit company_id says so in the query too."""
    query = select(CompanySetting).where(
        CompanySetting.company_id == _company(db),
        CompanySetting.module == setting.module,
        CompanySetting.setting_key == setting.key,
    )
    if lock:
        # Two changes of the same setting take turns, so each records the true old value.
        query = query.with_for_update()
    return db.scalars(query).one_or_none()


def setting_value(db: Session, name: str) -> int:
    """The company's value for a setting: its own choice, or the platform default."""
    setting = get_setting_def(name)
    row = _row(db, setting)
    return setting.default if row is None else _checked_or_default(setting, row.value)


def change_setting(db: Session, name: str, value: object, *, actor: Actor) -> int:
    """Set the company's value for a setting, within the rules, and audit the change.

    Raises SettingRejected, before anything changes, if the value would make the rule
    weaker than the platform's default or go past the platform's limit (AZ10). Does not
    commit: the caller commits the change and its audit entry together.
    """
    setting = get_setting_def(name)
    new = setting.check(value)
    row = _row(db, setting, lock=True)
    # The value in force before, as setting_value() would have read it.
    old = setting.default if row is None else _checked_or_default(setting, row.value)
    if row is None:
        db.add(CompanySetting(module=setting.module, setting_key=setting.key, value=new))
    else:
        row.value = new
    db.flush()
    record(
        db,
        actor=actor,
        action="settings.changed",
        details={"setting": setting.name, "old": old, "new": new},
    )
    return new


def _checked_or_default(setting: SettingDef, stored: object) -> int:
    """A stored value if the rules allow it, otherwise the default."""
    try:
        return setting.check(stored)
    except SettingRejected:
        # A value the rules do not allow can only have been written around the application
        # (straight into the database). Never let it weaken the rule: use the default, and
        # say so in the application log so it gets noticed (without the value itself).
        logger.warning("ignoring a stored value the rules refuse for setting %s", setting.name)
        return setting.default


def password_min_length(db: Session) -> int:
    """The company's minimum password length, for check_password(min_length=...)."""
    return setting_value(db, PASSWORD_MIN_LENGTH)
