"""The settings registry: every company setting the application knows (data-model.md,
company_settings; decision 0025; rule AZ10).

Each feature module declares its settings in app/modules/<feature>/settings.py, as a list
named SETTINGS; the shared layers (auth) declare theirs here, as the permission registry
does (app/authz/registry.py). The code is the source of truth: a company's row can only
hold a value for a setting declared here, and only a value its declaration allows.

Every setting has a platform DEFAULT, a platform LIMIT, and a STRICTER direction (a longer
minimum password is stricter, so it goes higher). A company may only choose values between
the default and the limit: it can make a rule stricter, up to the limit, but never weaker
than the platform's default (AZ10, threat E7). For example the minimum password length is
15 by default, and a company may choose anything from 15 to 64.

Settings are whole numbers for now; other types are added when a setting needs one.
"""

import importlib
import pkgutil
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from functools import lru_cache

from app import modules
from app.auth.passwords import MAX_MIN_LENGTH, MIN_LENGTH


class SettingRejected(ValueError):
    """A value a setting does not allow; the message explains why in plain words."""


class Stricter(StrEnum):
    """Which way makes a setting stricter."""

    HIGHER = "higher"  # for example a longer minimum password length
    LOWER = "lower"  # for example a shorter idle sign-out (a later setting)


@dataclass(frozen=True)
class SettingDef:
    """One setting as a module declares it. `module` is filled in by the registry."""

    key: str  # the name within the module, for example "password_min_length"
    default: int  # the platform default, used when the company has no row
    limit: int  # the furthest a company may go in the stricter direction
    stricter: Stricter
    description: str
    module: str = ""

    @property
    def name(self) -> str:
        """The full name, for example "auth.password_min_length"."""
        return f"{self.module}.{self.key}"

    def bounds(self) -> tuple[int, int]:
        """The lowest and highest values a company may choose (both included)."""
        return min(self.default, self.limit), max(self.default, self.limit)

    def check(self, value: object) -> int:
        """Return the value if this setting allows it; raise SettingRejected if not.

        Used both when a value is chosen and when a stored value is read, so a row written
        around the application (straight into the database) is never trusted blindly.
        """
        # The declared type, exactly: True counts as an int in Python, but is no count.
        if type(value) is not int:
            raise SettingRejected(f"{self.name} must be a whole number.")
        low, high = self.bounds()
        if low <= value <= high:
            return value
        # Outside the range: say which side, in the words of AZ10.
        weaker = value < low if self.stricter is Stricter.HIGHER else value > high
        if weaker:
            raise SettingRejected(
                f"{self.name} can only be made stricter than the platform's {self.default}."
            )
        raise SettingRejected(f"{self.name} cannot go past the platform's limit of {self.limit}.")


# Module and key names: lowercase letters and underscores, as in permission codes.
_NAME = re.compile(r"^[a-z_]+$")

# The shared layers' own settings (feature modules declare theirs in settings.py).
_SHARED = {
    "auth": [
        SettingDef(
            "password_min_length",
            default=MIN_LENGTH,
            limit=MAX_MIN_LENGTH,
            stricter=Stricter.HIGHER,
            description="The fewest characters a new password may have",
        ),
    ],
}


def _declared() -> list[SettingDef]:
    """Every declaration: the shared layers', then each module's settings.py."""
    found = [replace(s, module=module) for module, settings in _SHARED.items() for s in settings]
    for info in pkgutil.iter_modules(modules.__path__):
        if not info.ispkg:
            continue
        name = f"app.modules.{info.name}.settings"
        try:
            declared = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            # No settings.py: this module declares none. Any other missing import is a
            # real error and stops here (as permission discovery does).
            if exc.name == name:
                continue
            raise
        found += [replace(s, module=info.name) for s in getattr(declared, "SETTINGS", [])]
    return found


def check_declaration(setting: SettingDef) -> None:
    """Raise ValueError if a declaration breaks the registry's rules."""
    # The names fit the table's columns (module VARCHAR(50), setting_key VARCHAR(80)).
    if not _NAME.match(setting.module) or len(setting.module) > 50:
        raise ValueError(f"setting module {setting.module!r} must be lowercase, up to 50")
    if not _NAME.match(setting.key) or len(setting.key) > 80:
        raise ValueError(f"setting {setting.name!r} must be lowercase, up to 80 characters")
    if type(setting.default) is not int or type(setting.limit) is not int:
        raise ValueError(f"setting {setting.name!r}: only whole-number settings so far")
    # The limit must lie on the stricter side of the default, or "stricter only" would
    # let a company go weaker than the platform.
    if setting.stricter is Stricter.HIGHER and setting.limit < setting.default:
        raise ValueError(f"setting {setting.name!r}: its limit is below its default")
    if setting.stricter is Stricter.LOWER and setting.limit > setting.default:
        raise ValueError(f"setting {setting.name!r}: its limit is above its default")


@lru_cache
def all_settings() -> dict[str, SettingDef]:
    """Every setting by full name, checked against the rules (read once)."""
    registry: dict[str, SettingDef] = {}
    for setting in _declared():
        check_declaration(setting)
        if setting.name in registry:
            raise ValueError(f"setting {setting.name!r} is declared twice")
        registry[setting.name] = setting
    return registry


def get_setting_def(name: str) -> SettingDef:
    """One setting by full name. An unknown name is a bug in the caller, so it raises."""
    try:
        return all_settings()[name]
    except KeyError:
        raise LookupError(f"unknown setting {name!r}") from None
