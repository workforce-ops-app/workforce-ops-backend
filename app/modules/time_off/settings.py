"""The time-off settings (docs/features/time-off.md, required approvals).

The settings registry (app/settings/registry.py) finds this list by its name, SETTINGS.
"""

from app.settings.registry import SettingDef, Stricter

SETTINGS = [
    # How many direct managers must approve a request. More is stricter; 0 would let
    # requests through unreviewed, so a company can never go below the default of 1.
    SettingDef(
        "required_approvals",
        default=1,
        limit=5,
        stricter=Stricter.HIGHER,
        description="How many direct managers must approve a time-off request",
    ),
]
