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
    # How many days before the first day a request asked with offers goes up to the
    # managers by itself (coverage.md, the send-up minimum). More is stricter: reviewers
    # get longer. The software default is the day before.
    SettingDef(
        "offers_close_days",
        default=1,
        limit=14,
        stricter=Stricter.HIGHER,
        description="Days before time off starts that coworkers' offers close",
        per_department=True,  # a department's managers may raise it for their department
    ),
]
