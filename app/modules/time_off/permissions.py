"""The time-off permissions (authorization.md, core permissions)."""

from app.authz.registry import Kind, PermissionDef

PERMISSIONS = [
    PermissionDef("time_off.request", Kind.SELF, "Ask for time off for yourself"),
    PermissionDef("time_off.cancel_self", Kind.SELF, "Cancel your own time-off request"),
    PermissionDef("time_off.view", Kind.RECORD, "See time-off requests of people in scope"),
    PermissionDef(
        "time_off.review", Kind.PERSON, "Approve or deny the requests of people you are above"
    ),
]
