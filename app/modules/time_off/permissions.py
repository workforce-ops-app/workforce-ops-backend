"""The time-off permissions (authorization.md, core permissions)."""

from app.authz.registry import Kind, PermissionDef

PERMISSIONS = [
    PermissionDef("time_off.request_self", Kind.SELF, "Ask for time off for yourself"),
    PermissionDef("time_off.cancel_self", Kind.SELF, "Cancel your own time-off request"),
    PermissionDef("time_off.view", Kind.RECORD, "See time-off requests of people in scope"),
    PermissionDef(
        "time_off.review", Kind.PERSON, "Approve or deny the requests of people you are above"
    ),
    # Shift swaps and coverage (coverage.md): answering a coworker's time-off request asked
    # with offers. Asking is time_off.request_self; choosing offers is time_off.review.
    PermissionDef(
        "coverage.respond_self",
        Kind.SELF,
        "Offer to cover or swap a coworker's shift during their time off",
    ),
]
