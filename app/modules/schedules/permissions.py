"""The schedule permissions (authorization.md, core permissions)."""

from app.authz.registry import Kind, PermissionDef

PERMISSIONS = [
    PermissionDef("schedule.view_self", Kind.SELF, "See your own shifts"),
    PermissionDef("schedule.view", Kind.RECORD, "See shifts in scope, including open shifts"),
    PermissionDef("schedule.edit", Kind.RECORD, "Create, change, and cancel shifts in scope"),
]
