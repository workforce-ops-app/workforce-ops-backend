"""The announcement permission (authorization.md, core permissions).

announcement.create is a record permission: an assignment's scope must cover the
announcement's audience (app/modules/announcements/scope.py). Reading needs no permission;
it depends only on being in the audience (service.py, reading).
"""

from app.authz.registry import Kind, PermissionDef

PERMISSIONS = [
    PermissionDef(
        "announcement.create",
        Kind.RECORD,
        "Post, edit, and archive announcements for an audience in scope; see who read them",
    ),
]
