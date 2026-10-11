"""The permissions for people, the company's structure, and its settings (authorization.md)."""

from app.authz.registry import Kind, PermissionDef

PERMISSIONS = [
    PermissionDef("user.view", Kind.RECORD, "See people in scope"),
    PermissionDef(
        "user.manage", Kind.PERSON, "Create accounts, links, deactivate, unlock, sign out"
    ),
    PermissionDef("account.change_self", Kind.SELF, "Ask to change your own display name or email"),
    PermissionDef("org.manage", Kind.COMPANY, "Create, rename, and archive departments and teams"),
    PermissionDef("settings.manage", Kind.COMPANY, "Change company settings"),
    PermissionDef(
        "company.transfer_ownership", Kind.COMPANY, "Propose adding or removing an owner"
    ),
]
