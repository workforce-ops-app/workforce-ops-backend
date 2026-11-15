"""The security module's permission (authorization.md, detection.md "Who can use it").

security.view is a company permission: it needs a company-wide role assignment, so a
manager of one department or team can never hold it there. The Owner and Administrator
starting roles grant it (the Administrator role grants every permission except the
owner-only ones, app/authz/roles.py); Manager and Employee do not, so they never see
security events, including their own.
"""

from app.authz.registry import Kind, PermissionDef

PERMISSIONS = [
    PermissionDef("security.view", Kind.COMPANY, "See the company's security events"),
]
