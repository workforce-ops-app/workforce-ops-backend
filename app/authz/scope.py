"""Where a record or person belongs, and the database condition for lists (authorization.md).

authorize() does not know what a shift or a request is. Each module registers a SCOPE
RESOLVER for its records, which answers: which departments, which teams, and which
employee does this record belong to? authorize() then compares that with the scopes of
the user's role assignments:

    assignment scope   covers
    company            everything in the company
    department         records in the department, and the people whose home department it is
                       (and their records)
    team               the team's members and their records
    employee           that one person and their records

For lists, checking row by row would be slow and easy to forget, so scope_condition()
turns the same rules into one database condition the query adds: rows outside the user's
scopes are never loaded.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, false, or_, select, true
from sqlalchemy.orm import Session

from app.modules.org.models import TeamMember, User


@dataclass(frozen=True)
class Scope:
    """Where one record or person belongs."""

    # The departments it belongs to (a shift's department; a person's home department; for
    # a person's record, also that person's home department).
    department_ids: frozenset[uuid.UUID]
    # The teams whose members it belongs to.
    team_ids: frozenset[uuid.UUID]
    # The person it belongs to (none for, say, an open shift).
    employee_id: uuid.UUID | None


# One resolver per kind of record: a function from (database session, record) to its Scope.
Resolver = Callable[[Session, Any], Scope]
_resolvers: dict[type, Resolver] = {}


def scope_resolver(model: type) -> Callable[[Resolver], Resolver]:
    """Register the resolver for a kind of record:

    @scope_resolver(Shift)
    def shift_scope(db, shift): return Scope(...)
    """

    def register(resolver: Resolver) -> Resolver:
        _resolvers[model] = resolver
        return resolver

    return register


def resolve(db: Session, target: object) -> Scope:
    """The Scope of a record, from its module's resolver. No resolver is a bug: it raises."""
    resolver = _resolvers.get(type(target))
    if resolver is None:
        raise LookupError(f"no scope resolver for {type(target).__name__}")
    return resolver(db, target)


@scope_resolver(User)
def person_scope(db: Session, person: User) -> Scope:
    """A person belongs to their home department, the teams they are on, and themselves."""
    teams = db.scalars(select(TeamMember.team_id).where(TeamMember.user_id == person.id))
    return Scope(frozenset({person.department_id}), frozenset(teams), person.id)


@dataclass(frozen=True)
class Grant:
    """One role assignment that grants the permission being checked: where it applies."""

    scope_type: str
    department_id: uuid.UUID | None
    team_id: uuid.UUID | None
    employee_id: uuid.UUID | None


def covers(grant: Grant, scope: Scope) -> bool:
    """Whether one assignment's scope covers a record or person."""
    if grant.scope_type == "company":
        return True
    if grant.scope_type == "department":
        return grant.department_id in scope.department_ids
    if grant.scope_type == "team":
        return grant.team_id in scope.team_ids
    if grant.scope_type == "employee":
        return grant.employee_id is not None and grant.employee_id == scope.employee_id
    return False  # an unknown scope type grants nothing


@dataclass(frozen=True)
class ScopeColumns:
    """The columns of a listed table that say where each row belongs.

    For people: ScopeColumns(department=User.department_id, employee=User.id).
    For shifts: ScopeColumns(department=Shift.department_id, employee=Shift.employee_id).
    """

    department: Any = None
    employee: Any = None


def condition_for(db: Session, grant: Grant, columns: ScopeColumns) -> ColumnElement[bool]:
    """The rows one assignment covers, as a database condition (the same rules as covers()).

    A team's members and a department's people are looked up first, each in its own query
    in the company's session (so the company filter applies to them), and the condition
    then names their IDs. (A subquery inside the condition would hide those tables from the
    company filter, which refuses such queries.)
    """
    if grant.scope_type == "company":
        return true()
    if grant.scope_type == "department" and grant.department_id is not None:
        parts: list[ColumnElement[bool]] = []
        if columns.department is not None:
            parts.append(columns.department == grant.department_id)
        if columns.employee is not None:
            # Rows of people whose home department it is.
            home = db.scalars(select(User.id).where(User.department_id == grant.department_id))
            parts.append(columns.employee.in_(list(home)))
        return or_(false(), *parts)
    if grant.scope_type == "team" and grant.team_id is not None and columns.employee is not None:
        members = db.scalars(select(TeamMember.user_id).where(TeamMember.team_id == grant.team_id))
        return columns.employee.in_(list(members))
    if (
        grant.scope_type == "employee"
        and grant.employee_id is not None
        and columns.employee is not None
    ):
        return columns.employee == grant.employee_id
    return false()
