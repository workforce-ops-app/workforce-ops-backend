"""Tests for the department-list endpoint."""

import datetime as dt

from app.modules.org.models import Department
from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]


def test_list_departments_requires_sign_in(signin: SignInSetup) -> None:
    response = signin.client.get("/api/departments")

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


def test_list_departments_returns_only_active_departments_sorted_by_name(
    signin: SignInSetup,
) -> None:
    with signin.session_for(signin.company_a) as db:
        db.add_all(
            [
                Department(company_id=signin.company_a, name="Office"),
                Department(company_id=signin.company_a, name="Front of House"),
                Department(
                    company_id=signin.company_a,
                    name="Archived Department",
                    archived_at=dt.datetime.now(dt.UTC),
                ),
            ]
        )
        db.commit()

    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get("/api/departments")

    assert response.status_code == 200
    assert [department["name"] for department in response.json()] == [
        "Front of House",
        "Kitchen",
        "Office",
    ]
    assert all(set(department) == {"id", "name"} for department in response.json())
