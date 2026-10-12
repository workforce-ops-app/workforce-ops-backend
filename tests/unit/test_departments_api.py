"""Tests for the department-list endpoint."""

import datetime as dt
import uuid

from app.modules.org import repository
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
        office = Department(company_id=signin.company_a, name="Office")
        front = Department(company_id=signin.company_a, name="Front of House")
        archived = Department(
            company_id=signin.company_a,
            name="Archived Department",
            archived_at=dt.datetime.now(dt.UTC),
        )
        db.add_all(
            [
                office,
                front,
                archived,
            ]
        )
        db.commit()
        expected_added_ids = {str(office.id), str(front.id)}
        archived_id = str(archived.id)

    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get("/api/departments")

    assert response.status_code == 200
    page = response.json()
    assert set(page) == {"items", "next_cursor"}
    assert page["next_cursor"] is None
    assert [department["name"] for department in page["items"]] == [
        "Front of House",
        "Kitchen",
        "Office",
    ]
    returned_ids = {department["id"] for department in page["items"]}
    assert expected_added_ids <= returned_ids
    assert archived_id not in returned_ids
    assert all(set(department) == {"id", "name"} for department in page["items"])


def test_list_departments_follows_the_cursor_to_the_next_page(signin: SignInSetup) -> None:
    with signin.session_for(signin.company_a) as db:
        db.add_all(
            [
                Department(company_id=signin.company_a, name="Office"),
                Department(company_id=signin.company_a, name="Front of House"),
            ]
        )
        db.commit()

    signin.sign_in(signin.client, email(signin, "a_ana"))

    first = signin.client.get("/api/departments", params={"limit": 2}).json()
    second = signin.client.get(
        "/api/departments", params={"limit": 2, "cursor": first["next_cursor"]}
    ).json()

    assert [item["name"] for item in first["items"]] == ["Front of House", "Kitchen"]
    assert first["next_cursor"] is not None
    assert [item["name"] for item in second["items"]] == ["Office"]
    assert second["next_cursor"] is None


def test_list_departments_pages_after_a_long_accented_name(signin: SignInSetup) -> None:
    boundary_name = "M" + "é" * 119
    with signin.session_for(signin.company_a) as db:
        db.add_all(
            [
                Department(company_id=signin.company_a, name="A department"),
                Department(company_id=signin.company_a, name=boundary_name),
                Department(company_id=signin.company_a, name="Z department"),
            ]
        )
        db.commit()

    signin.sign_in(signin.client, email(signin, "a_ana"))

    first = signin.client.get("/api/departments", params={"limit": 3}).json()
    second = signin.client.get(
        "/api/departments", params={"limit": 3, "cursor": first["next_cursor"]}
    ).json()

    assert [item["name"] for item in first["items"]] == [
        "A department",
        "Kitchen",
        boundary_name,
    ]
    assert len(first["next_cursor"]) <= 200
    assert [item["name"] for item in second["items"]] == ["Z department"]


def test_list_departments_rejects_an_invalid_cursor(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get("/api/departments", params={"cursor": "not-a-cursor"})

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_list_departments_rejects_an_unknown_cursor_id(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get(
        "/api/departments", params={"cursor": repository.encode_cursor(uuid.uuid4())}
    )

    assert response.status_code == 422
