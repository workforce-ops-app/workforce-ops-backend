"""Tenant-isolation checks for department listing."""

from sqlalchemy import select

from app.modules.org import repository
from app.modules.org.models import Department
from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]


def test_list_departments_never_returns_another_companys_departments(
    signin: SignInSetup,
) -> None:
    with signin.session_for(signin.company_a) as db:
        db.add(Department(company_id=signin.company_a, name="Company A Office"))
        db.commit()
        company_a_ids = {str(item) for item in db.scalars(select(Department.id))}
    with signin.session_for(signin.company_b) as db:
        db.add(Department(company_id=signin.company_b, name="Company B Warehouse"))
        db.commit()
        company_b_ids = {str(item) for item in db.scalars(select(Department.id))}

    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get("/api/departments")

    assert response.status_code == 200
    returned_ids = {department["id"] for department in response.json()["items"]}
    assert returned_ids == company_a_ids
    assert returned_ids.isdisjoint(company_b_ids)


def test_list_departments_rejects_another_companys_cursor(signin: SignInSetup) -> None:
    with signin.session_for(signin.company_b) as db:
        other_department_id = db.scalar(select(Department.id))
        assert other_department_id is not None

    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get(
        "/api/departments",
        params={"cursor": repository.encode_cursor(other_department_id)},
    )

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
