"""Tenant-isolation checks for department listing."""

from app.modules.org.models import Department
from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]


def test_list_departments_never_returns_another_companys_departments(
    signin: SignInSetup,
) -> None:
    with signin.session_for(signin.company_a) as db:
        db.add(Department(company_id=signin.company_a, name="Company A Office"))
        db.commit()
    with signin.session_for(signin.company_b) as db:
        db.add(Department(company_id=signin.company_b, name="Company B Warehouse"))
        db.commit()

    signin.sign_in(signin.client, email(signin, "a_ana"))

    response = signin.client.get("/api/departments")

    assert response.status_code == 200
    names = {department["name"] for department in response.json()}
    assert "Company A Office" in names
    assert "Company B Warehouse" not in names
