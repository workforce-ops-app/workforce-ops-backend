"""Threat T6: numbers past what the database or the browser can hold (#105).

Python's integers never overflow, but MySQL's columns do (INT stops at 2,147,483,647,
SMALLINT at 32,767) and JavaScript rounds every number past 2^53. So every number a
request carries, in its path, query, or body, has a minimum and a maximum that fit the
column it ends up in, and a value past them is refused with 422 before any code uses it.

The tests read the API's own OpenAPI document, so a numeric field added later is checked
without anyone listing it here:

1. Every numeric input declares both limits, inside a MySQL INT (and so below 2^53).
2. Signed in, each input is sent its maximum and minimum (accepted: no error about that
   field), one past each limit, 10^30 and -10^30, and 1e309 (a float JSON reads as
   infinity): each refused with 422 naming that field, never a 500.

Validation runs before any permission check, so one ordinary account reaches every check.
"""

import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from app.db.base import Base
from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here

INT_MIN, INT_MAX = -(2**31), 2**31 - 1  # a MySQL INT, the widest integer column a request fills
METHODS = ("get", "post", "put", "patch", "delete")


@dataclass(frozen=True)
class NumericInput:
    """One number a request can carry: where it goes, and its declared limits."""

    method: str
    path: str
    where: str  # "query", "path", or "body"
    name: str
    minimum: int | float | None
    maximum: int | float | None
    body_base: dict  # for a body field: the other fields needed to pick its schema

    def __str__(self) -> str:
        return f"{self.method.upper()} {self.path} {self.where}.{self.name}"


def _openapi() -> dict:
    """The API's OpenAPI document, as the development settings serve it."""
    from app.core.config import Settings
    from app.main import create_app
    from tests.conftest import TEST_CSRF_KEY

    settings = Settings(
        app_env="test",
        database_url="mysql+pymysql://test:test@localhost:3307/test",
        csrf_key=TEST_CSRF_KEY,  # type: ignore[arg-type]
    )
    return create_app(settings).openapi()


def _limits(schema: dict) -> tuple[int | float | None, int | float | None]:
    """A numeric schema's lowest and highest allowed values (exclusive limits moved in)."""
    low = schema.get("minimum", schema.get("exclusiveMinimum"))
    high = schema.get("maximum", schema.get("exclusiveMaximum"))
    if "exclusiveMinimum" in schema and low is not None:
        low += 1
    if "exclusiveMaximum" in schema and high is not None:
        high -= 1
    # An integer field's limits are whole numbers even when the document writes them as
    # 1000.0, and a strict integer field rightly refuses the float 1000.0.
    if schema.get("type") == "integer":
        low = int(low) if low is not None else None
        high = int(high) if high is not None else None
    return low, high


def _numeric(schema: dict, components: dict) -> list[dict]:
    """The numeric schemas inside one field's schema (through refs, unions, and lists)."""
    if "$ref" in schema:
        schema = components[schema["$ref"].rsplit("/", 1)[1]]
    found = [schema] if schema.get("type") in ("integer", "number") else []
    for key in ("anyOf", "oneOf", "allOf"):
        for part in schema.get(key, []):
            found += _numeric(part, components)
    if schema.get("type") == "array":
        found += _numeric(schema.get("items", {}), components)
    return found


def _body_variants(schema: dict, components: dict) -> Iterator[tuple[dict, dict]]:
    """Each object schema a request body can be, with the fields that select it (a union
    with a discriminator, such as a shift batch's "action")."""
    if "$ref" in schema:
        yield from _body_variants(components[schema["$ref"].rsplit("/", 1)[1]], components)
        return
    if "oneOf" in schema or "anyOf" in schema:
        tag = schema.get("discriminator", {}).get("propertyName")
        for part in schema.get("oneOf", schema.get("anyOf", [])):
            for variant, base in _body_variants(part, components):
                if tag and tag in variant.get("properties", {}):
                    base = {**base, tag: variant["properties"][tag].get("const")}
                yield variant, base
        return
    if schema.get("type") == "object":
        yield schema, {}


def numeric_inputs() -> list[NumericInput]:
    """Every numeric input of every operation in the API."""
    document = _openapi()
    components = document["components"]["schemas"]
    found = []
    for path, operations in document["paths"].items():
        for method, operation in operations.items():
            if method not in METHODS:
                continue
            for parameter in operation.get("parameters", []):
                for schema in _numeric(parameter["schema"], components):
                    low, high = _limits(schema)
                    found.append(
                        NumericInput(
                            method, path, parameter["in"], parameter["name"], low, high, {}
                        )
                    )
            content = operation.get("requestBody", {}).get("content", {})
            body = content.get("application/json", {}).get("schema")
            if body is None:
                continue
            for variant, base in _body_variants(body, components):
                for name, field in variant.get("properties", {}).items():
                    for schema in _numeric(field, components):
                        low, high = _limits(schema)
                        found.append(NumericInput(method, path, "body", name, low, high, base))
    return found


INPUTS = numeric_inputs()


def test_the_api_has_numeric_inputs_to_check() -> None:
    """A guard: if the walk above found nothing, the tests below would pass vacuously."""
    assert len(INPUTS) >= 10, [str(found) for found in INPUTS]


@pytest.mark.parametrize("found", INPUTS, ids=str)
def test_every_numeric_input_has_limits_that_fit_a_mysql_int(found: NumericInput) -> None:
    assert found.minimum is not None, f"{found}: no minimum"
    assert found.maximum is not None, f"{found}: no maximum"
    assert INT_MIN <= found.minimum <= found.maximum <= INT_MAX, found
    assert found.maximum < 2**53  # also safe in the browser


def _send(client: TestClient, found: NumericInput, raw: str) -> object:
    """Send the request with the number written as `raw` (JSON text, so 1e309 can be sent
    as it is); every other part is a placeholder that passes or fails on its own."""
    path = found.path
    while "{" in path:  # every path parameter here is an ID
        start, end = path.index("{"), path.index("}")
        path = path[:start] + str(uuid.uuid4()) + path[end + 1 :]
    params = {found.name: raw} if found.where == "query" else None
    content = None
    headers = {}
    if found.where == "body":
        base = json.dumps(found.body_base)[:-1]  # the other fields, without the closing }
        content = (base + ", " if found.body_base else "{") + f'"{found.name}": {raw}' + "}"
        headers = {"Content-Type": "application/json"}
    return client.request(found.method, path, params=params, content=content, headers=headers)


def _errors_about(response: object, found: NumericInput) -> list[dict]:
    """The validation errors that name this input (other fields may fail too). The API's
    problem format names each error's location as "<where>.<field>" (app/core/errors.py);
    a body field inside a union also names the variant, such as "body.cancel.confirm_count"."""
    if response.status_code != 422:  # type: ignore[attr-defined]
        return []
    return [
        error
        for error in response.json().get("errors", [])  # type: ignore[attr-defined]
        if isinstance(error, dict)
        and str(error.get("location", "")).startswith(found.where + ".")
        and str(error.get("location", "")).split(".")[-1] == found.name
    ]


def _cases(found: NumericInput) -> list[tuple[str, bool]]:
    """(the number as JSON text, whether it must be refused)."""
    low, high = found.minimum, found.maximum
    assert low is not None and high is not None  # checked by the test above
    return [
        (str(high), False),
        (str(low), False),
        (str(high + 1), True),
        (str(low - 1), True),
        (str(10**30), True),
        (str(-(10**30)), True),
        ("1e309", True),
    ]


@pytest.mark.parametrize("found", INPUTS, ids=str)
def test_numbers_past_the_limits_answer_422_and_never_500(
    signin: SignInSetup, found: NumericInput
) -> None:
    # Every table, not only the sign-in ones, so an accepted value reaches a real query.
    Base.metadata.create_all(signin.engine)
    browser = signin.new_client()
    signin.sign_in(browser, email(signin, "a_ana"))
    for raw, refused in _cases(found):
        response = _send(browser, found, raw)
        assert response.status_code != 500, (str(found), raw)  # type: ignore[attr-defined]
        errors = _errors_about(response, found)
        if refused:
            assert response.status_code == 422, (str(found), raw, response.status_code)  # type: ignore[attr-defined]
            assert errors, (str(found), raw, response.json())  # type: ignore[attr-defined]
        else:
            assert not errors, (str(found), raw, errors)
