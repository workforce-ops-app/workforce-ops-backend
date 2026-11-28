"""Threat T6: numbers past what the database or the browser can hold (#105).

Python's integers never overflow, but MySQL's columns do (INT stops at 2,147,483,647,
SMALLINT at 32,767) and JavaScript rounds every number past 2^53. So every number a
request carries, in its path, query, or body, has a minimum and a maximum that fit the
column it ends up in, and a value past them is refused with 422 before any code uses it.

The tests read the API's own OpenAPI document, so a numeric field added later is checked
without anyone listing it here:

1. Every numeric input declares both limits, inside a MySQL INT (and so below 2^53).
2. Signed in, each input is sent its maximum and minimum, one past each limit, 10^30 and
   -10^30, and 1e309 (a float JSON reads as infinity). Every other part of the request is
   a valid placeholder made from its schema, so the limits get all the way past
   validation (the request reaches the service), and the other values are refused with
   422 naming that input, never a 500.

The walk follows numbers into nested objects, list items, and path parameters (review of
#202). A shape it cannot follow or fill (a map of numbers, a nested union of objects, a
string with a pattern) is listed by test_every_numeric_input_can_be_reached, which then
fails, so no input escapes the checks without a word. The walk itself is tested at the
end of this file, on a small app with those shapes.

Validation runs before any permission check, so one ordinary account reaches every check.
"""

import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Annotated

import pytest
from fastapi import Body, FastAPI, Path, Query
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from app.db.base import Base
from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here

INT_MIN, INT_MAX = -(2**31), 2**31 - 1  # a MySQL INT, the widest integer column a request fills
METHODS = ("get", "post", "put", "patch", "delete")

# One step of a path inside a request body: a property name, or 0 for "an item of the list".
Segment = str | int


@dataclass(frozen=True)
class NumericInput:
    """One number a request can carry: where it goes, its declared limits, and what the
    rest of a valid request is made from."""

    method: str
    path: str
    where: str  # "query", "path", or "body"
    name: str  # the parameter, or the body field's path ("slots.0.minutes")
    minimum: int | float | None
    maximum: int | float | None
    at: tuple[Segment, ...] = ()  # for a body field: its path inside the body
    variant: dict = field(default_factory=dict)  # the body's object schema, if any
    body_base: dict = field(default_factory=dict)  # the fields that pick that variant
    parameters: tuple[dict, ...] = ()  # the operation's path and query parameters

    def __str__(self) -> str:
        return f"{self.method.upper()} {self.path} {self.where}.{self.name}"


class Unsupported(Exception):
    """A schema shape the walk cannot follow, or cannot fill with a valid placeholder."""


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


def _resolve(schema: dict, components: dict) -> dict:
    """The schema a "$ref" points to (or the schema itself)."""
    while "$ref" in schema:
        schema = components[schema["$ref"].rsplit("/", 1)[1]]
    return schema


def _where(at: tuple[Segment, ...]) -> str:
    """A body path as text, for messages: "slots.0.minutes", or "body" for the top."""
    return ".".join(map(str, at)) or "body"


def _numbers(
    schema: dict,
    components: dict,
    at: tuple[Segment, ...] = (),
    seen: frozenset[str] = frozenset(),
) -> Iterator[tuple[tuple[Segment, ...], dict]]:
    """Every numeric schema inside `schema`, with its path: through refs, unions, nested
    objects, and list items. Raises Unsupported for a shape whose numbers it cannot
    reach, so a new field of that shape fails a test instead of escaping the checks."""
    if "$ref" in schema:
        name = schema["$ref"]
        if name in seen:  # a model inside itself: its numbers are walked already
            return
        yield from _numbers(_resolve(schema, components), components, at, seen | {name})
        return
    if schema.get("type") in ("integer", "number"):
        yield at, schema
    parts = schema.get("anyOf", schema.get("oneOf", []))
    shapes = [p for p in parts if _resolve(p, components).get("type") in ("object", "array")]
    if len(shapes) > 1:
        # Which part a nested union takes depends on the other fields, so the request
        # builder could not be sure to reach the number. (A whole body that is a union
        # with a discriminator, like a shift batch, is split up by _body_variants.)
        raise Unsupported(f"{_where(at)}: a union of several object or list shapes")
    for part in parts:
        yield from _numbers(part, components, at, seen)
    if "allOf" in schema:
        raise Unsupported(f"{_where(at)}: allOf")
    if schema.get("type") == "array":
        if "prefixItems" in schema:
            raise Unsupported(f"{_where(at)}: a list with fixed positions")
        yield from _numbers(schema.get("items", {}), components, (*at, 0), seen)
    if schema.get("type") == "object" or "properties" in schema:
        for name, part in schema.get("properties", {}).items():
            yield from _numbers(part, components, (*at, name), seen)
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict) and next(_numbers(extra, components, at, seen), None):
            raise Unsupported(f"{_where(at)}: a map of numbers")
        if "patternProperties" in schema:
            raise Unsupported(f"{_where(at)}: patternProperties")


def _body_variants(schema: dict, components: dict) -> Iterator[tuple[dict, dict]]:
    """Each object schema a request body can be, with the fields that select it (a union
    with a discriminator, such as a shift batch's "action")."""
    if "$ref" in schema:
        yield from _body_variants(_resolve(schema, components), components)
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


def numeric_inputs(document: dict) -> tuple[list[NumericInput], list[str]]:
    """Every numeric input of every operation in an OpenAPI document, and the operations
    the walk could not follow ("METHOD path: why")."""
    components = document.get("components", {}).get("schemas", {})
    found: list[NumericInput] = []
    unsupported: list[str] = []
    for path, operations in document["paths"].items():
        for method, operation in operations.items():
            if method not in METHODS:
                continue
            parameters = tuple(operation.get("parameters", []))
            content = operation.get("requestBody", {}).get("content", {})
            body = content.get("application/json", {}).get("schema")
            variants = list(_body_variants(body, components)) if body else []
            before = len(found)
            try:
                for parameter in parameters:
                    for _, schema in _numbers(parameter["schema"], components):
                        low, high = _limits(schema)
                        found.append(
                            NumericInput(
                                method,
                                path,
                                parameter["in"],
                                parameter["name"],
                                low,
                                high,
                                # A body is still needed for the request to pass validation.
                                variant=variants[0][0] if variants else {},
                                body_base=variants[0][1] if variants else {},
                                parameters=parameters,
                            )
                        )
                for variant, base in variants:
                    for at, schema in _numbers(variant, components):
                        low, high = _limits(schema)
                        found.append(
                            NumericInput(
                                method,
                                path,
                                "body",
                                _where(at),
                                low,
                                high,
                                at=at,
                                variant=variant,
                                body_base=base,
                                parameters=parameters,
                            )
                        )
                # Where there is a number to check, valid placeholders for the rest of the
                # request must be possible too, or its limits could not be shown to get
                # past validation.
                if len(found) > before:
                    for variant, _ in variants:
                        _example(variant, components)
                    for parameter in parameters:
                        if parameter.get("required"):
                            _example(parameter["schema"], components)
            except Unsupported as why:
                unsupported.append(f"{method.upper()} {path}: {why}")
    return found, unsupported


# Marks where the number under test goes. It is replaced by the number's JSON text after
# json.dumps, so a number Python cannot hold as a float (1e309) is sent exactly as written.
RAW = "\x00raw\x00"


def _example(schema: dict, components: dict, force: tuple[Segment, ...] | None = None) -> object:
    """A valid placeholder for `schema`: the required fields only, each the simplest value
    its schema allows. `force` is the path to the number under test, which is put there as
    RAW (the objects and lists on the way are made even when optional). Raises Unsupported
    when no valid placeholder can be made, such as for a string with a pattern."""
    schema = _resolve(schema, components)
    if force == ():
        return RAW
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    if "anyOf" in schema or "oneOf" in schema:
        parts = schema.get("anyOf", schema.get("oneOf", []))
        if force:  # the part on the way to the number
            parts = [p for p in parts if _leads_to(p, components, force)] or parts
        parts = [p for p in parts if _resolve(p, components).get("type") != "null"] or parts
        return _example(parts[0], components, force)
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        result = {}
        for name in schema.get("required", []):
            inner = force[1:] if force and force[0] == name else None
            result[name] = _example(properties[name], components, inner)
        if force and force[0] not in result:
            result[str(force[0])] = _example(properties[force[0]], components, force[1:])
        return result
    if kind == "array":
        count = max(schema.get("minItems", 0), 1 if force else 0)
        inner = force[1:] if force else None
        return [_example(schema.get("items", {}), components, inner) for _ in range(count)]
    if kind in ("integer", "number"):
        low, high = _limits(schema)
        if low is not None:
            return low
        return 0 if high is None or high >= 0 else high
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    if kind == "string":
        if "pattern" in schema:
            if schema.get("examples"):
                return schema["examples"][0]
            raise Unsupported(f"a string with a pattern ({schema['pattern']}) and no example")
        made = {
            "uuid": lambda: str(uuid.uuid4()),
            "date": lambda: "2026-01-05",
            "date-time": _next_moment,
            "time": lambda: "09:00:00",
            "email": lambda: "placeholder@example.com",
        }.get(schema.get("format", ""))
        if made:
            return made()
        return "a" * max(schema.get("minLength", 1), 1)
    raise Unsupported(f"no placeholder for {json.dumps(schema)[:80]}")


_moments = iter(range(10**9))


def _next_moment() -> str:
    """Moments an hour apart, in the order they are made, so a start comes before its end."""
    hour = next(_moments) % 480
    return f"2026-01-{5 + hour // 24:02d}T{hour % 24:02d}:00:00Z"


def _leads_to(schema: dict, components: dict, force: tuple[Segment, ...]) -> bool:
    """Whether the path `force` goes through `schema` to a number."""
    schema = _resolve(schema, components)
    if not force:
        return schema.get("type") in ("integer", "number")
    if force[0] == 0:
        items = schema.get("items", {})
        return schema.get("type") == "array" and _leads_to(items, components, force[1:])
    part = schema.get("properties", {}).get(force[0])
    return part is not None and _leads_to(part, components, force[1:])


def _send(client: TestClient, found: NumericInput, raw: str, components: dict) -> object:
    """Send the request with the number written as `raw` (JSON text, so 1e309 can be sent
    as it is). Every other part is a valid placeholder made from its own schema: an ID
    path parameter gets a UUID, a numeric one a number inside its limits."""
    path = found.path
    query: dict[str, object] = {}
    for parameter in found.parameters:
        mine = parameter["in"] == found.where and parameter["name"] == found.name
        if not mine and not parameter.get("required"):
            continue  # optional, and not under test: left out
        value = raw if mine else _example(parameter["schema"], components)
        if parameter["in"] == "path":
            path = path.replace("{" + parameter["name"] + "}", str(value))
        elif parameter["in"] == "query":
            query[parameter["name"]] = value
    content = None
    headers = {}
    if found.variant:  # the operation takes a body: send a valid one
        force = found.at if found.where == "body" else None
        body = _example(found.variant, components, force)
        assert isinstance(body, dict)
        content = json.dumps({**body, **found.body_base}).replace(json.dumps(RAW), raw)
        headers = {"Content-Type": "application/json"}
    return client.request(found.method, path, params=query, content=content, headers=headers)


def _validation_errors(response: object) -> list[dict] | None:
    """The request's validation errors, or None if it got past validation. Only request
    validation answers 422 with an "errors" list (app/core/errors.py)."""
    if response.status_code != 422:  # type: ignore[attr-defined]
        return None
    errors = response.json().get("errors")  # type: ignore[attr-defined]
    return errors if isinstance(errors, list) else None


def _errors_about(response: object, found: NumericInput) -> list[dict]:
    """The validation errors that name this input. The API's problem format names each
    error's location as "<where>.<field>" (app/core/errors.py); a body field inside a
    union also names the variant, such as "body.cancel.confirm_count", and an item of a
    list its position, such as "body.slots.0.minutes"."""
    return [
        error
        for error in _validation_errors(response) or []
        if isinstance(error, dict)
        and str(error.get("location", "")).startswith(found.where + ".")
        and str(error.get("location", "")).endswith("." + found.name)
    ]


def _cases(found: NumericInput) -> list[tuple[str, bool]]:
    """(the number as JSON text, whether it must be refused)."""
    low, high = found.minimum, found.maximum
    assert low is not None and high is not None  # checked by the limits test
    return [
        (str(high), False),
        (str(low), False),
        (str(high + 1), True),
        (str(low - 1), True),
        (str(10**30), True),
        (str(-(10**30)), True),
        ("1e309", True),
    ]


def _check(client: TestClient, found: NumericInput, components: dict) -> None:
    """Every case of one input: the limits get past validation, the other values are
    refused with 422 naming the input, and nothing answers 500."""
    for raw, refused in _cases(found):
        response = _send(client, found, raw, components)
        assert response.status_code != 500, (str(found), raw)  # type: ignore[attr-defined]
        if refused:
            assert response.status_code == 422, (str(found), raw, response.status_code)  # type: ignore[attr-defined]
            assert _errors_about(response, found), (str(found), raw, response.json())  # type: ignore[attr-defined]
        else:
            # No validation error at all, not only none about this input: otherwise
            # another field's error could stop the request before it reached the service
            # (review of #202).
            assert _validation_errors(response) is None, (str(found), raw, response.json())  # type: ignore[attr-defined]


DOCUMENT = _openapi()
COMPONENTS = DOCUMENT["components"]["schemas"]
INPUTS, UNSUPPORTED = numeric_inputs(DOCUMENT)


def test_the_api_has_numeric_inputs_to_check() -> None:
    """A guard: if the walk above found nothing, the tests below would pass vacuously."""
    assert len(INPUTS) >= 10, [str(found) for found in INPUTS]


def test_every_numeric_input_can_be_reached() -> None:
    """A shape the walk cannot follow fails here instead of escaping the checks below.
    To fix it, teach the walk the shape (with a test at the end of this file)."""
    assert UNSUPPORTED == []


@pytest.mark.parametrize("found", INPUTS, ids=str)
def test_every_numeric_input_has_limits_that_fit_a_mysql_int(found: NumericInput) -> None:
    assert found.minimum is not None, f"{found}: no minimum"
    assert found.maximum is not None, f"{found}: no maximum"
    assert INT_MIN <= found.minimum <= found.maximum <= INT_MAX, found
    assert found.maximum < 2**53  # also safe in the browser


@pytest.mark.parametrize("found", INPUTS, ids=str)
def test_numbers_past_the_limits_answer_422_and_never_500(
    signin: SignInSetup, found: NumericInput
) -> None:
    # Every table, not only the sign-in ones, so an accepted value reaches a real query.
    Base.metadata.create_all(signin.engine)
    browser = signin.new_client()
    signin.sign_in(browser, email(signin, "a_ana"))
    _check(browser, found, COMPONENTS)


# The walk itself, on a small app with shapes the API does not have yet: a numeric path
# parameter, numbers in a nested object, in objects in a list, and in a list of numbers,
# and a map of numbers, which the walk cannot follow and must report.


class _Slot(BaseModel):
    minutes: int = Field(ge=0, le=600)


class _Plan(BaseModel):
    name: str
    slot: _Slot  # a number in a nested object
    slots: list[_Slot] = Field(min_length=1)  # in objects in a list
    counts: list[Annotated[int, Field(ge=1, le=9)]] = []  # a list of numbers


class _Map(BaseModel):
    by_name: dict[str, Annotated[int, Field(ge=0, le=5)]]


def _small_app() -> FastAPI:
    """Two endpoints, with the API's own validation answer. Each answers 204 once valid."""
    from app.core.errors import request_validation_error_handler

    app = FastAPI()
    app.add_exception_handler(RequestValidationError, request_validation_error_handler)

    @app.put("/plans/{plan_id}/weeks/{week}", status_code=204)
    def put_plan(
        plan_id: uuid.UUID,
        week: Annotated[int, Path(ge=1, le=53)],
        plan: Annotated[_Plan, Body()],
        page: Annotated[int, Query(ge=1, le=10)] = 1,
    ) -> None:
        """Reached only with every number inside its limits."""

    @app.post("/maps", status_code=204)
    def post_map(body: _Map) -> None:
        """Its numbers sit under names nobody knows in advance."""

    return app


def _small() -> tuple[TestClient, dict, list[NumericInput], list[str]]:
    """A client for the small app, its schemas, and what the walk finds in it."""
    app = _small_app()
    document = app.openapi()
    found, unsupported = numeric_inputs(document)
    return TestClient(app), document["components"]["schemas"], found, unsupported


def test_the_walk_finds_path_nested_and_list_numbers() -> None:
    _, _, found, _ = _small()
    assert {str(one) for one in found} == {
        "PUT /plans/{plan_id}/weeks/{week} path.week",
        "PUT /plans/{plan_id}/weeks/{week} query.page",
        "PUT /plans/{plan_id}/weeks/{week} body.slot.minutes",
        "PUT /plans/{plan_id}/weeks/{week} body.slots.0.minutes",
        "PUT /plans/{plan_id}/weeks/{week} body.counts.0",
    }


def test_the_walk_reports_what_it_cannot_follow() -> None:
    _, _, _, unsupported = _small()
    assert unsupported == ["POST /maps: by_name: a map of numbers"]


def test_the_request_builder_reaches_every_kind_of_number() -> None:
    """The limits pass validation and reach the endpoint (204); every other value is
    refused naming the exact input: in the path, a nested object, or an item of a list."""
    client, components, found, _ = _small()
    assert found
    for one in found:
        _check(client, one, components)
        assert one.maximum is not None
        response = _send(client, one, str(one.maximum), components)
        assert response.status_code == 204, (str(one), response.json())  # type: ignore[attr-defined]


def test_an_accepted_limit_stopped_by_another_field_fails_the_check() -> None:
    """The earlier check passed when another field's error stopped the request; this one
    does not. Here the body is left empty, so its required fields are missing."""
    client, components, found, _ = _small()
    week = next(one for one in found if one.name == "week")
    empty_body = NumericInput(
        week.method,
        week.path,
        week.where,
        week.name,
        week.minimum,
        week.maximum,
        variant={"type": "object", "properties": {}},
        parameters=week.parameters,
    )
    with pytest.raises(AssertionError):
        _check(client, empty_body, components)
