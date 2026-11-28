"""Threat I7: text that looks like a format template is stored and shown as typed (#106).

If the application ever used user text as a template, these values would change on the way
back: `{0.__class__}` would turn into a class name, `%s%s%n` would fail or read memory in
C code, and `${7*7}` would become 49 in a template engine. They come back exactly as sent,
because the code only ever puts user text into templates it wrote itself
(tests/unit/test_no_user_templates.py checks the code for that).
"""

import pytest

from tests.shift_data import ShiftSetup, shifts

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here

TEMPLATES = [
    "{0.__class__.__init__.__globals__}",
    "{.__class__}",
    "%s%s%s%n",
    "%x%x%x%08x",
    "${7*7}",
    "{{7*7}}",
    "#{7*7}",
    "<%= 7*7 %>",
]


@pytest.mark.parametrize("text", TEMPLATES)
def test_shift_text_comes_back_exactly_as_typed(shifts: ShiftSetup, text: str) -> None:
    created = shifts.new_shift(notes=text, event_name=text[:120], details=text[:200])
    assert (created["notes"], created["event_name"], created["details"]) == (
        text,
        text[:120],
        text[:200],
    )
    again = shifts.browser("chef").get(f"/api/shifts/{created['id']}").json()
    assert again["notes"] == text


@pytest.mark.parametrize("text", TEMPLATES)
def test_names_come_back_exactly_as_typed(shifts: ShiftSetup, text: str) -> None:
    owner = shifts.browser("owner")
    kitchen = owner.patch(f"/api/departments/{shifts.ids['kitchen']}", json={"name": text})
    assert kitchen.status_code == 200, kitchen.text
    assert kitchen.json()["name"] == text
    person = owner.patch(f"/api/users/{shifts.ids['cara']}", json={"display_name": text})
    assert person.status_code == 200, person.text
    assert owner.get(f"/api/users/{shifts.ids['cara']}").json()["display_name"] == text
