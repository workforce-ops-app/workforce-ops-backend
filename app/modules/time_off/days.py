"""Days off as calendar dates in the employee's workplace zone (decision 0021), and the UTC
moments where they begin and end, for comparing with shifts and deadlines."""

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.modules.org.models import Department, User
from app.modules.schedules.repository import workplace_zone


def zone_of(db: Session, person: User) -> ZoneInfo:
    """The person's workplace time zone: their home department's, or the company's."""
    home = db.get(Department, person.department_id)
    if home is None:  # everyone has a home department of their own company
        raise RuntimeError("the person's home department is missing")
    return ZoneInfo(workplace_zone(db, home))


def day_starts(zone: ZoneInfo, day: date) -> datetime:
    """The UTC moment (without zone, as stored) where a day begins in a zone."""
    return datetime.combine(day, time(0), zone).astimezone(UTC).replace(tzinfo=None)


def days_span(zone: ZoneInfo, first: date, last: date) -> tuple[datetime, datetime]:
    """Where the days first..last (both included) begin and end, in stored UTC."""
    return day_starts(zone, first), day_starts(zone, last + timedelta(days=1))
