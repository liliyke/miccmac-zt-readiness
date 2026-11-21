"""Reference date for the date-dependent checks (``--as-of``).

Four checks compare a recorded date with "now": INV-04 (inventory record
reviewed within 90 days), ASM-01 and ASM-02 (scan and assessment performed
within the attestation's interval_days) and CUR-01 (last successful OS
update within 7 days on Linux, 30 days on Windows). Without --as-of they
read the real clock, so the same facts can give a different verdict on a
different day. With --as-of YYYY-MM-DD the checks use that date instead, so
a run can be repeated: replaying saved facts weeks later with the same date
gives the same verdicts.

How the age is counted:

- INV-04, ASM-01 and ASM-02 subtract calendar dates, so the age in days is
  the as_of date minus the recorded date.
- CUR-01 compares timestamps and keeps its existing arithmetic: the whole
  number of days in (now - last update), rounded down. For it, the as_of
  date stands for the very end of that day in UTC (23:59:59.999999). With
  that choice the rounded-down age equals the number of UTC calendar days
  between the update and the as_of date, whatever the time of day of the
  update: an update at 00:00 or at 23:59 UTC on 2026-11-16 is 7 days old as
  of 2026-11-23. Taking the start of the day instead would count an update
  made later in the day as one day younger, so the verdict would depend on
  the time of day, which an assessor counting calendar days before the
  session date would not do. Timestamps that carry a UTC offset are
  compared as absolute times, so "calendar day" means the update's UTC date.

CUR-04 is not affected: its list of expired certificates is computed on the
device when the facts are collected (osquery's strftime('%s', 'now')).

_today() and _now_utc() are the only reads of the real clock; tests replace
them.
"""
from __future__ import annotations

import datetime
import re
from typing import Mapping, Optional

AS_OF_KEY = "as_of"

_AS_OF_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_UTC_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# The last moment of a day, used when an as_of date stands for a time.
_END_OF_DAY = datetime.time(23, 59, 59, 999999)


def _today() -> datetime.date:
    """The real local date (what the checks used before --as-of existed)."""
    return datetime.date.today()


def _now_utc() -> datetime.datetime:
    """The real current time, timezone-aware, in UTC."""
    return datetime.datetime.now(datetime.timezone.utc)


def _as_of(context: Optional[Mapping]) -> Optional[datetime.date]:
    if not context:
        return None
    return context.get(AS_OF_KEY)


def reference_date(context: Optional[Mapping]) -> datetime.date:
    """The date to count ages against: context["as_of"] when it is set,
    otherwise today's real date."""
    as_of = _as_of(context)
    if as_of is not None:
        return as_of
    return _today()


def reference_now(context: Optional[Mapping]) -> datetime.datetime:
    """The moment to count ages against, timezone-aware in UTC: the end of
    the as_of day in UTC when context["as_of"] is set (see the module
    docstring for why), otherwise the real current time."""
    as_of = _as_of(context)
    if as_of is not None:
        return datetime.datetime.combine(as_of, _END_OF_DAY, tzinfo=datetime.timezone.utc)
    return _now_utc()


def as_of_label(context: Optional[Mapping]) -> str:
    """' (as of YYYY-MM-DD)' when context["as_of"] is set, else ''. The four
    date-dependent checks append it to details that report an age, so a
    result file shows which reference date produced it."""
    as_of = _as_of(context)
    if as_of is None:
        return ""
    return f" (as of {as_of.isoformat()})"


def parse_as_of(text: str) -> datetime.date:
    """Parse an --as-of value strictly: exactly YYYY-MM-DD (ASCII digits) and
    a real calendar date. Raises ValueError otherwise. (date.fromisoformat
    alone is not enough: from Python 3.11 it also accepts forms such as
    20261123.)"""
    if not isinstance(text, str) or not _AS_OF_RE.fullmatch(text):
        raise ValueError(f"expected a date in the form YYYY-MM-DD, got {text!r}")
    year, month, day = (int(part) for part in text.split("-"))
    try:
        return datetime.date(year, month, day)
    except ValueError:
        raise ValueError(f"{text!r} is not a real calendar date") from None


def now_utc() -> datetime.datetime:
    """The real current time in UTC, never the as_of date. Used for
    timestamps that record when something happened (run_at_utc,
    collected_at_utc)."""
    return _now_utc()


def format_utc(moment: datetime.datetime) -> str:
    """'YYYY-MM-DDTHH:MM:SSZ' for an aware datetime (seconds, no fraction)."""
    return moment.astimezone(datetime.timezone.utc).strftime(_UTC_TIMESTAMP_FORMAT)


def parse_utc(text: str) -> datetime.datetime:
    """Parse exactly 'YYYY-MM-DDTHH:MM:SSZ' into an aware UTC datetime.
    Raises ValueError otherwise. (Python 3.9's datetime.fromisoformat
    rejects the trailing Z, so this does not use it.)"""
    if not isinstance(text, str) or not _UTC_TIMESTAMP_RE.fullmatch(text):
        raise ValueError(f"expected a UTC timestamp in the form YYYY-MM-DDTHH:MM:SSZ, got {text!r}")
    try:
        parsed = datetime.datetime.strptime(text, _UTC_TIMESTAMP_FORMAT)
    except ValueError:
        raise ValueError(f"{text!r} is not a real date and time") from None
    return parsed.replace(tzinfo=datetime.timezone.utc)
