"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for --as-of and miccmac.clock.

The four date-dependent checks (ASM-01, ASM-02, INV-04, and CUR-01 on Linux
and on Windows) must give the same verdict and detail for a fixed as_of
date whatever the real clock says, and must still read the real clock when
no as_of is set. The real clock is replaced through miccmac.clock._today
and miccmac.clock._now_utc. Synthetic values only; no network."""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
import types

import pytest

from miccmac import clock
from miccmac.checks import assessed, current, inventoried
from miccmac.cli import main
from miccmac.model import Status

UTC = dt.timezone.utc
AS_OF = dt.date(2026, 11, 23)
LABEL = " (as of 2026-11-23)"
# Two "real" clocks far enough apart that every verdict below would change
# if a check read the real clock instead of as_of.
REAL_CLOCKS = (
    dt.datetime(2026, 11, 23, 8, 30, tzinfo=UTC),
    dt.datetime(2027, 1, 15, 22, 15, tzinfo=UTC),
)


@pytest.fixture
def real_clock(monkeypatch):
    """set_clock(moment): make `moment` the real clock that miccmac sees."""
    def set_clock(moment: dt.datetime) -> None:
        monkeypatch.setattr(clock, "_now_utc", lambda: moment)
        monkeypatch.setattr(clock, "_today", lambda: moment.date())
    return set_clock


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def _context(as_of, **items) -> dict:
    context = dict(items)
    if as_of is not None:
        context["as_of"] = as_of
    return context


def _asm01(last_scan: dt.date, as_of=AS_OF, interval_days=30):
    attestation = {"vulnerability_scanning": {
        "performed": True, "last_scan": last_scan.isoformat(), "interval_days": interval_days}}
    return _by_id(assessed.evaluate("x", _context(as_of, attestation=attestation)).checks, "ASM-01")


def _asm02(last_assessment: dt.date, as_of=AS_OF, interval_days=90):
    attestation = {"compliance_assessment": {
        "performed": True, "last_assessment": last_assessment.isoformat(), "interval_days": interval_days}}
    return _by_id(assessed.evaluate("x", _context(as_of, attestation=attestation)).checks, "ASM-02")


def _inv04(last_reviewed: dt.date, as_of=AS_OF):
    record = {"device_id": "H1", "tracked": True, "last_reviewed": last_reviewed.isoformat()}
    facts = {"os": {"platform": "ubuntu"}, "system_info": {}, "deb_packages": []}
    context = _context(as_of, facts=facts, inventory_record=record)
    return _by_id(inventoried.evaluate("x", context).checks, "INV-04")


def _cur01_linux(last_update: dt.datetime, as_of=AS_OF, timer="active"):
    facts = {
        "os": {"platform": "ubuntu"},
        "systemd_units": {"apt-daily-upgrade.timer": {"active_state": timer}},
        "apt_update_stamp_mtime": None if last_update is None else int(last_update.timestamp()),
        "apt_sources": [], "expired_certificates": [],
    }
    return _by_id(current.evaluate("x", _context(as_of, facts=facts)).checks, "CUR-01")


def _cur01_windows(last_install_iso, as_of=AS_OF, service_status="RUNNING"):
    facts = {
        "os": {"platform": "windows"},
        "services": {"wuauserv": {"status": service_status, "start_type": "DEMAND_START"}},
        "programs": [], "last_update_installed_iso": last_install_iso, "expired_certificates": [],
    }
    return _by_id(current.evaluate("x", _context(as_of, facts=facts)).checks, "CUR-01")


# check -> (result for the fixed AS_OF, expected status, expected detail)
FIXED_CASES = {
    "ASM-01": (lambda: _asm01(dt.date(2026, 11, 3)), Status.PASS,
               "Vulnerability scanning last performed 20 day(s) ago (policy: 30)." + LABEL),
    "ASM-02": (lambda: _asm02(dt.date(2026, 8, 1)), Status.FAIL,
               "Compliance assessment last performed 114 day(s) ago, exceeding the "
               "90-day policy interval." + LABEL),
    "INV-04": (lambda: _inv04(dt.date(2026, 9, 1)), Status.PASS,
               "Inventory record last reviewed 83 day(s) ago (policy: 90)." + LABEL),
    "CUR-01-linux": (lambda: _cur01_linux(dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC)), Status.PASS,
                     "apt-daily-upgrade.timer active; last successful apt update 3 day(s) ago." + LABEL),
    "CUR-01-windows": (lambda: _cur01_windows("2026-11-01T09:00:00"), Status.PASS,
                       "Windows Update service active; last successful update installed "
                       "22 day(s) ago." + LABEL),
}


@pytest.mark.parametrize("case", sorted(FIXED_CASES))
def test_fixed_as_of_gives_the_same_verdict_and_detail_under_any_real_clock(case, real_clock):
    make, status, detail = FIXED_CASES[case]
    for moment in REAL_CLOCKS:
        real_clock(moment)
        result = make()
        assert (result.status, result.detail) == (status, detail), f"real clock {moment}"


def test_the_fixed_cases_would_change_with_the_real_clock(real_clock):
    """Sanity check for the test above: without as_of, the later real clock
    changes the verdict, so that test really exercises as_of."""
    real_clock(REAL_CLOCKS[1])
    assert _asm01(dt.date(2026, 11, 3), as_of=None).status == Status.FAIL
    assert _inv04(dt.date(2026, 9, 1), as_of=None).status == Status.FAIL
    assert _cur01_linux(dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC), as_of=None).status == Status.FAIL
    assert _cur01_windows("2026-11-01T09:00:00", as_of=None).status == Status.FAIL


# ---------------------------------------------------------------- boundaries under as_of

def test_apt_boundary_is_seven_utc_calendar_days_whatever_the_time_of_day(real_clock):
    real_clock(REAL_CLOCKS[1])
    for moment in (dt.datetime(2026, 11, 16, 0, 0, 0, tzinfo=UTC),
                   dt.datetime(2026, 11, 16, 23, 59, 59, tzinfo=UTC)):
        result = _cur01_linux(moment)
        assert result.status == Status.PASS
        assert result.detail == ("apt-daily-upgrade.timer active; last successful apt update "
                                 "7 day(s) ago." + LABEL)
    result = _cur01_linux(dt.datetime(2026, 11, 15, 23, 59, 59, tzinfo=UTC))
    assert result.status == Status.FAIL
    assert result.detail == ("apt-daily-upgrade.timer active, but last successful apt update was "
                             "8 day(s) ago, exceeding the 7-day policy." + LABEL)


def test_an_update_on_the_as_of_day_is_zero_days_old(real_clock):
    real_clock(REAL_CLOCKS[0])
    result = _cur01_linux(dt.datetime(2026, 11, 23, 23, 59, 59, tzinfo=UTC))
    assert result.status == Status.PASS
    assert "0 day(s) ago" in result.detail


def test_windows_update_boundary_is_thirty_days(real_clock):
    real_clock(REAL_CLOCKS[1])
    for iso in ("2026-10-24T00:00:00", "2026-10-24T23:59:59"):
        result = _cur01_windows(iso)
        assert result.status == Status.PASS
        assert result.detail == ("Windows Update service active; last successful update installed "
                                 "30 day(s) ago." + LABEL)
    result = _cur01_windows("2026-10-23T23:59:59")
    assert result.status == Status.FAIL
    assert result.detail == ("Windows Update service active, but last successful update was "
                             "31 day(s) ago, exceeding the 30-day policy." + LABEL)


@pytest.mark.parametrize("make, label, interval", [
    (_asm01, "Vulnerability scanning", 30),
    (_asm02, "Compliance assessment", 90),
    (_asm01, "Vulnerability scanning", 7),
])
def test_assessed_boundary_is_the_attestations_interval_days(make, label, interval, real_clock):
    real_clock(REAL_CLOCKS[1])
    on_limit = make(AS_OF - dt.timedelta(days=interval), interval_days=interval)
    assert on_limit.status == Status.PASS
    assert on_limit.detail == (f"{label} last performed {interval} day(s) ago "
                               f"(policy: {interval})." + LABEL)
    past_limit = make(AS_OF - dt.timedelta(days=interval + 1), interval_days=interval)
    assert past_limit.status == Status.FAIL
    assert past_limit.detail == (f"{label} last performed {interval + 1} day(s) ago, exceeding the "
                                 f"{interval}-day policy interval." + LABEL)


def test_inventory_review_boundary_is_ninety_days(real_clock):
    real_clock(REAL_CLOCKS[1])
    on_limit = _inv04(dt.date(2026, 8, 25))
    assert on_limit.status == Status.PASS
    assert on_limit.detail == "Inventory record last reviewed 90 day(s) ago (policy: 90)." + LABEL
    past_limit = _inv04(dt.date(2026, 8, 24))
    assert past_limit.status == Status.FAIL
    assert past_limit.detail == ("Inventory record last reviewed 91 day(s) ago, exceeding the "
                                 "90-day policy interval." + LABEL)


# ---------------------------------------------------------------- no as_of: the real clock

def test_without_as_of_the_date_checks_use_the_real_date(real_clock):
    real_clock(dt.datetime(2026, 11, 23, 12, 0, tzinfo=UTC))
    assert _inv04(dt.date(2026, 8, 25), as_of=None).detail == \
        "Inventory record last reviewed 90 day(s) ago (policy: 90)."
    assert _asm01(dt.date(2026, 10, 24), as_of=None).detail == \
        "Vulnerability scanning last performed 30 day(s) ago (policy: 30)."
    real_clock(dt.datetime(2026, 11, 24, 12, 0, tzinfo=UTC))
    assert _inv04(dt.date(2026, 8, 25), as_of=None).status == Status.FAIL
    assert _asm01(dt.date(2026, 10, 24), as_of=None).status == Status.FAIL
    assert _asm02(dt.date(2026, 8, 25), as_of=None).status == Status.FAIL


def test_without_as_of_cur01_uses_the_real_time_of_day(real_clock):
    """The existing arithmetic, unchanged: with the real clock the time of
    day still counts, which is exactly what --as-of takes away."""
    stamp = dt.datetime(2026, 11, 16, 13, 0, tzinfo=UTC)
    real_clock(dt.datetime(2026, 11, 23, 12, 0, tzinfo=UTC))
    assert _cur01_linux(stamp, as_of=None).detail == \
        "apt-daily-upgrade.timer active; last successful apt update 6 day(s) ago."
    real_clock(dt.datetime(2026, 11, 23, 14, 0, tzinfo=UTC))
    assert _cur01_linux(stamp, as_of=None).detail == \
        "apt-daily-upgrade.timer active; last successful apt update 7 day(s) ago."
    real_clock(dt.datetime(2026, 11, 30, 14, 0, tzinfo=UTC))
    assert _cur01_linux(stamp, as_of=None).status == Status.FAIL
    assert _cur01_windows("2026-10-24T13:00:00", as_of=None).status == Status.FAIL
    real_clock(dt.datetime(2026, 11, 23, 12, 0, tzinfo=UTC))
    assert _cur01_windows("2026-10-24T13:00:00", as_of=None).detail == \
        "Windows Update service active; last successful update installed 29 day(s) ago."


def test_check_functions_default_to_the_real_clock(real_clock):
    """Called directly with no reference given (None), the check functions
    read the clock helpers, as they did before."""
    real_clock(dt.datetime(2026, 11, 23, 12, 0, tzinfo=UTC))
    record = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-11-13"}
    assert "10 day(s) ago" in inventoried._check_inv04(record).detail
    units = {"apt-daily-upgrade.timer": {"active_state": "active"}}
    stamp = int(dt.datetime(2026, 11, 21, 12, 0, tzinfo=UTC).timestamp())
    assert "2 day(s) ago" in current._check_cur01(units, stamp).detail
    services = {"wuauserv": {"status": "RUNNING"}}
    assert "5 day(s) ago" in current._check_cur01_windows(services, "2026-11-18T12:00:00").detail
    attestation = {"vulnerability_scanning": {"performed": True, "last_scan": "2026-11-20",
                                              "interval_days": 30}}
    assert "3 day(s) ago" in assessed._check_asm01(attestation).detail


# ---------------------------------------------------------------- Windows timestamps (CC-04)

# Python 3.9's documented datetime.fromisoformat grammar (3.10 reads the same;
# 3.11 widened it):  YYYY-MM-DD[*HH[:MM[:SS[.fff[fff]]]][+HH:MM[:SS[.ffffff]]]]
# where * is any single character. No "Z", and a fraction of 3 or 6 digits only.
PY39_FROMISOFORMAT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"(?:.[0-9]{2}(?::[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?)?)?"
    r"(?:[+-][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{6})?)?)?)?",
    re.DOTALL,
)
EST = dt.timezone(dt.timedelta(hours=-5))
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
# The forms Windows CUR-01 meets: PowerShell's ToString('o') prints 7 fraction
# digits, then nothing (DateTimeKind Unspecified), the local offset (Local) or
# "Z" (Utc). With the value every Python version must read from each.
POWERSHELL_FORMS = [
    ("2026-11-12T00:00:00.0000000", dt.datetime(2026, 11, 12)),
    ("2026-11-12T00:00:00.0000000-05:00", dt.datetime(2026, 11, 12, tzinfo=EST)),
    ("2026-11-12T00:00:00.0000000Z", dt.datetime(2026, 11, 12, tzinfo=UTC)),
    ("2026-11-12T13:45:30.1234567+05:30", dt.datetime(2026, 11, 12, 13, 45, 30, 123456, tzinfo=IST)),
    ("2026-11-12T13:45:30.9999999Z", dt.datetime(2026, 11, 12, 13, 45, 30, 999999, tzinfo=UTC)),
    ("2026-11-12 13:45:30.1234567", dt.datetime(2026, 11, 12, 13, 45, 30, 123456)),
    ("2026-11-12T13:45:30.5", dt.datetime(2026, 11, 12, 13, 45, 30, 500000)),
    ("2026-11-12T13:45:30.123", dt.datetime(2026, 11, 12, 13, 45, 30, 123000)),
    ("2026-11-12T13:45:30.123456", dt.datetime(2026, 11, 12, 13, 45, 30, 123456)),
    ("2026-11-12T13:45:30.123456789012", dt.datetime(2026, 11, 12, 13, 45, 30, 123456)),
    ("2026-11-12T13:45:30Z", dt.datetime(2026, 11, 12, 13, 45, 30, tzinfo=UTC)),
    ("2026-11-12T13:45:30", dt.datetime(2026, 11, 12, 13, 45, 30)),
    ("2026-11-12T13:45:30-00:00", dt.datetime(2026, 11, 12, 13, 45, 30, tzinfo=UTC)),
]
# Every input form, for the 3.11+ identity table: the PowerShell forms above,
# forms the helper leaves alone for fromisoformat to judge as it always did,
# and forms no version accepts.
ISO_FORMS = [text for text, _ in POWERSHELL_FORMS] + [
    "2026-11-12T13:45:30.12", "2026-11-12T13:45:30.1234", "2026-11-12T13:45:30.12345",
    "2026-11-12T00:00:00.0000000+00:00", "2026-11-12T00:00:00.0000000+14:00",
    "2026-11-12T23:59:59.9999999-05:00", "2026-11-12T13:45:30+00:00",
    # Left unchanged by the helper (any version's fromisoformat decides).
    "2026-11-12", "2026-11-12T13:45", "2026-11-12T13", "2026-11-12T13:45:30,123",
    "20261112T134530", "2026-W46-4", "2026-11-12t13:45:30.1234567", "2026-11-12x13:45:30.5",
    "2026-11-12T13:45:30.1234567+05:00:00", "2026-11-12T13:45:30.1234567+0500",
    "2026-11-12T13:45:30.1234567+05", "2026-11-12T13:45:30.Z",
    # Invalid everywhere, before and after the helper.
    "2026-11-12Z", "2026-11-12T13:45:30z", "2026-11-12T13:45:30.", "2026-13-01T00:00:00.0000000",
    "2026-11-12T25:00:00.0000000", "2026-11-31T00:00:00.0000000", "2026-11-12T24:00:00.0000000",
    " 2026-11-12T00:00:00.0000000", "2026-11-12T00:00:00.0000000 ", "2026-11-12T00:00:00.0000000\n",
    "2026-11-12T13:45:30.12a", "2026-11-12T13:45:30.1234567Z+00:00", "2026-11-12T13:45:30+00:00Z",
    "2026-11-12T13:45:30.1234567+24:00", "２０２６-11-12T00:00:00.0000000", "not a date", "",
]


def _parse_outcome(parse, text):
    """repr() of the parsed value (date, time, fraction and tzinfo), or the
    exception type."""
    try:
        return repr(parse(text))
    except ValueError:
        return "ValueError"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="the identity is with Python 3.11+'s fromisoformat")
@pytest.mark.parametrize("text", ISO_FORMS)
def test_the_parse_helper_gives_exactly_what_fromisoformat_gives_on_python_311_and_later(text):
    """The version freeze: on 3.11+ the helper reads every form exactly as
    datetime.fromisoformat alone did before it existed, or fails as it did."""
    assert _parse_outcome(current._parse_iso_datetime, text) == _parse_outcome(dt.datetime.fromisoformat, text)


@pytest.mark.parametrize("text, expected", POWERSHELL_FORMS)
def test_powershell_timestamps_parse_to_the_same_value_on_every_python(text, expected):
    """On 3.9 and 3.10 too: the CI's 3.9 job runs this with the real 3.9 parser."""
    parsed = current._parse_iso_datetime(text)
    assert parsed == expected
    assert parsed.utcoffset() == expected.utcoffset()


@pytest.mark.parametrize("text, expected", POWERSHELL_FORMS)
def test_normalized_timestamps_fit_the_python_39_fromisoformat_grammar(text, expected):
    normalized = current._normalize_iso_datetime(text)
    assert PY39_FROMISOFORMAT.fullmatch(normalized), normalized
    parsed = dt.datetime.fromisoformat(normalized)  # what any version's parser reads from it
    assert (parsed, parsed.utcoffset()) == (expected, expected.utcoffset())


def test_raw_powershell_timestamps_do_not_fit_the_python_39_grammar():
    """Why the helper is needed: these are what the 3.9 parser rejected."""
    for text in ("2026-11-12T00:00:00.0000000", "2026-11-12T00:00:00.0000000-05:00",
                 "2026-11-12T13:45:30Z"):
        assert not PY39_FROMISOFORMAT.fullmatch(text)


def test_the_helper_leaves_other_forms_and_non_strings_alone():
    for text in ("2026-11-12", "20261112T134530", "2026-11-12T13:45:30,123", "2026-11-12T13:45:30.Z",
                 "2026-11-12t13:45:30.1234567", "not a date", ""):
        assert current._normalize_iso_datetime(text) == text
    with pytest.raises(TypeError):  # as fromisoformat itself raises for a non-string
        current._parse_iso_datetime(20261112)


@pytest.mark.parametrize("iso, status, days", [
    ("2026-11-12T00:00:00.0000000", Status.PASS, 11),
    ("2026-11-12T00:00:00.0000000-05:00", Status.PASS, 11),
    ("2026-11-12T00:00:00.0000000Z", Status.PASS, 11),
    ("2026-10-24T00:00:00.0000000", Status.PASS, 30),     # on the 30-day limit
    ("2026-10-23T23:59:59.9999999", Status.FAIL, 31),     # one day past it
])
def test_cur01_windows_reads_powershell_7_digit_timestamps(iso, status, days, real_clock):
    real_clock(REAL_CLOCKS[1])
    result = _cur01_windows(iso)
    assert result.status == status
    if status == Status.PASS:
        expected = f"Windows Update service active; last successful update installed {days} day(s) ago."
    else:
        expected = (f"Windows Update service active, but last successful update was {days} day(s) ago, "
                    f"exceeding the 30-day policy.")
    assert result.detail == expected + LABEL


class _Python39DateTime(dt.datetime):
    """datetime as Python 3.9 and 3.10 read ISO strings: the documented
    grammar only. (For a string in that grammar they give the value 3.11+
    gives.)"""

    @classmethod
    def fromisoformat(cls, text):
        if not isinstance(text, str) or not PY39_FROMISOFORMAT.fullmatch(text):
            raise ValueError(f"Invalid isoformat string: {text!r}")
        return dt.datetime.fromisoformat(text)


def test_cur01_windows_under_python_39_parsing(monkeypatch, real_clock):
    """The CC-04 failure and its fix, reproduced on any interpreter: under
    3.9's parser the raw 7-digit timestamp is rejected (CUR-01 used to report
    ERROR), and CUR-01 now reads it."""
    monkeypatch.setattr(current, "datetime", types.SimpleNamespace(datetime=_Python39DateTime,
                                                                    timezone=dt.timezone))
    real_clock(REAL_CLOCKS[1])
    with pytest.raises(ValueError):
        current.datetime.datetime.fromisoformat("2026-11-12T00:00:00.0000000")
    for iso in ("2026-11-12T00:00:00.0000000", "2026-11-12T00:00:00.0000000-05:00",
                "2026-11-12T00:00:00.0000000Z"):
        result = _cur01_windows(iso)
        assert (result.status, result.detail) == (
            Status.PASS, "Windows Update service active; last successful update installed "
                         "11 day(s) ago." + LABEL), iso
    assert _cur01_windows("2026-11-12T13:45:30.Z").status == Status.ERROR  # still not a 3.9 form


def test_label_only_on_results_that_report_an_age():
    as_of = {"as_of": AS_OF}
    not_performed = _by_id(assessed.evaluate("x", dict(as_of, attestation={
        "vulnerability_scanning": {"performed": False}})).checks, "ASM-01")
    no_date = _by_id(assessed.evaluate("x", dict(as_of, attestation={
        "compliance_assessment": {"performed": True}})).checks, "ASM-02")
    bad_date = _by_id(assessed.evaluate("x", dict(as_of, attestation={
        "vulnerability_scanning": {"performed": True, "last_scan": "soon", "interval_days": 30}})).checks,
        "ASM-01")
    facts = {"os": {"platform": "ubuntu"}, "system_info": {}, "deb_packages": []}
    no_review = _by_id(inventoried.evaluate("x", dict(as_of, facts=facts, inventory_record={
        "device_id": "H1", "tracked": True})).checks, "INV-04")
    results = [not_performed, no_date, bad_date, no_review,
               _cur01_linux(dt.datetime(2026, 11, 20, tzinfo=UTC), timer="inactive"),
               _cur01_linux(None),
               _cur01_windows("2026-11-20T00:00:00", service_status="STOPPED"),
               _cur01_windows(None)]
    for result in results:
        assert "(as of" not in result.detail, result


# ---------------------------------------------------------------- miccmac.clock

def test_reference_now_is_the_last_moment_of_the_as_of_day_in_utc():
    now = clock.reference_now({"as_of": AS_OF})
    assert now == dt.datetime(2026, 11, 23, 23, 59, 59, 999999, tzinfo=UTC)
    assert now.utcoffset() == dt.timedelta(0)
    assert clock.reference_date({"as_of": AS_OF}) == AS_OF
    assert clock.as_of_label({"as_of": AS_OF}) == LABEL


def test_reference_date_and_now_fall_back_to_the_real_clock(real_clock):
    real_clock(REAL_CLOCKS[1])
    for context in (None, {}, {"as_of": None}, {"facts": {}}):
        assert clock.reference_date(context) == REAL_CLOCKS[1].date()
        assert clock.reference_now(context) == REAL_CLOCKS[1]
        assert clock.as_of_label(context) == ""
    assert clock.now_utc() == REAL_CLOCKS[1]


def test_utc_timestamps_round_trip():
    moment = dt.datetime(2026, 11, 23, 19, 5, 7, 123456, tzinfo=UTC)
    assert clock.format_utc(moment) == "2026-11-23T19:05:07Z"
    eastern = dt.datetime(2026, 11, 23, 14, 5, 7, tzinfo=dt.timezone(dt.timedelta(hours=-5)))
    assert clock.format_utc(eastern) == "2026-11-23T19:05:07Z"
    assert clock.parse_utc("2026-11-23T19:05:07Z") == moment.replace(microsecond=0)
    for bad in ("2026-11-23T19:05:07", "2026-11-23 19:05:07Z", "2026-11-23T19:05:07+00:00",
                "2026-11-31T19:05:07Z", None):
        with pytest.raises(ValueError):
            clock.parse_utc(bad)


def test_parse_as_of_accepts_exactly_yyyy_mm_dd():
    assert clock.parse_as_of("2026-11-23") == AS_OF
    assert clock.parse_as_of("2028-02-29") == dt.date(2028, 2, 29)


@pytest.mark.parametrize("text", [
    "2026-11-5", "2026-1-05", "2026/11/23", "20261123", "2026-11-23T00:00:00", "2026-11-23 ",
    " 2026-11-23", "2026-11-23\n", "2026-02-30", "2026-13-01", "2026-00-10", "23-11-2026",
    "", "today", "２０２６-11-23",
])
def test_parse_as_of_rejects_anything_else(text):
    with pytest.raises(ValueError):
        clock.parse_as_of(text)


# ---------------------------------------------------------------- the CLI

LINUX_FACTS = {
    "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "resolute"},
    "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                    "hardware_serial": ""},
    "deb_packages": [{"name": "bash", "version": "5.2"}],
    "systemd_units": {"systemd-journald.service": {"active_state": "active"},
                      "apt-daily-upgrade.timer": {"active_state": "active"}},
    "rsyslog_forwarding_configured": False, "root_locked": True, "sudo_users": ["assessor"],
    "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"}],
    "hardening_sysctls": {}, "apt_sources": ["http://archive.ubuntu.com/ubuntu"],
    "apt_update_stamp_mtime": int(dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC).timestamp()),
    "platform_info": {}, "expired_certificates": [],
}
ATTESTATION = {
    "vulnerability_scanning": {"performed": True, "last_scan": "2026-11-03", "interval_days": 30},
    "compliance_assessment": {"performed": True, "last_assessment": "2026-08-01", "interval_days": 90},
}
INVENTORY_RECORD = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-09-01"}


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Input files in tmp_path and a fake Linux connector (the class cli.py
    imports); returns the list of collect_facts calls."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "attestation.json").write_text(json.dumps(ATTESTATION), encoding="utf-8")
    (tmp_path / "inventory-record.json").write_text(json.dumps(INVENTORY_RECORD), encoding="utf-8")
    calls = []

    class FakeConnector:
        def __init__(self, ssh_user, ssh_key_path, port=22):
            pass

        def collect_facts(self, target, extended=False):
            calls.append((target, extended))
            return json.loads(json.dumps(LINUX_FACTS))

    monkeypatch.setattr("miccmac.connectors.ssh_osquery.SSHOsqueryConnector", FakeConnector)
    return calls


LIVE_ARGS = [
    "assess", "192.0.2.10", "--connector", "ssh-osquery",
    "--ssh-user", "assessor", "--ssh-key", "keys/id_ed25519",
    "--attestation", "attestation.json", "--inventory-record", "inventory-record.json",
    "--methodology", "cmmi", "--format", "json",
]


def _details(data: dict) -> dict:
    return {c["check_id"]: c["detail"] for p in data["properties"] for c in p["checks"]}


def test_cli_as_of_end_to_end_same_output_under_two_real_clocks(lab, real_clock, capsys):
    outputs = []
    for moment in REAL_CLOCKS:
        real_clock(moment)
        # --stdout added deliberately: a --connector run with --as-of now
        # needs -o or --stdout (V1-N8; tests/test_output_safety.py).
        assert main(LIVE_ARGS + ["--as-of", "2026-11-23", "--stdout"]) == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        outputs.append(json.loads(captured.out))

    for data, moment in zip(outputs, REAL_CLOCKS):
        provenance = data["provenance"]
        assert provenance["as_of"] == "2026-11-23"
        assert provenance["as_of_source"] == "cli"
        # The only real-clock readings: when the run started and when collection finished.
        assert provenance.pop("run_at_utc") == clock.format_utc(moment)
        assert provenance.pop("facts_collected_at_utc") == clock.format_utc(moment)
    assert outputs[0] == outputs[1]

    details = _details(outputs[0])
    assert details["INV-04"] == "Inventory record last reviewed 83 day(s) ago (policy: 90)." + LABEL
    assert details["ASM-01"] == "Vulnerability scanning last performed 20 day(s) ago (policy: 30)." + LABEL
    assert details["ASM-02"].endswith("exceeding the 90-day policy interval." + LABEL)
    assert details["CUR-01"] == ("apt-daily-upgrade.timer active; last successful apt update "
                                 "3 day(s) ago." + LABEL)
    assert lab == [("192.0.2.10", False), ("192.0.2.10", False)]


def test_cli_without_as_of_uses_the_real_clock_and_adds_no_label(lab, real_clock, capsys):
    real_clock(dt.datetime(2026, 11, 23, 12, 0, tzinfo=UTC))
    assert main(LIVE_ARGS) == 0
    data = json.loads(capsys.readouterr().out)
    assert (data["provenance"]["as_of"], data["provenance"]["as_of_source"]) == (None, None)
    details = _details(data)
    assert details["INV-04"] == "Inventory record last reviewed 83 day(s) ago (policy: 90)."
    assert details["CUR-01"] == "apt-daily-upgrade.timer active; last successful apt update 3 day(s) ago."
    assert not any("(as of" in detail for detail in details.values())


def test_cli_as_of_alone_changes_no_result(tmp_path, monkeypatch, capsys):
    """CC-06: with no facts and no input file there is nothing for the
    reference date to feed. Every check keeps its placeholder, exactly as in
    the plain run (Claimed and Assessed stay NOT_IMPLEMENTED rather than
    turning NOT_APPLICABLE), and only the provenance block, which records
    the date, is added."""
    monkeypatch.chdir(tmp_path)
    assert main(["assess", "test-device", "--format", "json", "--methodology", "cmmi"]) == 0
    plain = json.loads(capsys.readouterr().out)
    assert main(["assess", "test-device", "--format", "json", "--methodology", "cmmi",
                 "--as-of", "2026-11-23"]) == 0
    dated = json.loads(capsys.readouterr().out)
    provenance = dated.pop("provenance")
    assert (provenance["as_of"], provenance["as_of_source"]) == ("2026-11-23", "cli")
    assert dated == plain
    statuses = {c["check_id"]: c["status"] for p in dated["properties"] for c in p["checks"]}
    assert set(statuses.values()) == {"NOT_IMPLEMENTED"}
    for check_id in ("CLM-01", "CLM-02", "CLM-03", "ASM-01", "ASM-02", "ASM-03"):
        assert statuses[check_id] == "NOT_IMPLEMENTED"


def test_cli_as_of_still_reaches_the_checks_with_only_an_input_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "attestation.json").write_text(json.dumps(ATTESTATION), encoding="utf-8")
    assert main(["assess", "test-device", "--format", "json", "--attestation", "attestation.json",
                 "--as-of", "2026-11-23"]) == 0
    details = _details(json.loads(capsys.readouterr().out))
    assert details["ASM-01"] == "Vulnerability scanning last performed 20 day(s) ago (policy: 30)." + LABEL


@pytest.mark.parametrize("bad", ["2026-11-5", "20261123", "2026-11-23T00:00:00", "2026-02-30", "tomorrow"])
def test_cli_rejects_a_malformed_as_of_before_connecting(bad, lab, capsys):
    assert main(LIVE_ARGS + ["--as-of", bad]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: --as-of must be a date in the form YYYY-MM-DD")
    assert captured.out == ""
    assert lab == []
