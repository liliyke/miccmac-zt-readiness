"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Synthetic study folder for pipeline tests: ``python -m miccmac_study synthetic``.

    python -m miccmac_study synthetic --out DIR [--hosts 5] [--seed 7] [--session-date 2026-11-23]

SYNTHETIC DATA ONLY. Nothing here reads real study data or touches a real
device: the facts, attestations, inventory records, manual verdicts, levels
and register judgments are made up by a seeded random generator, so the
same seed always gives the same data (apart from timestamps).

The folder follows the study layout in formats.py. It is built with the
real instruments and the real miccmac CLI, in the protocol's order, so that
every stage is exercised, including every safeguard a real study meets:

1. study.yaml (synthetic: true, with a declared level_rule: manual
   approved, tool side tool-cutoffs, overall pooled-checks, which is how
   the dummy levels below are made), README-SYNTHETIC.txt and inputs/:
   list-checks.json from `miccmac list-checks --format json`, and a made-up
   attestation and inventory record per host, each marked "synthetic":
   true and named by its role (<H>-attestation.json,
   <H>-inventory-record.json), as the identical-inputs check needs. All of
   them are hashed (`ledger record`, which also keeps a copy of every
   hashed file in ledger-archive/).
2. The tool's verdicts are computed in memory from the made-up facts with
   miccmac.engine, exactly as the CLI computes them later.
3. worksheets/: blank sheets from the worksheet command with --study-config
   (also kept, unchanged, in blank-worksheets/), filled with dummy entries:
   the in-memory verdicts with about 15% changed at random, one check
   UNASSESSED with a reason, levels from the approved 4-bucket rule
   (overall levels pooled over every scorable check), and every cell the
   lint asks for (assessor, level_rule, and a pass criterion, evidence
   steps and procedure source on each check). Every worksheet is hashed
   with `ledger record --kind worksheet`, whose pre-hash lint must find
   nothing, before any tool output exists.
4. outputs/: a made-up facts envelope per host (connector "synthetic"),
   scored by the real CLI in replay mode (--facts, --as-of) for CMMI and
   CISA ZTMM into new files (study runs never overwrite one), then hashed.
5. register/: the register-sheet command (the seal, ledger.seal_status,
   must open: there is no synthetic exemption; opening it appends the
   ledger's "seal opened by register-sheet" row), filled with dummy
   Y/N/UNSURE judgments for every entry (findings and missing-data entries,
   with the optional next_level_accurate and threat_plausible answers from a
   generator of their own) and 0-2 dummy missed gaps per host, then hashed.

The missing-owner profile (H3 in the default kit) also leaves
firmware_currency out of its attestation, after every random draw, so CUR-03
becomes a missing-data entry in both of its outputs and the register sheets,
H2 and health --inputs (which then needs --allow-missing H3:firmware_currency)
see one end to end; every other made-up value stays the same.

The manual side is derived from the tool's own verdicts, so agreement
figures computed from this folder say nothing about the tool. The approved
level rule appears here only to generate dummy levels; it is not part of
any analysis.

The command prints two lines and nothing else: the folder path, and the
next command (agreement) as one line that runs as printed in Windows
PowerShell. That line first sets PYTHONPATH to the folder holding
miccmac_study (the repository), because the study instruments are not
installed with the package.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import io
import json
import os
import random
import shutil
import sys
import time
import uuid
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Union

import miccmac
from miccmac import clock
from miccmac import facts_file as facts_file_mod
from miccmac import provenance
from miccmac.cli import main as miccmac_main
from miccmac.config import Config, ConfigError
from miccmac.engine import run_assessment
from miccmac.metadata import MappingsError
from miccmac.model import PROPERTY_KEYS, Status

from miccmac_study.__main__ import main as study_main
from miccmac_study.formats import (
    CONFIG_FILE,
    DEFAULT_INPUT_DRIVEN_CHECKS,
    DEFAULT_INPUT_DRIVEN_PROPERTIES,
    ENTRY_FINDING,
    ENTRY_MISSING_DATA,
    INPUTS_DIR,
    LEDGER_FILE,
    MISSED_GAPS_COLUMNS,
    OUTPUTS_DIR,
    OVERALL,
    OVERALL_EXCL,
    REGISTER_DIR,
    REGISTER_REVIEW_COLUMNS,
    ROW_CHECK,
    ROW_LEVEL,
    ROW_META,
    SYNTHETIC_BANNER,
    UNASSESSED,
    WORKSHEET_COLUMNS,
    WORKSHEETS_DIR,
    StudyError,
    facts_name,
    load_study_config,
    load_tool_output,
    missed_gaps_name,
    parse_utc_timestamp,
    read_csv,
    read_ledger,
    register_entry_type,
    register_review_name,
    tool_output_name,
    validate_host_code,
    worksheet_name,
    write_csv,
    write_json,
)
from miccmac_study.ledger import STUDY_HOST_CODE
from miccmac_study.worksheet import read_list_checks

PathLike = Union[str, Path]

DEFAULT_HOSTS = 5
MAX_HOSTS = 20
DEFAULT_SEED = 7
DEFAULT_SESSION_DATE = "2026-11-23"
METHODOLOGIES = ("cmmi", "cisa-ztmm")
# Share of dummy manual verdicts changed away from the tool's verdict.
CHANGE_RATE = 0.15

SYNTHETIC_CONNECTOR = "synthetic"
SYNTHETIC_ASSESSOR = "synthetic"
# The worksheet's free-text level_rule meta cell, and the study.yaml level_rule
# block that declares the same rule, so that the pre-hash lint (ledger record
# --kind worksheet) checks every dummy level against the dummy verdicts.
SYNTHETIC_LEVEL_RULE = "approved 4-bucket, overall pooled over all checks (synthetic)"
SYNTHETIC_LEVEL_RULE_CONFIG = {"manual": "approved", "tool_side": "tool-cutoffs", "overall": "pooled-checks"}
UNASSESSED_REASON = "synthetic: the evidence source was not reachable during this pass"
README_NAME = "README-SYNTHETIC.txt"
BLANK_WORKSHEETS_DIR = "blank-worksheets"
LIST_CHECKS_NAME = "list-checks.json"
# An extended-fact item a Windows 11 host fails to collect (an SSH session
# without elevation cannot run auditpol), as the connector records it, so
# that health shows its "not collected" line in a rehearsal.
NOT_COLLECTED_ITEM = "audit_policy"
NOT_COLLECTED_ERROR = ("ConnectorError: command failed (exit 1): Error 0x00000522 occurred: A required privilege "
                       "is not held by the client.")

# Host profiles, given to the hosts in turn.
PROFILES = ("current", "stale", "missing-owner")
_PROFILE_TEXT = {
    "current": "scan, assessment, inventory review and last OS update all within their policy limits",
    "stale": "scan, assessment, inventory review and last OS update all past their policy limits",
    "missing-owner": ("no business owner assigned; no firmware_currency attestation, so CUR-03 becomes a "
                      "missing-data register entry; other dates at random"),
}
# The attestation entry the missing-owner profile leaves out (after every draw).
OMITTED_ATTESTATION_ENTRY = "firmware_currency"
_PLATFORM_TEXT = {
    "linux": "Linux (Ubuntu 26.04) facts",
    "windows-11": "Windows 11 Enterprise facts",
    "windows-server": "Windows Server 2025 Standard facts",
}
# How a dummy verdict changes when it is changed (neighbouring answers first).
_ALTERNATIVES = {
    "PASS": ("PARTIAL", "FAIL"),
    "PARTIAL": ("PASS", "FAIL"),
    "FAIL": ("PARTIAL", "PASS"),
    "NOT_APPLICABLE": ("FAIL", "PASS"),
}
# How a dummy verdict is written on the worksheet (as an assessor would type it).
_VERDICT_TEXT = {"NOT_APPLICABLE": "N/A"}


class SyntheticError(StudyError):
    """The synthetic study folder could not be built."""


@dataclass
class HostPlan:
    """Everything made up for one host, before any file is written."""
    host: str
    platform: str                  # a key of _PLATFORM_TEXT
    profile: str                   # one of PROFILES
    facts: dict
    attestation: dict
    inventory_record: dict
    statuses: Dict[str, str] = field(default_factory=dict)     # check id -> tool status (in memory)
    properties: Dict[str, str] = field(default_factory=dict)   # check id -> property key
    verdicts: Dict[str, str] = field(default_factory=dict)     # check id -> dummy manual verdict
    reasons: Dict[str, str] = field(default_factory=dict)      # check id -> unassessed reason


# ------------------------------------------------------------------ names and commands
def host_codes(count: int) -> List[str]:
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_HOSTS:
        raise SyntheticError(f"--hosts must be a whole number from 1 to {MAX_HOSTS}")
    return [f"H{number}" for number in range(1, count + 1)]


def attestation_name(host: str) -> str:
    return f"{validate_host_code(host)}-attestation.json"


def inventory_name(host: str) -> str:
    return f"{validate_host_code(host)}-inventory-record.json"


def target_name(host: str) -> str:
    """The target recorded in a host's made-up facts envelope."""
    return f"synthetic-{validate_host_code(host)}"


def replay_argv(host: str, methodology: str, session_date: str, output: Optional[str] = None) -> List[str]:
    """The `miccmac assess` arguments that score a host's saved facts, run
    from the study folder (paths relative to it, as provenance records them)."""
    return [
        "assess", "--facts", f"{OUTPUTS_DIR}/{facts_name(host)}",
        "--attestation", f"{INPUTS_DIR}/{attestation_name(host)}",
        "--inventory-record", f"{INPUTS_DIR}/{inventory_name(host)}",
        "--methodology", methodology, "--risk-register", "--format", "json",
        "--as-of", session_date,
        "-o", output or f"{OUTPUTS_DIR}/{tool_output_name(host, methodology)}",
    ]


@contextlib.contextmanager
def _working_dir(path: Path) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(str(path))
    try:
        yield
    finally:
        os.chdir(previous)


def _call(main: Callable[[List[str]], int], argv: List[str], label: str, cwd: Optional[Path] = None) -> str:
    """Run a command-line entry point with its output captured (this command
    prints only its own two lines) and return what it printed. A non-zero
    exit becomes a SyntheticError carrying what the command reported."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        if cwd is not None:
            stack.enter_context(_working_dir(cwd))
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        try:
            code = main(argv)
        except SystemExit as exc:  # an argparse usage error
            code = exc.code if isinstance(exc.code, int) else 2
    if code:
        message = " ".join(err.getvalue().split()) or "no message"
        raise SyntheticError(f"`{label} {argv[0]}` failed (exit {code}): {message}")
    return out.getvalue()


def _study_command(argv: List[str]) -> str:
    """One `python -m miccmac_study` command."""
    return _call(study_main, argv, "python -m miccmac_study")


def _miccmac_command(argv: List[str], cwd: Path) -> str:
    """One `python -m miccmac` command, run from `cwd`."""
    return _call(miccmac_main, argv, "python -m miccmac", cwd=cwd)


def _record(ledger: Path, host: str, kind: str, paths: Sequence[Path], note: str = "") -> None:
    argv = ["ledger", "record", "--ledger", str(ledger), "--host", host, "--kind", kind]
    if note:
        argv += ["--note", note]
    _study_command(argv + [str(path) for path in paths])


# ------------------------------------------------------------------ random helpers
def _rng(seed: int, *parts: str) -> random.Random:
    """A random generator for one purpose (and host), fixed by the seed, so
    each part of the data stays the same when another part changes."""
    return random.Random("/".join(["miccmac-synthetic", str(seed)] + list(parts)))


def _chance(rng: random.Random, probability: float) -> bool:
    return rng.random() < probability


def _pick(rng: random.Random, options: Sequence):
    return options[rng.randrange(len(options))]


def _days_before(day: dt.date, days: int) -> dt.date:
    return day - dt.timedelta(days=days)


def _hex(rng: random.Random, digits: int) -> str:
    return f"{rng.getrandbits(4 * digits):0{digits}x}"


def _ok(data: object) -> dict:
    """An extended-fact item that was collected (connectors/base.py format)."""
    return {"ok": True, "data": data}


def _round_trip(value: object) -> object:
    """The value as a JSON file gives it back, which is what the CLI reads."""
    return json.loads(json.dumps(value))


# ------------------------------------------------------------------ made-up facts
def _certificates(rng: random.Random, session: dt.date) -> List[dict]:
    """Every certificate (for the extended facts); the first may be expired."""
    expired = _chance(rng, 0.3)
    certificates = []
    if expired:
        moment = dt.datetime.combine(_days_before(session, 400), dt.time(0, 0), tzinfo=dt.timezone.utc)
        certificates.append({"common_name": "Synthetic Expired Root CA",
                             "not_valid_after": str(int(moment.timestamp())), "sha1": _hex(rng, 40)})
    moment = dt.datetime.combine(_days_before(session, -3650), dt.time(0, 0), tzinfo=dt.timezone.utc)
    certificates.append({"common_name": "Synthetic Root CA", "not_valid_after": str(int(moment.timestamp())),
                         "sha1": _hex(rng, 40)})
    return certificates


def _expired(certificates: List[dict]) -> List[dict]:
    """The expired ones, as the main certificates query reports them."""
    return [{"common_name": c["common_name"], "not_valid_after": c["not_valid_after"]}
            for c in certificates if c["common_name"].startswith("Synthetic Expired")]


def _system_info(rng: random.Random, host: str) -> dict:
    return {
        "hostname": target_name(host).lower(), "uuid": str(uuid.UUID(int=rng.getrandbits(128))),
        "hardware_vendor": "Synthetic Hardware Co.", "hardware_model": "Synthetic VM",
        "hardware_serial": "" if _chance(rng, 0.35) else f"SYN-{host}-0001",
        "cpu_brand": "Synthetic CPU", "physical_memory": "8589934592",
    }


def _update_age(rng: random.Random, profile: str, within_policy: int) -> Optional[int]:
    """Days since the last successful OS update, or None for none recorded:
    within the policy limit for a "current" host, past it for a "stale" one,
    anything (or nothing) otherwise."""
    if profile == "current":
        return rng.randrange(0, within_policy)
    if profile == "stale":
        return rng.randrange(within_policy + 5, 3 * within_policy)
    return None if _chance(rng, 0.15) else rng.randrange(0, 2 * within_policy)


def linux_facts(rng: random.Random, host: str, session: dt.date, profile: str) -> dict:
    """Facts shaped like the ssh-osquery connector's (Linux), with extended facts."""
    units: Dict[str, dict] = {}

    def unit(unit_id: str, state: str) -> None:  # state: active, inactive or not-found
        active = state == "active"
        units[unit_id] = {"id": unit_id, "active_state": "active" if active else "inactive",
                          "sub_state": ("waiting" if unit_id.endswith(".timer") else "running") if active else "dead",
                          "load_state": "not-found" if state == "not-found" else "loaded"}

    unit("systemd-journald.service", "active")
    if _chance(rng, 0.7):
        unit("rsyslog.service", "active")
    unit("osqueryd.service", "active" if _chance(rng, 0.7) else "inactive")
    unit("auditd.service", _pick(rng, ("active", "inactive", "not-found")))
    unit("ufw.service", "active" if _chance(rng, 0.7) else "inactive")
    timer = "active" if profile != "missing-owner" or _chance(rng, 0.6) else "inactive"
    unit("apt-daily-upgrade.timer", timer)

    packages = [{"name": "bash", "version": "5.2.21"}, {"name": "coreutils", "version": "9.4"},
                {"name": "openssh-server", "version": "1:9.6p1"}, {"name": "osquery", "version": "5.12.1"}]
    for name, version, probability in (("ansible", "9.2.0", 0.5), ("openscap-scanner", "1.3.9", 0.4),
                                       ("telnetd", "0.17", 0.25)):
        if _chance(rng, probability):
            packages.append({"name": name, "version": version})
    packages.sort(key=lambda package: package["name"])

    ports = [{"port": "22", "protocol": "6", "address": "0.0.0.0"}]
    if _chance(rng, 0.5):
        ports.append({"port": "5353", "protocol": "17", "address": "0.0.0.0"})
    if _chance(rng, 0.35):
        ports.append({"port": "8080", "protocol": "6", "address": "0.0.0.0"})
    processes = {"22": "sshd", "5353": "avahi-daemon", "8080": "python3"}

    sysctls = {}
    for name, hardened, default in (("kernel.dmesg_restrict", "1", "0"), ("kernel.kptr_restrict", "1", "0"),
                                    ("fs.suid_dumpable", "0", "2"), ("net.ipv4.conf.all.rp_filter", "1", "0")):
        sysctls[name] = hardened if _chance(rng, 0.65) else default

    stamp = None
    age = _update_age(rng, profile, 7)
    if age is not None:
        moment = dt.datetime.combine(_days_before(session, age), dt.time(6, 25), tzinfo=dt.timezone.utc)
        stamp = int(moment.timestamp())
    sources = ["http://archive.ubuntu.com/ubuntu", "http://security.ubuntu.com/ubuntu"]
    if _chance(rng, 0.4):
        sources.append("https://ppa.example.invalid/synthetic/ubuntu")
    certificates = _certificates(rng, session)

    facts = {
        "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "synthetic"},
        "system_info": _system_info(rng, host),
        "deb_packages": packages,
        "systemd_units": units,
        "rsyslog_forwarding_configured": _chance(rng, 0.4),
        "root_locked": _chance(rng, 0.85),
        "sudo_users": ["assessor"] if _chance(rng, 0.9) else [],
        "listening_ports": ports,
        "hardening_sysctls": sysctls,
        "apt_update_stamp_mtime": stamp,
        "apt_sources": sources,
        "platform_info": {"vendor": "Synthetic BIOS", "version": f"1.0.{rng.randrange(1, 9)}",
                          "date": "01/15/2026"},
        "expired_certificates": _expired(certificates),
    }
    facts["extra"] = {
        "osquery_info": _ok([{"version": "5.12.1", "build_platform": "ubuntu", "build_distro": "synthetic"}]),
        "os_version_full": _ok([{"name": "Ubuntu", "version": "26.04", "major": "26", "minor": "4",
                                 "build": "", "platform": "ubuntu", "platform_like": "debian",
                                 "codename": "synthetic"}]),
        "listening_ports_processes": _ok([dict(p, process=processes[p["port"]]) for p in ports]),
        "certificates_all": _ok(certificates),
        "update_units": _ok([
            {"id": "apt-daily-upgrade.timer", "active_state": units["apt-daily-upgrade.timer"]["active_state"],
             "sub_state": units["apt-daily-upgrade.timer"]["sub_state"], "load_state": "loaded"},
            {"id": "apt-daily.timer", "active_state": "active", "sub_state": "waiting", "load_state": "loaded"},
            {"id": "unattended-upgrades.service", "active_state": "active", "sub_state": "running",
             "load_state": "loaded"},
        ]),
        "apt_periodic_config": _ok('APT::Periodic::Update-Package-Lists "1";\n'
                                   'APT::Periodic::Unattended-Upgrade "1";\n'),
        "audit_rules": _ok("cat: /etc/audit/audit.rules: Permission denied\n"),
    }
    return facts


def windows_facts(rng: random.Random, host: str, session: dt.date, server: bool, profile: str) -> dict:
    """Facts shaped like the ssh-osquery-windows connector's, with extended facts."""
    name = "Microsoft Windows Server 2025 Standard" if server else "Microsoft Windows 11 Enterprise"
    services: Dict[str, dict] = {}

    def service(service_name: str, running: bool, start_type: str = "AUTO_START") -> None:
        services[service_name] = {"name": service_name, "status": "RUNNING" if running else "STOPPED",
                                  "start_type": start_type}

    service("EventLog", _chance(rng, 0.95))
    service("mpssvc", True)
    service("osqueryd", _chance(rng, 0.7))
    service("wuauserv", profile != "missing-owner" or _chance(rng, 0.6), "DEMAND_START")
    if _chance(rng, 0.45):
        service("Sysmon64", True)
    if _chance(rng, 0.35):
        service("winlogbeat", True)
    if _chance(rng, 0.1):
        service("TlntSvr", True)

    microsoft = "Microsoft Corporation"
    programs = [{"name": "Microsoft Edge", "version": "131.0.2903.70", "publisher": microsoft},
                {"name": "Microsoft Visual C++ 2022 X64 Minimum Runtime", "version": "14.40.33810",
                 "publisher": microsoft}]
    for program, probability in (
            ({"name": "osquery", "version": "5.12.1", "publisher": "osquery"}, 0.7),
            ({"name": "Microsoft Intune Management Extension", "version": "1.83.107.0", "publisher": microsoft}, 0.5),
            ({"name": "Microsoft Security Compliance Toolkit", "version": "1.0", "publisher": microsoft}, 0.4),
            ({"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"}, 0.4),
            ({"name": "Chocolatey", "version": "2.3.0", "publisher": "Chocolatey Software, Inc."}, 0.3)):
        if _chance(rng, probability):
            programs.append(program)
    programs.sort(key=lambda program: program["name"])

    ports = [{"port": "22", "protocol": "6", "address": "0.0.0.0"},
             {"port": "3389", "protocol": "6", "address": "0.0.0.0"}]
    if _chance(rng, 0.5):
        ports.append({"port": "5985", "protocol": "6", "address": "0.0.0.0"})
    if _chance(rng, 0.3):
        ports.append({"port": "8080", "protocol": "6", "address": "0.0.0.0"})
    processes = {"22": "sshd.exe", "3389": "svchost.exe", "5985": "System", "8080": "synthetic-app.exe"}

    registry = {}
    for setting, hardened, weak in (("EnableLUA", "1", "0"), ("SMB1", "0", "1"),
                                    ("DisableRealtimeMonitoring", "0", "1"), ("NoDriveTypeAutoRun", "255", "145")):
        registry[setting] = hardened if _chance(rng, 0.65) else weak

    installed = None
    hotfixes = []
    age = _update_age(rng, profile, 30)
    if age is not None:
        day = _days_before(session, age)
        installed = f"{day.isoformat()}T00:00:00"
        hotfixes = [{"HotFixID": "KB5000001", "Description": "Update", "InstalledOn": f"{_days_before(day, 30)}T00:00:00"},
                    {"HotFixID": "KB5000002", "Description": "Security Update", "InstalledOn": installed}]
    certificates = _certificates(rng, session)
    updates_running = services["wuauserv"]["status"]

    facts = {
        "os": {"platform": "windows", "name": name, "version": "10.0.26100", "codename": None},
        "system_info": _system_info(rng, host),
        "programs": programs,
        "services": services,
        "local_admins": ["assessor"] if _chance(rng, 0.85) else [],
        "builtin_admin_enabled": _chance(rng, 0.2),
        "firewall_all_profiles_enabled": _chance(rng, 0.75),
        "listening_ports": ports,
        "legacy_features_enabled": list(_pick(rng, ((), (), ("TelnetClient",), ("SMB1Protocol",)))),
        "hardening_registry": registry,
        "last_update_installed_iso": installed,
        "expired_certificates": _expired(certificates),
    }
    au_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
    audit_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"
    tasks = "\\Microsoft\\Windows\\UpdateOrchestrator\\"
    facts["extra"] = {
        "osquery_info": _ok([{"version": "5.12.1", "build_platform": "windows", "build_distro": "10"}]),
        "os_version_full": _ok([{"name": name, "version": "10.0.26100", "major": "10", "minor": "0",
                                 "build": "26100", "platform": "windows", "platform_like": "windows",
                                 "codename": name}]),
        "listening_ports_processes": _ok([dict(p, process=processes[p["port"]]) for p in ports]),
        "certificates_all": _ok(certificates),
        "update_services": _ok([
            {"name": "BITS", "status": "STOPPED", "start_type": "DEMAND_START"},
            {"name": "UsoSvc", "status": "RUNNING", "start_type": "AUTO_START"},
            {"name": "wuauserv", "status": updates_running, "start_type": "DEMAND_START"},
        ]),
        "update_policy_registry": _ok([{"key": au_key, "path": au_key + "\\NoAutoUpdate", "name": "NoAutoUpdate",
                                        "type": "REG_DWORD", "data": "0"}] if _chance(rng, 0.5) else []),
        "update_orchestrator_tasks": _ok([{"name": "Schedule Scan", "path": tasks + "Schedule Scan", "enabled": "1",
                                           "state": "ready", "last_run_time": "0", "next_run_time": "0",
                                           "last_run_code": "0"}]),
        "audit_registry": _ok([{"key": audit_key, "path": audit_key + "\\ProcessCreationIncludeCmdLine_Enabled",
                                "name": "ProcessCreationIncludeCmdLine_Enabled",
                                "data": "1" if _chance(rng, 0.5) else "0"}]),
        "windows_update_results": _ok({"LastSearchSuccessDate": f"{session.isoformat()}T06:00:00.0000000Z",
                                       "LastInstallationSuccessDate": installed}),
        "hotfixes": _ok(hotfixes),
        NOT_COLLECTED_ITEM: _ok("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,"
                                "Exclusion Setting\n"
                                f"{target_name(host).upper()},System,Logon,"
                                "{00000000-0000-0000-0000-000000000000},Success and Failure,\n"),
    }
    if not server:  # Windows 11: this item was not collected (no check reads it)
        facts["extra"][NOT_COLLECTED_ITEM] = {"ok": False, "error": NOT_COLLECTED_ERROR}
    return facts


# ------------------------------------------------------------------ made-up organizational inputs
def make_attestation(rng: random.Random, host: str, session: dt.date, profile: str) -> dict:
    """An attestation file with the fields the checks read (CTL-03, CLM-*,
    ASM-*, CUR-03); the extra "synthetic" key is ignored by every check."""
    stale = profile == "stale"
    purpose: Dict[str, object] = {"documented": True}
    if _chance(rng, 0.7):
        purpose["data_classification"] = _pick(rng, ("internal", "confidential"))
    owner = ({"assigned": False, "name": ""} if profile == "missing-owner"
             else {"assigned": True, "name": f"Synthetic Owner {host}"})
    scan_age = rng.randrange(40, 120) if stale else rng.randrange(1, 28)
    assessment_age = rng.randrange(100, 200) if stale else rng.randrange(5, 85)
    attestation = {
        "synthetic": True,
        "identity_aware_access": {"enabled": _chance(rng, 0.7)},
        "business_owner": owner,
        "system_administrator": {"assigned": True, "name": "assessor"},
        "business_purpose": purpose,
        "vulnerability_scanning": {"performed": True, "last_scan": _days_before(session, scan_age).isoformat(),
                                   "interval_days": 30},
        "compliance_assessment": {"performed": True,
                                  "last_assessment": _days_before(session, assessment_age).isoformat(),
                                  "interval_days": 90},
        "finding_remediation_sla": {"tracked": _chance(rng, 0.75), "sla_days": 30},
        "firmware_currency": {"current": _chance(rng, 0.7)},
    }
    if profile == "missing-owner":
        # Left out after every draw, so the inventory record's draws that follow are unchanged.
        attestation.pop(OMITTED_ATTESTATION_ENTRY)
    return attestation


def make_inventory_record(rng: random.Random, host: str, session: dt.date, profile: str) -> dict:
    """An inventory record with the fields INV-01 and INV-04 read; the extra
    "synthetic" key is ignored by both checks."""
    age = rng.randrange(100, 300) if profile == "stale" else rng.randrange(3, 85)
    return {"synthetic": True, "device_id": target_name(host), "tracked": _chance(rng, 0.9),
            "last_reviewed": _days_before(session, age).isoformat()}


def plan_host(host: str, index: int, seed: int, session: dt.date) -> HostPlan:
    """Made-up facts and inputs for host number `index` (0-based): odd host
    numbers get Linux facts, even ones Windows (alternating Windows 11 and
    Windows Server). The profiles go round in PROFILES order and set how
    recent the dated records and the last OS update are."""
    profile = PROFILES[index % len(PROFILES)]
    facts_rng = _rng(seed, "facts", host)
    if index % 2 == 0:
        platform, facts = "linux", linux_facts(facts_rng, host, session, profile)
    else:
        server = (index // 2) % 2 == 1
        platform = "windows-server" if server else "windows-11"
        facts = windows_facts(facts_rng, host, session, server, profile)
    inputs_rng = _rng(seed, "inputs", host)
    return HostPlan(host=host, platform=platform, profile=profile, facts=facts,
                    attestation=make_attestation(inputs_rng, host, session, profile),
                    inventory_record=make_inventory_record(inputs_rng, host, session, profile))


# ------------------------------------------------------------------ dummy manual side
def compute_tool_verdicts(plan: HostPlan, session: dt.date) -> None:
    """The tool's verdicts for the host, from the engine run the CLI will
    repeat (same facts as read back from JSON, same inputs, same as_of)."""
    context = {"facts": _round_trip(plan.facts), "inventory_record": _round_trip(plan.inventory_record),
               "attestation": _round_trip(plan.attestation), clock.AS_OF_KEY: session}
    assessment = run_assessment(target_name(plan.host), context=context, config=Config())
    for prop in assessment.properties:
        for check in prop.checks:
            if check.status in (Status.ERROR, Status.NOT_IMPLEMENTED):
                raise SyntheticError(f"{plan.host}: the made-up facts give {check.check_id} the status "
                                     f"{check.status.value}; the synthetic generator needs fixing")
            plan.statuses[check.check_id] = check.status.value
            plan.properties[check.check_id] = prop.key


def perturb_verdicts(statuses: Dict[str, str], rng: random.Random,
                     change_rate: float = CHANGE_RATE) -> Dict[str, str]:
    """Dummy manual verdicts: the tool's verdict, changed to a neighbouring
    answer with probability `change_rate`, in the order given."""
    verdicts = {}
    for check_id, status in statuses.items():
        verdict = status
        if rng.random() < change_rate:
            verdict = _pick(rng, _ALTERNATIVES[status])
        verdicts[check_id] = verdict
    return verdicts


def approved_rule_level(verdicts: Sequence[str]) -> str:
    """SYNTHETIC DATA GENERATION ONLY, not analysis: the approved 4-bucket
    level rule applied to dummy verdicts. Pass ratio = (PASS + 0.5 x PARTIAL)
    / scorable checks (PASS, PARTIAL, FAIL); 0 gives 1, under 0.5 gives 2,
    under 1 gives 3, 1 gives 4; nothing scorable gives UNASSESSED."""
    scorable = [v for v in verdicts if v in ("PASS", "PARTIAL", "FAIL")]
    if not scorable:
        return UNASSESSED
    ratio = Fraction(sum(2 if v == "PASS" else 1 if v == "PARTIAL" else 0 for v in scorable), 2 * len(scorable))
    if ratio == 0:
        return "1"
    if ratio < Fraction(1, 2):
        return "2"
    if ratio < 1:
        return "3"
    return "4"


def dummy_levels(plan: HostPlan, input_driven_properties: Sequence[str]) -> Dict[str, str]:
    """Dummy manual level per scope: each property over its own checks,
    overall over every check, and overall_excl_input_driven over the checks
    of the properties that are not input-driven (pooled, not averaged)."""
    excluded = set(input_driven_properties)
    levels = {}
    for key in PROPERTY_KEYS:
        levels[key] = approved_rule_level([v for c, v in plan.verdicts.items() if plan.properties[c] == key])
    levels[OVERALL] = approved_rule_level(list(plan.verdicts.values()))
    levels[OVERALL_EXCL] = approved_rule_level(
        [v for c, v in plan.verdicts.items() if plan.properties[c] not in excluded])
    return levels


def fill_worksheet(path: Path, plan: HostPlan, levels: Dict[str, str]) -> None:
    """Fill a blank worksheet's judgment cells with the dummy entries,
    leaving every other cell exactly as the worksheet command wrote it."""
    rows = read_csv(path, WORKSHEET_COLUMNS)
    for row in rows:
        kind, item = row["row_type"], row["item"]
        if kind == ROW_META and item == "assessor":
            row["value"] = SYNTHETIC_ASSESSOR
        elif kind == ROW_META and item == "level_rule":
            row["value"] = SYNTHETIC_LEVEL_RULE
        elif kind == ROW_CHECK:
            verdict = plan.verdicts[item]
            row["value"] = _VERDICT_TEXT.get(verdict, verdict)
            row["pass_criterion"] = "Synthetic pass criterion (pipeline test)."
            row["evidence_procedure"] = "Synthetic evidence step (pipeline test)."
            row["procedure_source"] = "Synthetic source (pipeline test)."
            row["unassessed_reason"] = plan.reasons.get(item, "")
        elif kind == ROW_LEVEL:
            row["value"] = levels[row["property"]]
    write_csv(path, WORKSHEET_COLUMNS, rows, overwrite=True)


def dummy_review(manual_verdict: Optional[str], rng: random.Random,
                 entry_type: str = ENTRY_FINDING) -> Dict[str, str]:
    """Dummy judgments for one register entry. A finding for a check the
    dummy manual pass found in place (PASS) is judged not accurate; a
    missing-data entry is judged on whether its input was missing (always
    true here) and on its how-to-supply text."""
    missing = entry_type == ENTRY_MISSING_DATA
    accurate = "N" if manual_verdict == "PASS" and not missing else ("Y" if _chance(rng, 0.9) else "N")
    actionable = "Y" if _chance(rng, 0.8) else "N"
    draw = rng.random()
    prioritized = "Y" if draw < 0.7 else ("N" if draw < 0.85 else "UNSURE")
    if missing:
        reason = ("synthetic: the manual pass found the input this entry names" if accurate == "N"
                  else "synthetic: the input is missing, but how to supply it is unclear" if actionable == "N"
                  else "synthetic: the input is missing and the entry says how to supply it")
    elif manual_verdict == "PASS":
        reason = "synthetic: the manual pass found this control in place"
    elif accurate == "N":
        reason = "synthetic: the manual pass did not confirm this finding"
    elif actionable == "N":
        reason = "synthetic: finding confirmed, but the fix is too general to act on"
    else:
        reason = "synthetic: finding confirmed and the fix can be acted on"
    if prioritized == "UNSURE":
        reason += "; priority unclear"
    return {"accurate": accurate, "actionable": actionable, "prioritized": prioritized, "reason": reason}


def dummy_optional_review(rng: random.Random) -> Dict[str, str]:
    """Dummy answers for the optional, descriptive columns (sometimes blank,
    as a reviewer may leave them)."""
    def answer(probability: float) -> str:
        draw = rng.random()
        return "" if draw < 0.2 else ("Y" if draw < 0.2 + 0.8 * probability else "N")
    return {"next_level_accurate": answer(0.9), "threat_plausible": answer(0.8)}


def fill_register_review(path: Path, plan: HostPlan, rng: random.Random,
                         optional_rng: Optional[random.Random] = None) -> None:
    rows = read_csv(path, REGISTER_REVIEW_COLUMNS)
    for row in rows:
        row.update(dummy_review(plan.verdicts.get(row["check_id"]), rng, row.get("entry_type") or ENTRY_FINDING))
        if optional_rng is not None:
            row.update(dummy_optional_review(optional_rng))
    write_csv(path, REGISTER_REVIEW_COLUMNS, rows, overwrite=True)


def fill_missed_gaps(path: Path, plan: HostPlan, finding_ids: Sequence[str], rng: random.Random) -> None:
    """0-2 dummy missed gaps: checks the dummy manual pass judged FAIL or
    PARTIAL that have no finding in the register (no entry, or only a
    missing-data entry, which reports no gap), or a gap outside the checks."""
    candidates = [c for c, v in plan.verdicts.items() if v in ("FAIL", "PARTIAL") and c not in finding_ids]
    rows = read_csv(path, MISSED_GAPS_COLUMNS)
    for row in rows[:rng.randrange(3)]:
        if candidates:
            row["check_id"] = candidates.pop(rng.randrange(len(candidates)))
            row["description"] = "synthetic: the manual pass found a gap here that has no finding in the register"
        else:
            row["description"] = "synthetic: a gap outside the enabled checks"
        row["evidence"] = "synthetic evidence note"
    write_csv(path, MISSED_GAPS_COLUMNS, rows, overwrite=True)


# ------------------------------------------------------------------ timeline
def collection_time(session: dt.date, index: int, now: dt.datetime) -> dt.datetime:
    """When host number `index` (0-based) had its made-up facts "collected":
    on the session date, at 12:00 UTC plus 30 minutes per host, unless that
    is not later than `now` (a session date in the past); then `now`. The
    caller makes `now` later than every worksheet hash, so the facts always
    follow the worksheet hash, as the agreement order check requires."""
    planned = (dt.datetime.combine(session, dt.time(12, 0), tzinfo=dt.timezone.utc)
               + dt.timedelta(minutes=30 * index))
    return planned if planned > now else now


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _wait_past(moment: dt.datetime, limit_seconds: float = 5.0) -> None:
    """Wait until the real clock, in whole seconds, is past `moment`, so every
    timestamp recorded from now on sorts strictly after it."""
    deadline = time.monotonic() + limit_seconds
    while _utc_now() <= moment:
        if time.monotonic() > deadline:
            raise SyntheticError(f"the system clock did not pass {moment.isoformat()}; check the clock")
        time.sleep(0.05)


def _latest_ledger_time(ledger: Path) -> dt.datetime:
    return max(parse_utc_timestamp(row.recorded_at_utc) for row in read_ledger(ledger))


# ------------------------------------------------------------------ text files
def study_config_text(hosts: Sequence[str]) -> str:
    rule = ", ".join(f"{key}: {value}" for key, value in SYNTHETIC_LEVEL_RULE_CONFIG.items())
    return (
        f"# {SYNTHETIC_BANNER}\n"
        "# Written by `python -m miccmac_study synthetic`. These settings exercise every part\n"
        "# of the analysis; they are not the study's decisions.\n"
        f"hosts: [{', '.join(hosts)}]\n"
        "threshold: 0.80\n"
        "primary_methodology: cmmi\n"
        "secondary_methodologies: [cisa-ztmm]\n"
        "manual_max_level: {cmmi: 4, cisa-ztmm: 4}\n"
        "# How the dummy manual levels are made (the pre-hash lint checks them against it);\n"
        "# the tool's levels are compared as the tool reports them.\n"
        f"level_rule: {{{rule}}}\n"
        "input_driven_checks: [" + ", ".join(DEFAULT_INPUT_DRIVEN_CHECKS) + "]\n"
        "input_driven_properties: [" + ", ".join(DEFAULT_INPUT_DRIVEN_PROPERTIES) + "]\n"
        "bootstrap: {iterations: 10000, seed: 20261122, exact_limit: 1000000}\n"
        "weighted_kappa: true\n"
        "synthetic: true\n"
    )


def readme_text(plans: Sequence[HostPlan], seed: int, session: dt.date) -> str:
    hosts = ", ".join(plan.host for plan in plans)
    lines = [
        SYNTHETIC_BANNER,
        "",
        "These are synthetic pipeline-test data, not study results. Nothing here comes from a",
        "real device, a real assessment or a real register review.",
        "",
        f"Generated by: python -m miccmac_study synthetic --hosts {len(plans)} --seed {seed} "
        f"--session-date {session.isoformat()}",
        f"Hosts: {hosts}",
        "",
        "What is made up, and how:",
        "- study.yaml: settings that exercise every part of the analysis (synthetic: true). Its",
        "  level_rule (manual approved, tool side tool-cutoffs, overall pooled-checks) is how the",
        "  dummy levels are made; it is not a study decision.",
        "- inputs/: attestation and inventory-record files, each marked \"synthetic\": true;",
        "  list-checks.json is the real output of `miccmac list-checks --format json`.",
        "- outputs/<H>-facts.json: made-up facts (connector \"synthetic\"); the tool outputs next",
        "  to them were written by the real miccmac CLI replaying those facts (--facts, --as-of).",
        f"  Windows 11 hosts record the extended item {NOT_COLLECTED_ITEM} as not collected, as an",
        "  SSH session without elevation would; no check reads extended facts.",
        "- worksheets/: sheets from the worksheet command, filled with dummy entries. The dummy",
        "  verdicts are the tool's own verdicts with about 15% changed at random, plus one check",
        "  marked UNASSESSED; the dummy levels come from the approved 4-bucket rule applied to them",
        "  (overall levels pooled over every scorable check). Each passed the pre-hash lint.",
        "- blank-worksheets/: the same sheets before the dummy entries (a real study has no such folder).",
        "- register/: sheets from the register-sheet command, with dummy Y/N/UNSURE judgments",
        "  for every entry (findings and missing-data entries, and dummy answers in the optional",
        "  next_level_accurate and threat_plausible columns) and 0-2 dummy missed gaps per host.",
        "- ledger.csv: real SHA-256 hashes of the files above, in the protocol's order. register-sheet",
        "  and agreement record each seal opening there too: a \"seal opened by ...\" row (host STUDY,",
        "  kind protocol) each time they open the seal, so there is one from register-sheet already,",
        "  and agreement adds one per run.",
        "- ledger-archive/: a copy of every hashed file, named by its SHA-256 (made by ledger record).",
        "",
        "Because the manual side is derived from the tool's output, any agreement figure computed",
        "from this folder says nothing about the tool. Use this folder only to check that the",
        "instruments run end to end, and never copy anything from it into a study folder.",
        "",
        "Made-up hosts:",
    ]
    for plan in plans:
        lines.append(f"- {plan.host}: {_PLATFORM_TEXT[plan.platform]}; {plan.profile} profile "
                     f"({_PROFILE_TEXT[plan.profile]}).")
    lines += [
        "",
        f"Facts are dated as collected on {session.isoformat()} (12:00 UTC plus 30 minutes per host),",
        "or at generation time when that date has already passed, so that they always follow the",
        "worksheet hashes in the ledger.",
    ]
    return "\n".join(lines) + "\n"


def _write_text(path: Path, text: str) -> Path:
    """Write text as UTF-8 with LF line ends, refusing to replace a file."""
    if path.exists():
        raise SyntheticError(f"{path} already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


# ------------------------------------------------------------------ building the folder
def _parse_session_date(raw: str) -> dt.date:
    try:
        return clock.parse_as_of(raw)
    except ValueError as exc:
        raise SyntheticError(f"--session-date must be a YYYY-MM-DD date: {exc}") from None


def _prepare_folder(out_dir: PathLike) -> Path:
    root = Path(out_dir)
    if root.exists():
        if not root.is_dir():
            raise SyntheticError(f"{root} exists and is not a folder")
        if any(root.iterdir()):
            raise SyntheticError(f"{root} exists and is not empty; choose a new or empty folder")
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SyntheticError(f"cannot create {root}: {exc}") from exc
    return root.resolve()


def build_synthetic_study(out_dir: PathLike, hosts: int = DEFAULT_HOSTS, seed: int = DEFAULT_SEED,
                          session_date: str = DEFAULT_SESSION_DATE) -> Path:
    """Build the synthetic study folder and return its absolute path. Refuses
    a folder that exists and is not empty. If a step fails, the folder is
    left as it is and the error says so (delete it before running again)."""
    session = _parse_session_date(session_date)
    codes = host_codes(hosts)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise SyntheticError("--seed must be a whole number")
    root = _prepare_folder(out_dir)
    try:
        _build(root, codes, seed, session)
    except (StudyError, ConfigError, MappingsError, OSError) as exc:  # ConfigError: a facts file that cannot be written
        raise SyntheticError(f"{exc} (the folder {root} is incomplete; delete it before running again)") from exc
    return root


def _build(root: Path, codes: Sequence[str], seed: int, session: dt.date) -> None:
    plans = [plan_host(code, index, seed, session) for index, code in enumerate(codes)]
    _write_text(root / README_NAME, readme_text(plans, seed, session))
    config_path = _write_text(root / CONFIG_FILE, study_config_text(codes))
    config = load_study_config(config_path)
    ledger = root / LEDGER_FILE

    list_checks = _write_inputs(root, plans)
    _record(ledger, STUDY_HOST_CODE, "other", [config_path], note="study configuration (synthetic)")
    _record(ledger, STUDY_HOST_CODE, "list-checks", [list_checks], note="miccmac list-checks --format json")
    for plan in plans:
        _record(ledger, plan.host, "input", [root / INPUTS_DIR / attestation_name(plan.host),
                                              root / INPUTS_DIR / inventory_name(plan.host)])

    ids = read_list_checks(list_checks)
    for plan in plans:
        compute_tool_verdicts(plan, session)
        if list(plan.statuses) != ids:
            raise SyntheticError(f"{plan.host}: the engine's checks differ from {LIST_CHECKS_NAME}")
    _make_dummy_verdicts(plans, seed)
    _write_worksheets(root, plans, config.input_driven_properties, list_checks, session)
    for plan in plans:
        _record(ledger, plan.host, "worksheet", [root / WORKSHEETS_DIR / worksheet_name(plan.host)])

    # The seal: no tool output exists until every worksheet is hashed.
    _wait_past(_latest_ledger_time(ledger))
    for index, plan in enumerate(plans):
        _write_outputs(root, plan, index, session)
        _record(ledger, plan.host, "facts", [root / OUTPUTS_DIR / facts_name(plan.host)])
        _record(ledger, plan.host, "tool-output",
                [root / OUTPUTS_DIR / tool_output_name(plan.host, m) for m in METHODOLOGIES])

    _study_command(["register-sheet", "--study-dir", str(root)])
    _fill_register(root, plans, seed)
    for plan in plans:
        _record(ledger, plan.host, "register-review", [root / REGISTER_DIR / register_review_name(plan.host)])
        _record(ledger, plan.host, "missed-gaps", [root / REGISTER_DIR / missed_gaps_name(plan.host)])


def _write_inputs(root: Path, plans: Sequence[HostPlan]) -> Path:
    """inputs/: the enabled check list from the real CLI, and each host's
    made-up attestation and inventory record."""
    text = _miccmac_command(["list-checks", "--format", "json"], cwd=root)
    list_checks = _write_text(root / INPUTS_DIR / LIST_CHECKS_NAME, text)
    for plan in plans:
        write_json(root / INPUTS_DIR / attestation_name(plan.host), plan.attestation)
        write_json(root / INPUTS_DIR / inventory_name(plan.host), plan.inventory_record)
    return list_checks


def _make_dummy_verdicts(plans: Sequence[HostPlan], seed: int) -> None:
    for plan in plans:
        plan.verdicts = perturb_verdicts(plan.statuses, _rng(seed, "verdicts", plan.host))
    rng = _rng(seed, "unassessed")
    plan = plans[rng.randrange(len(plans))]
    check_id = _pick(rng, list(plan.verdicts))
    plan.verdicts[check_id] = UNASSESSED
    plan.reasons[check_id] = UNASSESSED_REASON


def _write_worksheets(root: Path, plans: Sequence[HostPlan], input_driven_properties: Sequence[str],
                      list_checks: Path, session: dt.date) -> None:
    """Blank sheets from the worksheet command (with --study-config, as in
    a real study, so each level row states the study's allowed levels), a
    copy of each kept in blank-worksheets/, then the dummy entries filled in."""
    folder = root / WORKSHEETS_DIR
    argv = ["worksheet", "--list-checks", str(list_checks), "--hosts", ",".join(p.host for p in plans),
            "--out", str(folder), "--session-date", session.isoformat(), "--synthetic",
            "--study-config", str(root / CONFIG_FILE)]
    for methodology in METHODOLOGIES:
        argv += ["--methodology", methodology]
    _study_command(argv)
    blank = root / BLANK_WORKSHEETS_DIR
    blank.mkdir()
    for plan in plans:
        path = folder / worksheet_name(plan.host)
        shutil.copyfile(str(path), str(blank / path.name))
        fill_worksheet(path, plan, dummy_levels(plan, input_driven_properties))


def _write_outputs(root: Path, plan: HostPlan, index: int, session: dt.date) -> None:
    """The host's made-up facts envelope, scored by the real CLI for each
    methodology; the CLI's verdicts must equal the in-memory ones."""
    collected = collection_time(session, index, _utc_now())
    envelope = facts_file_mod.build_envelope(
        plan.facts, tool_version=miccmac.__version__, tool_commit=provenance.tool_commit(),
        connector=SYNTHETIC_CONNECTOR, target=target_name(plan.host),
        collected_at_utc=clock.format_utc(collected), as_of=session,
    )
    (root / OUTPUTS_DIR).mkdir(exist_ok=True)
    facts_file_mod.save_envelope(str(root / OUTPUTS_DIR / facts_name(plan.host)), envelope)
    for methodology in METHODOLOGIES:
        _miccmac_command(replay_argv(plan.host, methodology, session.isoformat()), cwd=root)
        output = load_tool_output(root / OUTPUTS_DIR / tool_output_name(plan.host, methodology))
        if output.statuses() != plan.statuses:
            differing = sorted(c for c in plan.statuses if output.statuses().get(c) != plan.statuses[c])
            raise SyntheticError(f"{plan.host}: the CLI's {methodology} verdicts differ from the in-memory "
                                 f"engine run for {', '.join(differing) or 'the check list'}")


def _fill_register(root: Path, plans: Sequence[HostPlan], seed: int) -> None:
    folder = root / REGISTER_DIR
    for plan in plans:
        rng = _rng(seed, "register", plan.host)
        fill_register_review(folder / register_review_name(plan.host), plan, rng,
                             optional_rng=_rng(seed, "register-optional", plan.host))
        output = load_tool_output(root / OUTPUTS_DIR / tool_output_name(plan.host, METHODOLOGIES[0]))
        finding_ids = [str(entry.get("check_id")) for entry in output.risk_register or []
                       if register_entry_type(entry) == ENTRY_FINDING]
        fill_missed_gaps(folder / missed_gaps_name(plan.host), plan, finding_ids, rng)


# ------------------------------------------------------------------ command line
def powershell_quote(text: str) -> str:
    """`text` as a double-quoted PowerShell string that stays literal: the
    backtick, PowerShell's escape character, escapes itself, $ and "."""
    escaped = text.replace("`", "``").replace("$", "`$").replace('"', '`"')
    return f'"{escaped}"'


def code_folder() -> Path:
    """The folder that holds the miccmac_study package (the repository root
    in a checkout): what PYTHONPATH must name for `-m miccmac_study` to run
    from any other folder, since the instruments are not installed."""
    return Path(__file__).resolve().parent.parent


def next_command(root: Path) -> str:
    """The agreement command for the built folder, as one line that runs as
    printed in Windows PowerShell (5.1 or later): it sets PYTHONPATH for that
    window, then calls this Python by its full path."""
    python = sys.executable or "python"
    return (f"$env:PYTHONPATH = {powershell_quote(str(code_folder()))}; "
            f"& {powershell_quote(python)} -m miccmac_study agreement --study-dir {powershell_quote(str(root))}")


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", required=True, metavar="DIR",
                        help="New (or empty) folder for the synthetic study; keep it outside the repository.")
    parser.add_argument("--hosts", type=int, default=DEFAULT_HOSTS, metavar="N",
                        help=f"Number of made-up hosts, H1..HN (1-{MAX_HOSTS}; default {DEFAULT_HOSTS}).")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help=f"Seed for the made-up data; the same seed gives the same data (default {DEFAULT_SEED}).")
    parser.add_argument("--session-date", default=DEFAULT_SESSION_DATE, metavar="YYYY-MM-DD",
                        help=f"Session date for the worksheets and --as-of (default {DEFAULT_SESSION_DATE}).")


def run(args: argparse.Namespace) -> int:
    root = build_synthetic_study(args.out, hosts=args.hosts, seed=args.seed, session_date=args.session_date)
    print(root)
    print(next_command(root))
    return 0
