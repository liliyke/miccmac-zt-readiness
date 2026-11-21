"""Tests for miccmac_study.agreement (protocol section 8): the seal it waits
for (ledger.seal_status) and the seal-opening row it records, its integrity
checks against the ledger (inputs by role, the pre-registered study.yaml
and sensitivity runs, worksheets hashed and hosts withdrawn after the seal
opened, worksheets recorded with --force, typed levels against the declared
manual rule), the pre-hash worksheet lint (lint_worksheet), and the
study.yaml level_rule settings and decoding it reads (miccmac_study.formats).

Each test builds a small synthetic study folder in tmp_path: worksheets
written with formats.write_csv in the WORKSHEET_COLUMNS layout, tool JSONs
made by running miccmac.engine.run_assessment on fake Linux/Windows facts
(dateless, so verdicts never depend on today's date) with a provenance block
attached, risk registers from miccmac.risk_register.build_risk_register,
input and facts files, and a ledger written in the protocol's order. Rows
the commands append themselves (agreement's seal-opening row, ledger
record, ledger withdraw) get a pinned ledger time after every hand-written
row (the ledger_clock fixture). No network, no real hosts; only synthetic
values. Level-rule expectations are worked out by hand in the comments.
"""
from __future__ import annotations

import copy
import csv
import dataclasses
import datetime as dt
import hashlib
import json
import subprocess
from fractions import Fraction
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest
import yaml

from miccmac.engine import enabled_check_ids, overall_score, readiness_tier, run_assessment, score_property
from miccmac.methodology import apply_methodology, get_methodology
from miccmac.model import Status
from miccmac.risk_register import build_risk_register
from miccmac_study import agreement, formats, ledger, stats
from miccmac_study.__main__ import main

# The real git check, kept before the autouse fixture below replaces it.
REAL_ANALYSIS_TREE_CLEAN = agreement._analysis_tree_clean


@pytest.fixture(autouse=True)
def committed_analysis_code(monkeypatch):
    """Whether miccmac_study is committed depends on the repository at hand,
    so the tests pin it as committed; the tests of the git check itself use
    REAL_ANALYSIS_TREE_CLEAN with a fake git."""
    monkeypatch.setattr(agreement, "_analysis_tree_clean", lambda package_dir: True)


# When the rows that commands append are recorded: agreement's seal-opening row,
# `ledger record` and `ledger withdraw`. After every row StudyBuilder writes (its
# sessions are in late November 2026), so they stay in time order whatever today is.
LEDGER_NOW = "2026-12-01T09:00:00Z"


@pytest.fixture(autouse=True)
def ledger_clock(monkeypatch):
    """The ledger's clock, pinned to LEDGER_NOW; a test moves it on with clock['now'] = ..."""
    clock = {"now": LEDGER_NOW}
    monkeypatch.setattr(ledger, "utc_now_iso", lambda: clock["now"])
    return clock


HOSTS = ("H1", "H2", "H3", "H4", "H5")
SESSION = dt.date(2026, 11, 23)
TOOL_COMMIT = "0123456789abcdef0123456789abcdef01234567"
INPUT_PROPS = ("claimed", "assessed")

# Tool levels the fake facts below produce (asserted in test_fixture_levels).
CMMI_LEVELS = {"monitored": 4, "inventoried": 4, "controlled": 5, "claimed": 4, "minimized": 4,
               "assessed": 3, "current": 4, "overall": 4, "overall_excl_input_driven": 4}


# ------------------------------------------------------------------ fake facts
def linux_facts() -> dict:
    return {
        "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "synthetic"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": "VMware-1"},
        "deb_packages": [{"name": "ansible"}, {"name": "openscap-scanner"}, {"name": "bash"}],
        "systemd_units": {
            "systemd-journald.service": {"active_state": "active"},
            "rsyslog.service": {"active_state": "active"},
            "osqueryd.service": {"active_state": "active"},
            "auditd.service": {"active_state": "active"},
            "ufw.service": {"active_state": "active"},
            "apt-daily-upgrade.timer": {"active_state": "active"},
        },
        "rsyslog_forwarding_configured": False,          # MON-02 FAIL
        "root_locked": True,
        "sudo_users": ["assessor"],
        "listening_ports": [{"port": "22", "protocol": "6", "address": "192.0.2.10"}],
        "hardening_sysctls": {"kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "1"},  # MIN-04 PARTIAL
        "apt_update_stamp_mtime": None,                  # CUR-01 PARTIAL (no date involved)
        "apt_sources": [],                               # CUR-02 NOT_APPLICABLE
        "expired_certificates": [],
    }


def windows_facts() -> dict:
    def running(*names):
        return {n: {"status": "RUNNING", "start_type": "AUTO_START"} for n in names}
    return {
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": "VMware-2"},
        "programs": [
            {"name": "Microsoft Intune Management Extension", "publisher": "Microsoft Corporation"},
            {"name": "Microsoft Security Compliance Toolkit", "publisher": "Microsoft Corporation"},
        ],
        "services": running("EventLog", "osqueryd", "Sysmon", "wuauserv"),
        "local_admins": ["assessor"],
        "builtin_admin_enabled": False,
        "firewall_all_profiles_enabled": True,
        "listening_ports": [{"port": "22", "protocol": "6", "address": "192.0.2.10"}],
        "legacy_features_enabled": [],
        "hardening_registry": {"EnableLUA": "1", "SMB1": "0"},
        "last_update_installed_iso": None,
        "expired_certificates": [],
    }


ATTESTATION = {
    "identity_aware_access": {"enabled": True},
    "business_owner": {"assigned": True, "name": "Example Owner"},
    "system_administrator": {"assigned": True, "name": "assessor"},
    "business_purpose": {"documented": True},            # CLM-03 PARTIAL
    "vulnerability_scanning": {"performed": False},      # ASM-01 FAIL
    "compliance_assessment": {"performed": True},        # ASM-02 PARTIAL
    "finding_remediation_sla": {"tracked": True, "sla_days": 30},
    "firmware_currency": {"current": True},
}

_MANUAL_DEFAULT = {"PASS": "PASS", "PARTIAL": "PARTIAL", "FAIL": "FAIL", "NOT_APPLICABLE": "N/A",
                   "ERROR": "FAIL", "NOT_IMPLEMENTED": "UNASSESSED"}
_ENABLED_IDS: List[str] = []


def enabled_ids() -> List[str]:
    """`miccmac list-checks` for the default configuration (computed once)."""
    if not _ENABLED_IDS:
        _ENABLED_IDS.extend(enabled_check_ids())
    return list(_ENABLED_IDS)


def near_perfect_statuses() -> Dict[str, str]:
    """25 PASS and MON-04 FAIL: monitored 75.0, every other property 100.0,
    tool overall round((75 + 6 x 100) / 7, 1) = 96.4, inside [90, 100)."""
    statuses = {check_id: "PASS" for check_id in enabled_ids()}
    statuses["MON-04"] = "FAIL"
    return statuses


def force_statuses(assessment, statuses: Dict[str, str], methodology: str) -> None:
    """Set check statuses and rescore with miccmac's own functions, so the
    tool JSON stays self-consistent (its levels reproduce)."""
    for prop in assessment.properties:
        for check in prop.checks:
            if check.check_id in statuses:
                check.status = Status(statuses[check.check_id])
        prop.score = score_property(prop)
    assessment.overall_score = overall_score(assessment.properties)
    assessment.readiness_tier = readiness_tier(assessment.overall_score)
    assessment.methodology = apply_methodology(assessment, methodology)


# ------------------------------------------------------------------ study builder
class StudyBuilder:
    """Builds a study folder. Defaults give perfect agreement: manual
    verdicts equal the tool statuses and manual levels equal the tool levels
    (capped at manual_max_level). The ledger holds what the protocol has the
    researcher record, in time order: at setup (the day before the first
    session) study.yaml, inputs/list-checks.json and each host's attestation
    and inventory record; per host its worksheet (generated at 09:00 and
    hashed at 18:00 on its session day) and, after the 19:05 tool run, its
    facts file (and tool outputs with ledger_outputs). Change the
    attributes, then build()."""

    def __init__(self, root: Path, hosts=HOSTS, methodologies=("cmmi",), **config):
        self.root = Path(root)
        self.hosts = list(hosts)
        self.methodologies = list(methodologies)
        self.config = {"hosts": self.hosts, "threshold": 0.8, "primary_methodology": self.methodologies[0],
                       "secondary_methodologies": self.methodologies[1:]}
        self.config.update(config)
        self.facts = {h: (windows_facts() if h == "H5" else linux_facts()) for h in self.hosts}
        self.inventory = {h: {"device_id": f"synthetic-{h}", "tracked": True} for h in self.hosts}
        self.session = {h: SESSION + dt.timedelta(days=i) for i, h in enumerate(self.hosts)}
        self.verdicts: Dict[str, Dict[str, tuple]] = {h: {} for h in self.hosts}   # check -> (value, reason)
        self.levels: Dict[str, Dict[tuple, str]] = {h: {} for h in self.hosts}     # (method, scope) -> value
        self.meta: Dict[str, Dict[str, str]] = {h: {} for h in self.hosts}
        self.provenance: Dict[str, Dict[str, dict]] = {h: {} for h in self.hosts}  # method -> overrides
        self.status_edits: Dict[tuple, str] = {}       # (host, method, check) -> status written to the JSON
        self.ledger = True
        self.ledger_outputs = False                    # also record the sealed tool outputs
        self.ledger_setup = True                       # record study.yaml and inputs/list-checks.json (STUDY)
        self.ledger_inputs = True                      # record each host's input files at setup
        self.ledger_facts = True                       # record each host's facts file after its tool run
        self.ledger_register = False                   # record the register sheets once filled
        self.hashed_at = {h: "T18:00:00Z" for h in self.hosts}
        self.reviews: Dict[str, Dict[str, tuple]] = {}  # host -> check -> (accurate, actionable, prioritized)
        # host -> check -> {optional judgment column: value} (next_level_accurate, threat_plausible)
        self.optional_reviews: Dict[str, Dict[str, Dict[str, str]]] = {}
        self.gaps: Dict[str, List[str]] = {}           # host -> descriptions
        self.skip_outputs: List[tuple] = []            # (host, method) not written
        self.absent: List[str] = []                    # hosts in study.yaml with no file at all
        self.drop_checks: Dict[str, List[str]] = {h: [] for h in self.hosts}   # check rows left off before hashing
        self.inputs_of: Dict[str, str] = {}            # host -> host whose input files its tool run used
        # host -> provenance input key -> the role of the input file given for it (a swap or a duplicate)
        self.run_inputs: Dict[str, Dict[str, str]] = {}
        self.sheet_notes: Dict[str, str] = {}          # host -> note of its worksheet row
        self.cell_edits: Dict[str, Dict[str, Dict[str, str]]] = {h: {} for h in self.hosts}  # check -> column -> value
        self.miccmac_config: Dict[str, Path] = {}      # host -> miccmac config file its tool run used (--config)
        self.study_files: List[Path] = []              # more files recorded at setup as STUDY rows (kind other)
        self.list_checks = enabled_ids()               # inputs/list-checks.json as exported at setup
        self.connectors = {h: ("synthetic" if self.config.get("synthetic") else "ssh-osquery") for h in self.hosts}
        self.forced_statuses: Dict[str, Dict[str, str]] = {}   # host -> check -> status, rescored
        self.assessments: Dict[tuple, object] = {}

    # tool side -------------------------------------------------------
    def assessment(self, host: str, methodology: str):
        key = (host, methodology)
        if key not in self.assessments:
            context = {"facts": copy.deepcopy(self.facts[host]), "attestation": copy.deepcopy(ATTESTATION),
                       "inventory_record": copy.deepcopy(self.inventory[host])}
            assessment = run_assessment("192.0.2.10", context=context, methodology_name=methodology)
            if host in self.forced_statuses:
                force_statuses(assessment, self.forced_statuses[host], methodology)
            self.assessments[key] = assessment
        return self.assessments[key]

    def register_ids(self, host: str) -> List[str]:
        return [e.check_id for e in build_risk_register(self.assessment(host, self.methodologies[0]))]

    def judge_all(self, host: str, answers: Optional[Dict[str, tuple]] = None,
                  default: tuple = ("Y", "Y", "Y")) -> None:
        """A review row for every register entry: `answers` where given, else `default`."""
        answers = answers or {}
        self.reviews[host] = {cid: answers.get(cid, default) for cid in self.register_ids(host)}

    def tool_levels(self, host: str, methodology: str) -> Dict[str, Optional[int]]:
        assessment = self.assessment(host, methodology)
        method = get_methodology(methodology)
        levels = {k: v.level for k, v in assessment.methodology.properties.items()}
        levels["overall"] = assessment.methodology.overall.level
        kept = [p for p in assessment.properties if p.key not in INPUT_PROPS]
        levels["overall_excl_input_driven"] = method.score_overall(overall_score(kept)).level
        return levels

    def manual_cap(self, methodology: str) -> int:
        caps = self.config.get("manual_max_level") or {}
        return caps.get(methodology, len(get_methodology(methodology).levels))

    def input_paths(self, host: str) -> Dict[str, Path]:
        folder = self.root / formats.INPUTS_DIR
        return {"attestation": folder / f"{host}-attestation.json",
                "inventory_record": folder / f"{host}-inventory-record.json"}

    def provenance_block(self, host: str, methodology: str) -> dict:
        ids = enabled_ids()
        day = self.session[host].isoformat()
        facts = self.root / formats.OUTPUTS_DIR / formats.facts_name(host)
        # As typed on the command line (backslashes): agreement matches inputs by hash, never by path.
        files = self.input_paths(self.inputs_of.get(host, host))
        roles = self.run_inputs.get(host, {})
        inputs = {key: {"path": "inputs\\" + files[roles.get(key, key)].name,
                        "sha256": formats.sha256_file(files[roles.get(key, key)])} for key in files}
        settings = self.miccmac_config.get(host)
        config = {"path": settings.name, "sha256": formats.sha256_file(settings)} if settings else None
        block = {
            "provenance_format": formats.PROVENANCE_FORMAT, "tool_version": "0.1.0", "tool_commit": TOOL_COMMIT,
            "tool_tree_clean": True, "python_version": "3.12.0", "platform": "synthetic",
            "run_at_utc": f"{day}T19:05:00Z", "as_of": day, "as_of_source": "cli",
            "methodology": methodology, "risk_register": True, "target": "192.0.2.10",
            "facts_source": "facts-file", "connector": "ssh-osquery", "facts_collected_at_utc": f"{day}T19:00:00Z",
            "facts_file": {"path": f"outputs\\{host}-facts.json", "sha256": formats.sha256_file(facts),
                           "role": "replayed"},
            "inputs": dict(inputs, config=config),
            "enabled_check_ids": ids, "enabled_check_ids_fingerprint": formats.check_ids_fingerprint(ids),
            "os": {"platform": "linux", "name": "Ubuntu", "version": "26.04", "build": None},
            "osquery_version": "5.12.1", "extended_facts": False,
        }
        block.update(self.provenance[host].get(methodology, {}))
        return block

    def facts_envelope(self, host: str) -> dict:
        day = self.session[host].isoformat()
        return {"facts_format": formats.FACTS_FORMAT, "tool_version": "0.1.0", "tool_commit": None,
                "connector": self.connectors[host], "target": "192.0.2.10", "collected_at_utc": f"{day}T19:00:00Z",
                "as_of": day, "facts": self.facts[host]}

    # manual side -----------------------------------------------------
    def worksheet_rows(self, host: str) -> List[dict]:
        primary = self.assessment(host, self.methodologies[0])
        ids = enabled_ids()
        # Generated at step 1 of the session, after Setup recorded the inputs.
        meta = {"worksheet_format": formats.WORKSHEET_FORMAT, "host_code": host,
                "session_date": self.session[host].isoformat(), "assessor": "assessor",
                "level_rule": "approved rule", "methodologies": ";".join(self.methodologies),
                "enabled_checks_fingerprint": formats.check_ids_fingerprint(ids),
                "generated_at_utc": f"{self.session[host].isoformat()}T09:00:00Z", "synthetic": "no"}
        meta.update(self.meta[host])
        rows = [{"row_type": "meta", "item": k, "value": v} for k, v in meta.items()]
        for prop in primary.properties:
            for check in prop.checks:
                if check.check_id in self.drop_checks[host]:
                    continue
                value, reason = self.verdicts[host].get(check.check_id,
                                                        (_MANUAL_DEFAULT[check.status.value], ""))
                if value == "UNASSESSED" and check.check_id not in self.verdicts[host]:
                    reason = "check logic not implemented"
                rows.append(dict({"row_type": "check", "item": check.check_id, "property": prop.key,
                                  "description": check.name, "control_refs": "; ".join(check.control_refs),
                                  "value": value, "pass_criterion": "synthetic criterion",
                                  "evidence_procedure": "synthetic step", "procedure_source": "synthetic source",
                                  "unassessed_reason": reason}, **self.cell_edits[host].get(check.check_id, {})))
        for methodology in self.methodologies:
            tool = self.tool_levels(host, methodology)
            cap = self.manual_cap(methodology)
            for scope in formats.LEVEL_SCOPES:
                default = "" if tool[scope] is None else str(min(tool[scope], cap))
                value = self.levels[host].get((methodology, scope), default)
                rows.append({"row_type": "level", "item": methodology, "property": scope, "value": value})
        return rows

    # writing ---------------------------------------------------------
    def ledger_row(self, when: str, host: str, kind: str, path: Path, note: str = "") -> dict:
        return {"recorded_at_utc": when, "host_code": host, "kind": kind,
                "path": formats.ledger_relpath(self.root / formats.LEDGER_FILE, path),
                "sha256": formats.sha256_file(path), "bytes": path.stat().st_size, "note": note}

    def build(self) -> Path:
        root = self.root
        root.mkdir(parents=True, exist_ok=True)
        config_path = root / formats.CONFIG_FILE
        config_path.write_text(yaml.safe_dump(self.config, sort_keys=False), encoding="utf-8")
        present = [h for h in self.hosts if h not in self.absent]
        setup = (min(self.session.values()) - dt.timedelta(days=1)).isoformat() + "T10:00:00Z"
        list_checks = root / formats.INPUTS_DIR / "list-checks.json"
        list_checks.parent.mkdir(parents=True, exist_ok=True)
        list_checks.write_text(json.dumps(self.list_checks, indent=2) + "\n", encoding="utf-8")
        ledger_rows = []
        if self.ledger_setup:
            ledger_rows.append(self.ledger_row(setup, "STUDY", "other", config_path, "study configuration"))
            ledger_rows.append(self.ledger_row(setup, "STUDY", "list-checks", list_checks))
            ledger_rows.extend(self.ledger_row(setup, "STUDY", "other", path) for path in self.study_files)
        for host in present:
            paths = self.input_paths(host)
            paths["attestation"].write_text(json.dumps(ATTESTATION), encoding="utf-8")
            paths["inventory_record"].write_text(json.dumps(self.inventory[host]), encoding="utf-8")
            if self.ledger_inputs:
                ledger_rows.extend(self.ledger_row(setup, host, "input", path) for path in paths.values())
        for host in present:
            day = self.session[host].isoformat()
            sheet = root / formats.WORKSHEETS_DIR / formats.worksheet_name(host)
            formats.write_csv(sheet, formats.WORKSHEET_COLUMNS, self.worksheet_rows(host))
            ledger_rows.append(self.ledger_row(day + self.hashed_at[host], host, "worksheet", sheet,
                                               self.sheet_notes.get(host, "")))
            methodologies = [m for m in self.methodologies if (host, m) not in self.skip_outputs]
            if methodologies:
                facts = formats.write_json(root / formats.OUTPUTS_DIR / formats.facts_name(host),
                                           self.facts_envelope(host))
                if self.ledger_facts:
                    ledger_rows.append(self.ledger_row(day + "T19:10:00Z", host, "facts", facts))
            for methodology in methodologies:
                output = self.write_output(host, methodology)
                if self.ledger_outputs:
                    ledger_rows.append(self.ledger_row(day + "T19:10:00Z", host, "tool-output", output, "sealed"))
            if host in self.reviews:
                self.write_review(host)
                if self.ledger_register:
                    after = (max(self.session.values()) + dt.timedelta(days=1)).isoformat() + "T10:00:00Z"
                    folder = root / formats.REGISTER_DIR
                    ledger_rows.append(self.ledger_row(after, host, "register-review",
                                                       folder / formats.register_review_name(host)))
                    ledger_rows.append(self.ledger_row(after, host, "missed-gaps",
                                                       folder / formats.missed_gaps_name(host)))
        if self.ledger:
            ordered = sorted(ledger_rows, key=lambda row: row["recorded_at_utc"])   # an append-only ledger
            formats.write_csv(root / formats.LEDGER_FILE, formats.LEDGER_COLUMNS, ordered)
        return root

    def write_output(self, host: str, methodology: str) -> Path:
        assessment = self.assessment(host, methodology)
        data = assessment.to_dict()
        for prop in data["properties"]:
            for check in prop["checks"]:
                edit = self.status_edits.get((host, methodology, check["check_id"]))
                if edit:
                    check["status"] = edit
        data["provenance"] = self.provenance_block(host, methodology)
        register = [e.to_dict() for e in build_risk_register(assessment)]
        path = self.root / formats.OUTPUTS_DIR / formats.tool_output_name(host, methodology)
        return formats.write_json(path, {"assessment": data, "risk_register": register})

    def write_review(self, host: str) -> None:
        register = build_risk_register(self.assessment(host, self.methodologies[0]))
        answers = self.reviews[host]
        rows = []
        for number, entry in enumerate(register, start=1):
            accurate, actionable, prioritized = answers.get(entry.check_id, ("", "", ""))
            rows.append(dict({"host_code": host, "entry_no": number, "check_id": entry.check_id,
                              "property": entry.property_key, "name": entry.name, "tool_status": entry.status.value,
                              "cis_ig": entry.cis_ig, "risk_rating": entry.risk_rating, "detail": entry.detail,
                              "recommended_fix": entry.remediation, "entry_type": entry.entry_type,
                              "accurate": accurate, "actionable": actionable,
                              "prioritized": prioritized, "reason": "synthetic reason" if accurate else ""},
                             **self.optional_reviews.get(host, {}).get(entry.check_id, {})))
        folder = self.root / formats.REGISTER_DIR
        formats.write_csv(folder / formats.register_review_name(host), formats.REGISTER_REVIEW_COLUMNS, rows)
        gaps = [{"host_code": host, "gap_no": i, "check_id": "", "description": text, "evidence": ""}
                for i, text in enumerate(self.gaps.get(host, []), start=1)]
        formats.write_csv(folder / formats.missed_gaps_name(host), formats.MISSED_GAPS_COLUMNS, gaps)


# ------------------------------------------------------------------ helpers
def run_agreement(root: Path, *extra: str) -> int:
    return main(["agreement", "--study-dir", str(root), *extra])


def out_file(root: Path, name: str, synthetic: bool = False, out: str = "analysis") -> Path:
    return root / out / ((agreement.SYNTHETIC_PREFIX if synthetic else "") + name)


def csv_rows(path: Path) -> List[Dict[str, str]]:
    return formats.read_csv(path, ())


def summary(root: Path, synthetic: bool = False) -> dict:
    return json.loads(out_file(root, "summary.json", synthetic).read_text(encoding="utf-8"))


def h1(root: Path, methodology: str, scope: str, measure: str = "within_one", synthetic: bool = False) -> dict:
    rows = csv_rows(out_file(root, "agreement_h1.csv", synthetic))
    return next(r for r in rows if r["methodology"] == methodology and r["scope"] == scope
                and r["measure"] == measure)


def level_row(root: Path, host: str, methodology: str, scope: str) -> dict:
    rows = csv_rows(out_file(root, "host_levels.csv"))
    return next(r for r in rows if r["host"] == host and r["methodology"] == methodology and r["scope"] == scope)


def findings(root: Path, level: str, synthetic: bool = False) -> List[dict]:
    return [r for r in summary(root, synthetic)["integrity"]["checks"] if r["result"] == level]


def details(root: Path, check: str, level: str = "CRITICAL", synthetic: bool = False) -> List[tuple]:
    """(host, detail) of the findings of one integrity check."""
    return [(f["host"], f["detail"]) for f in findings(root, level, synthetic) if f["check"] == check]


def ledger_rows(root: Path) -> List[Dict[str, str]]:
    return csv_rows(root / formats.LEDGER_FILE)


def write_ledger(root: Path, rows: Sequence[Dict[str, object]]) -> None:
    formats.write_csv(root / formats.LEDGER_FILE, formats.LEDGER_COLUMNS, rows, overwrite=True)


def append_row(root: Path, when: str, host: str, kind: str, path: Path, note: str = "",
               sha256: Optional[str] = None) -> None:
    """Append one ledger row as `ledger record` would, at a chosen time."""
    ledger_file = root / formats.LEDGER_FILE
    with open(ledger_file, "a", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerow([when, host, kind, formats.ledger_relpath(ledger_file, path),
                                 sha256 or formats.sha256_file(path), path.stat().st_size, note])


def row_for(root: Path, when: str, host: str, kind: str, path: Path, note: str = "") -> Dict[str, object]:
    """A ledger row for a file as it is now, at a chosen time."""
    return {"recorded_at_utc": when, "host_code": host, "kind": kind,
            "path": formats.ledger_relpath(root / formats.LEDGER_FILE, path), "sha256": formats.sha256_file(path),
            "bytes": path.stat().st_size, "note": note}


def insert_rows(root: Path, *rows: Dict[str, object]) -> None:
    """Rows recorded at their own times, as if appended then (the ledger stays in time order)."""
    write_ledger(root, sorted(ledger_rows(root) + list(rows), key=lambda row: row["recorded_at_utc"]))


def point_outputs_at(root: Path, host: str, key: str, path: Path) -> None:
    """Every tool output of `host` names `path` (its current hash) as its `key` input, as a run given that file."""
    for output in sorted((root / formats.OUTPUTS_DIR).glob(f"{host}-*.json")):
        if output.name == formats.facts_name(host):
            continue
        data = json.loads(output.read_text(encoding="utf-8"))
        data["assessment"]["provenance"]["inputs"][key] = {"path": "inputs\\" + path.name,
                                                           "sha256": formats.sha256_file(path)}
        formats.write_json(output, data, overwrite=True)


# ------------------------------------------------------------------ fixture sanity
def test_fixture_levels(tmp_path):
    builder = StudyBuilder(tmp_path)
    for host in HOSTS:
        assert builder.tool_levels(host, "cmmi") == CMMI_LEVELS


# ------------------------------------------------------------------ level agreement
def test_perfect_agreement(tmp_path):
    root = StudyBuilder(tmp_path / "study").build()
    assert run_agreement(root) == 0
    for scope in agreement.H1_SCOPES:
        row = h1(root, "cmmi", scope)
        assert (row["k"], row["n"], row["rate"], row["meets_threshold"]) == ("5", "5", "1.0000", "yes")
        assert (row["wilson_low"], row["wilson_high"]) == ("0.5655", "1.0000")
        assert h1(root, "cmmi", scope, "exact")["k"] == "5"
        assert h1(root, "cmmi", scope, "exact")["threshold"] == ""
    data = summary(root)
    assert data["integrity"]["status"] == "OK"
    assert data["h2"]["available"] is False
    assert not out_file(root, "register_h2.csv").exists()
    assert csv_rows(out_file(root, "disagreements.csv")) == []
    checks = {r["group"]: r for r in csv_rows(out_file(root, "check_agreement.csv"))}
    assert (checks["device"]["k"], checks["device"]["n"]) == ("80", "80")
    assert (checks["input"]["k"], checks["input"]["n"]) == ("50", "50")
    assert checks["all"]["kappa"] == "1.0000"
    confusion = {r["tool_level"]: r for r in csv_rows(out_file(root, "confusion_levels_cmmi.csv"))}
    assert (confusion["4"]["manual_4"], confusion["5"]["manual_5"], confusion["3"]["manual_3"]) == ("25", "5", "5")
    pooled = {(r["measure"], r["subset"]): r for r in csv_rows(out_file(root, "pooled.csv"))}
    assert (pooled[("within_one", "all_properties")]["k"], pooled[("within_one", "all_properties")]["n"]) == ("35", "35")
    assert pooled[("exact", "excl_input_driven")]["n"] == "25"
    assert pooled[("within_one", "all_properties")]["boot_method"] == "exact"
    assert pooled[("within_one", "all_properties")]["boot_resamples"] == "3125"
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert text.startswith("# MICCMAC agreement analysis")
    assert "With n = 5 hosts, the threshold 0.8000 (= 4/5) needs at least 4 of 5." in text
    assert "## 7. How to hand-check" in text


def test_property_off_by_one_is_within_one_but_not_exact(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H2"][("cmmi", "monitored")] = "3"
    root = builder.build()
    assert run_agreement(root) == 0
    row = level_row(root, "H2", "cmmi", "monitored")
    assert (row["tool_level_used"], row["manual_level"], row["diff"]) == ("4", "3", "1")
    assert (row["exact"], row["within_one"], row["l5_rule_only"]) == ("no", "yes", "no")
    assert (h1(root, "cmmi", "monitored")["k"], h1(root, "cmmi", "monitored", "exact")["k"]) == ("5", "4")
    log = csv_rows(out_file(root, "disagreements.csv"))
    assert [(r["kind"], r["host"], r["item"], r["tool_value"], r["manual_value"]) for r in log] == [
        ("level", "H2", "monitored", "4", "3")]


def test_property_off_by_two_is_not_within_one(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H3"][("cmmi", "assessed")] = "L5"     # tool 3; lenient level syntax
    root = builder.build()
    assert run_agreement(root) == 0
    row = level_row(root, "H3", "cmmi", "assessed")
    assert (row["manual_level"], row["diff"], row["within_one"], row["exact"]) == ("5", "-2", "no", "no")
    assert h1(root, "cmmi", "assessed")["k"] == "4"


def test_level5_rule_only_case(tmp_path):
    builder = StudyBuilder(tmp_path / "study", manual_max_level={"cmmi": 4})
    root = builder.build()        # manual controlled defaults to the cap 4; the tool says 5
    assert run_agreement(root) == 0
    row = level_row(root, "H1", "cmmi", "controlled")
    assert (row["tool_level_used"], row["manual_level"], row["l5_rule_only"]) == ("5", "4", "yes")
    assert (h1(root, "cmmi", "controlled")["k"], h1(root, "cmmi", "controlled", "exact")["k"]) == ("5", "0")
    data = summary(root)
    l5 = {r["scope"]: r for r in data["l5_rule_only"] if r["methodology"] == "cmmi"}
    assert (l5["controlled"]["exact_mismatches"], l5["controlled"]["l5_rule_only"]) == (5, 5)
    assert l5["monitored"]["l5_rule_only"] == 0
    chance = data["chance_baselines"][0]
    assert (chance["within_one_fraction"], chance["exact_fraction"]) == ("11/20", "1/5")
    log = csv_rows(out_file(root, "disagreements.csv"))
    assert len(log) == 5 and all(r["l5_rule_only"] == "yes" and r["item"] == "controlled" for r in log)


def test_unassessed_check_changes_recomputed_tool_level(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.verdicts["H1"]["MON-02"] = ("UNASSESSED", "no access to the log collector")
    builder.levels["H1"][("cmmi", "monitored")] = "5"
    root = builder.build()
    assert run_agreement(root) == 0
    row = level_row(root, "H1", "cmmi", "monitored")
    assert (row["tool_level_reported"], row["tool_level_used"], row["manual_level"]) == ("4", "5", "5")
    assert row["exact"] == "yes" and "MON-02" in row["note"]
    verdict = next(r for r in csv_rows(out_file(root, "check_verdicts.csv"))
                   if r["host"] == "H1" and r["check_id"] == "MON-02")
    assert (verdict["compared"], verdict["agree"]) == ("no", "")
    device = next(r for r in csv_rows(out_file(root, "check_agreement.csv")) if r["group"] == "device")
    assert device["n"] == "79"


def test_both_sides_unassessed_left_out_of_n(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    for check in ("CLM-01", "CLM-02", "CLM-03"):
        builder.verdicts["H3"][check] = ("UNASSESSED", "owner records not available")
    builder.levels["H3"][("cmmi", "claimed")] = "UNASSESSED"
    root = builder.build()
    assert run_agreement(root) == 0
    row = level_row(root, "H3", "cmmi", "claimed")
    assert (row["tool_level_used"], row["manual_level"], row["within_one"], row["exact"]) == (
        "unassessed", "UNASSESSED", "", "")
    assert "left out of n" in row["note"]
    assert (h1(root, "cmmi", "claimed")["k"], h1(root, "cmmi", "claimed")["n"]) == ("4", "4")
    confusion = {r["tool_level"]: r for r in csv_rows(out_file(root, "confusion_levels_cmmi.csv"))}
    assert confusion["unassessed"]["manual_unassessed"] == "1"


def test_one_side_unassessed_counts_as_disagreement(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H4"][("cmmi", "monitored")] = "UNASSESSED"
    root = builder.build()
    assert run_agreement(root) == 0
    row = level_row(root, "H4", "cmmi", "monitored")
    assert (row["within_one"], row["exact"], row["diff"]) == ("no", "no", "")
    assert "counted as a disagreement" in row["note"]
    assert (h1(root, "cmmi", "monitored")["k"], h1(root, "cmmi", "monitored")["n"]) == ("4", "5")
    log = csv_rows(out_file(root, "disagreements.csv"))
    assert [(r["host"], r["item"], r["manual_value"], r["within_one"]) for r in log] == [
        ("H4", "monitored", "UNASSESSED", "no")]


def test_four_of_five_meets_and_three_of_five_does_not(tmp_path):
    builder = StudyBuilder(tmp_path / "four")
    builder.levels["H1"][("cmmi", "minimized")] = "2"     # tool 4: off by two
    root = builder.build()
    assert run_agreement(root) == 0
    row = h1(root, "cmmi", "minimized")
    assert (row["k"], row["n"], row["meets_threshold"]) == ("4", "5", "yes")
    assert (row["wilson_low"], row["wilson_high"]) == ("0.3755", "0.9638")

    builder = StudyBuilder(tmp_path / "three")
    builder.levels["H1"][("cmmi", "minimized")] = "2"
    builder.levels["H2"][("cmmi", "minimized")] = "2"
    root = builder.build()
    assert run_agreement(root) == 0
    row = h1(root, "cmmi", "minimized")
    assert (row["k"], row["n"], row["meets_threshold"]) == ("3", "5", "no")


def test_threshold_override_is_recorded(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H1"][("cmmi", "minimized")] = "2"
    root = builder.build()
    assert run_agreement(root, "--threshold", "0.9") == 0
    row = h1(root, "cmmi", "minimized")
    assert (row["k"], row["threshold"], row["meets_threshold"]) == ("4", "0.9000", "no")
    config = summary(root)["config"]
    assert config["threshold"] == 0.9 and config["config_threshold"] == 0.8
    assert config["threshold_source"].startswith("--threshold")
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "from --threshold (sensitivity check); the study configuration has 0.8000" in text


def test_secondary_methodology_reported_and_labelled(tmp_path):
    root = StudyBuilder(tmp_path / "study", methodologies=("cmmi", "cisa-ztmm")).build()
    assert run_agreement(root) == 0
    assert h1(root, "cisa-ztmm", "overall")["k"] == "5"
    assert out_file(root, "confusion_levels_cisa-ztmm.csv").exists()
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "### 6.1 cisa-ztmm (secondary): within-one-level agreement" in text
    chance = {r["methodology"]: r for r in summary(root)["chance_baselines"]}
    assert chance["cisa-ztmm"]["within_one_fraction"] == "5/8"
    assert chance["cmmi"]["within_one_fraction"] == "13/25"


def test_weighted_kappa_only_when_configured(tmp_path):
    root = StudyBuilder(tmp_path / "off").build()
    assert run_agreement(root) == 0
    assert summary(root)["weighted_kappa"] is None
    root = StudyBuilder(tmp_path / "on", weighted_kappa=True).build()
    assert run_agreement(root) == 0
    rows = {r["subset"]: r for r in summary(root)["weighted_kappa"]}
    assert rows["pooled_all_properties"]["linear_weighted_kappa"] == pytest.approx(1.0)
    assert rows["overall"]["linear_weighted_kappa"] is None      # every overall pair is (4, 4)
    assert "### 5.8 Linear-weighted kappa" in out_file(root, "summary.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------ check agreement
def test_check_verdicts_and_disagreement_log_columns_blank(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.verdicts["H5"]["MIN-01"] = ("FAIL", "")       # tool PASS
    builder.verdicts["H2"]["CUR-02"] = ("NA", "")         # tool NOT_APPLICABLE: an alias, agrees
    builder.levels["H2"][("cmmi", "current")] = "2"
    root = builder.build()
    assert run_agreement(root) == 0
    verdicts = csv_rows(out_file(root, "check_verdicts.csv"))
    assert len(verdicts) == 5 * 26
    cur02 = next(r for r in verdicts if r["host"] == "H2" and r["check_id"] == "CUR-02")
    assert (cur02["manual_verdict"], cur02["agree"]) == ("NOT_APPLICABLE", "yes")
    log = csv_rows(out_file(root, "disagreements.csv"))
    assert [(r["kind"], r["host"], r["item"]) for r in log] == [
        ("level", "H2", "current"), ("check", "H5", "MIN-01")]
    for row in log:
        assert (row["root_cause"], row["action"], row["assessor_error_note"]) == ("", "", "")
    check = log[1]
    assert (check["tool_value"], check["manual_value"], check["methodology"]) == ("PASS", "FAIL", "")
    confusion = {r["tool_status"]: r for r in csv_rows(out_file(root, "confusion_verdicts.csv"))}
    assert confusion["PASS"]["manual_FAIL"] == "1"
    device = next(r for r in csv_rows(out_file(root, "check_agreement.csv")) if r["group"] == "device")
    assert (device["k"], device["n"]) == ("79", "80")


def test_tool_error_status_is_a_warning_and_compared(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.inventory["H2"]["last_reviewed"] = "not-a-date"     # INV-04 ERROR, scored 0 like FAIL
    root = builder.build()
    assert run_agreement(root) == 0
    warnings = findings(root, "WARNING")
    assert any(f["check"] == "tool_status" and f["host"] == "H2" and "INV-04 ERROR" in f["detail"]
               for f in warnings)
    row = next(r for r in csv_rows(out_file(root, "check_verdicts.csv"))
               if r["host"] == "H2" and r["check_id"] == "INV-04")
    assert (row["tool_status"], row["manual_verdict"], row["compared"], row["agree"]) == ("ERROR", "FAIL", "yes", "no")


# ------------------------------------------------------------------ integrity
def test_status_mismatch_between_methodologies_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", methodologies=("cmmi", "cisa-ztmm"))
    builder.status_edits[("H2", "cisa-ztmm", "MON-02")] = "PASS"
    root = builder.build()
    assert run_agreement(root) == 3
    critical = findings(root, "CRITICAL")
    assert any(f["check"] == "consistency" and f["host"] == "H2" and "MON-02 (FAIL vs PASS)" in f["detail"]
               for f in critical)
    assert out_file(root, "summary.md").read_text(encoding="utf-8").startswith(agreement.INTEGRITY_BANNER)
    assert summary(root)["integrity_banner"] == agreement.INTEGRITY_BANNER


def test_as_of_different_from_session_date_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.provenance["H1"]["cmmi"] = {"as_of": "2026-11-24"}
    root = builder.build()
    assert run_agreement(root) == 3
    assert any(f["check"] == "as_of" and f["host"] == "H1" and "2026-11-24" in f["detail"]
               for f in findings(root, "CRITICAL"))


def test_worksheet_edited_after_hashing_keeps_the_seal_closed(tmp_path, capsys):
    # Deliberately changed: this used to run with a CRITICAL ledger_hash (exit 3). The gate is now
    # ledger.seal_status, which never opens while a hashed worksheet differs from its hash (exit 2).
    root = StudyBuilder(tmp_path / "study").build()
    sheet = root / formats.WORKSHEETS_DIR / formats.worksheet_name("H3")
    original = sheet.read_bytes()
    sheet.write_bytes(original.replace(b"synthetic step", b"synthetic step, revised", 1))
    assert run_agreement(root) == 2
    err = capsys.readouterr().err
    assert "H3 (worksheet changed after it was hashed: worksheets/H3-worksheet.csv" in err
    assert "restore the original bytes" in err and "cannot be re-hashed" in err
    assert not (root / formats.ANALYSIS_DIR).exists()
    sheet.write_bytes(original)                      # restored byte for byte: the seal opens again
    assert run_agreement(root) == 0


def test_tool_run_before_worksheet_hashed_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.provenance["H2"]["cmmi"] = {"run_at_utc": "2026-11-24T17:00:00Z"}   # hashed at 18:00
    root = builder.build()
    assert run_agreement(root) == 3
    assert any(f["check"] == "ledger_order" and f["host"] == "H2" and "tool run before" in f["detail"]
               for f in findings(root, "CRITICAL"))


def test_sealed_tool_output_changed_after_hashing_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.ledger_outputs = True
    root = builder.build()
    assert run_agreement(root, "--out", str(root / "clean")) == 0
    output = root / formats.OUTPUTS_DIR / "H2-cmmi.json"
    output.write_text(output.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert run_agreement(root) == 3
    assert any(f["check"] == "ledger_hash" and f["host"] == "H2" and "outputs/H2-cmmi.json changed" in f["detail"]
               for f in findings(root, "CRITICAL"))


def test_sealed_tool_output_recorded_before_worksheet_hash_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.ledger_outputs = True
    builder.hashed_at["H4"] = "T19:20:00Z"       # after the 19:05 run and the 19:10 sealing row
    root = builder.build()
    assert run_agreement(root) == 3
    details = [f["detail"] for f in findings(root, "CRITICAL") if f["check"] == "ledger_order" and f["host"] == "H4"]
    assert any("tool run before the worksheet was hashed" in d for d in details)
    assert any("outputs/H4-cmmi.json was recorded in the ledger at" in d for d in details)


def test_missing_tool_output_is_critical_and_host_left_out(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.skip_outputs.append(("H5", "cmmi"))
    root = builder.build()
    assert run_agreement(root) == 3
    assert any(f["check"] == "files" and f["host"] == "H5" for f in findings(root, "CRITICAL"))
    assert h1(root, "cmmi", "overall")["n"] == "4"
    assert "With n = 4 hosts" in out_file(root, "summary.md").read_text(encoding="utf-8")


def test_missing_verdict_and_level_are_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.verdicts["H1"]["MON-03"] = ("", "")
    builder.levels["H1"][("cmmi", "current")] = ""
    root = builder.build()
    assert run_agreement(root) == 3
    details = [(f["check"], f["detail"]) for f in findings(root, "CRITICAL")]
    assert ("verdicts", "MON-03: missing verdict") in details
    assert ("levels", "missing level(s) for cmmi: current") in details
    row = level_row(root, "H1", "cmmi", "current")
    assert (row["within_one"], row["manual_level"]) == ("no", "")
    verdict = next(r for r in csv_rows(out_file(root, "check_verdicts.csv"))
                   if r["host"] == "H1" and r["check_id"] == "MON-03")
    assert (verdict["compared"], verdict["agree"]) == ("yes", "no")


def test_check_set_mismatch_is_critical(tmp_path):
    # The CUR-04 row is left off before the sheet is hashed (an edit after hashing keeps the seal closed).
    builder = StudyBuilder(tmp_path / "study")
    builder.drop_checks["H4"] = ["CUR-04"]
    root = builder.build()
    assert run_agreement(root) == 3
    assert any(f["check"] == "check_set" and f["host"] == "H4" and "CUR-04" in f["detail"]
               for f in findings(root, "CRITICAL"))


# ------------------------------------------------------------------ blinding gate
def test_study_data_stays_sealed_until_every_worksheet_is_hashed(tmp_path, capsys):
    builder = StudyBuilder(tmp_path / "study")
    builder.ledger = False
    root = builder.build()
    assert run_agreement(root) == 2
    err = capsys.readouterr().err
    assert "sealed" in err and "H1 (worksheet not hashed" in err and "worksheets/H1-worksheet.csv" in err
    assert not (root / formats.ANALYSIS_DIR).exists()


def test_gate_refuses_when_one_worksheet_is_not_hashed(tmp_path, capsys):
    root = StudyBuilder(tmp_path / "study").build()
    ledger = root / formats.LEDGER_FILE
    rows = [r for r in csv_rows(ledger) if r["host_code"] != "H5"]
    formats.write_csv(ledger, formats.LEDGER_COLUMNS, rows, overwrite=True)
    assert run_agreement(root) == 2
    err = capsys.readouterr().err
    assert "H5 (worksheet not hashed" in err and "H1" not in err.split("not yet done for:")[1]
    assert not (root / formats.ANALYSIS_DIR).exists()


def test_synthetic_study_without_ledger_stays_sealed(tmp_path, capsys):
    # Deliberately changed (BI-02): synthetic data used to be exempt from the seal and ran with WARNINGs.
    # There is no exemption now; the synthetic kit hashes every worksheet first and passes the real gate.
    builder = StudyBuilder(tmp_path / "study", synthetic=True)
    builder.ledger = False
    root = builder.build()
    assert run_agreement(root) == 2
    err = capsys.readouterr().err
    assert "sealed" in err and "STUDY (no ledger found at" in err and "H1 (worksheet not hashed" in err
    assert not (root / formats.ANALYSIS_DIR).exists()


SUBSET_CONFIG = "hosts: [H1, H2, H3]\nthreshold: 0.8\nprimary_methodology: cmmi\n"


def test_a_configuration_listing_fewer_hosts_never_opens_the_seal(tmp_path, capsys):
    root = StudyBuilder(tmp_path / "study").build()
    write_ledger(root, [r for r in ledger_rows(root)
                        if not (r["kind"] == "worksheet" and r["host_code"] in ("H4", "H5"))])
    subset = tmp_path / "first-three.yaml"
    subset.write_text(SUBSET_CONFIG, encoding="utf-8")
    assert run_agreement(root, "--config", str(subset), "--out", str(tmp_path / "early")) == 2
    err = capsys.readouterr().err
    assert "H4 (worksheet not hashed" in err and "H5 (worksheet not hashed" in err
    assert "ledger withdraw" in err and "study.yaml" not in err
    assert not (tmp_path / "early").exists()


def test_a_withdrawn_host_is_left_out_with_its_time_and_reason(tmp_path, capsys):
    builder = StudyBuilder(tmp_path / "study")
    builder.absent = ["H5"]
    root = builder.build()
    assert run_agreement(root) == 2                      # H5 not assessed and not withdrawn: still sealed
    err = capsys.readouterr().err
    assert "H5 (no worksheet yet: worksheets/H5-worksheet.csv not found" in err and "ledger withdraw" in err
    append_row(root, "2026-11-29T09:00:00Z", "H5", "protocol", root / formats.CONFIG_FILE,
               note="withdrawn: Windows 11 VM could not be rearmed")
    assert run_agreement(root) == 0
    data = summary(root)
    assert (data["config"]["hosts"], data["config"]["config_hosts"]) == (["H1", "H2", "H3", "H4"], list(HOSTS))
    assert data["config"]["withdrawn"] == {
        "H5": {"recorded_at_utc": "2026-11-29T09:00:00Z", "reason": "Windows 11 VM could not be rearmed"}}
    assert details(root, "hosts", "WARNING") == [
        ("H5", "withdrawn in the ledger at 2026-11-29T09:00:00Z: Windows 11 VM could not be rearmed; left out of "
               "the analysis")]
    # A planned withdrawal (before the seal opened, before any tool output of H5): that WARNING and nothing else.
    assert [(r["check"], r["result"]) for r in data["integrity"]["checks"] if r["result"] != "OK"] == [
        ("hosts", "WARNING")]
    assert data["config"]["sensitivity_run"] is False
    assert h1(root, "cmmi", "overall")["n"] == "4"
    assert "H5" not in {r["host"] for r in csv_rows(out_file(root, "host_levels.csv"))}
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert ("| Withdrawn hosts (ledger withdraw; left out) | H5 (withdrawn 2026-11-29T09:00:00Z: Windows 11 VM "
            "could not be rearmed) |") in text


def test_a_host_outside_the_configuration_is_left_out_with_a_warning(tmp_path):
    # Deliberately changed (V1-N3 b): a --config that leaves hosts out is no longer exit 0. It differs from
    # study.yaml as recorded when the seal opened, so it is a CRITICAL config finding and a labelled sensitivity run.
    root = StudyBuilder(tmp_path / "study").build()     # every host hashed: the seal is open
    subset = tmp_path / "first-three.yaml"
    subset.write_text(SUBSET_CONFIG, encoding="utf-8")
    assert run_agreement(root, "--config", str(subset)) == 3
    assert details(root, "hosts", "WARNING") == [("H4", "has study files but is not in first-three.yaml; left out"),
                                                 ("H5", "has study files but is not in first-three.yaml; left out")]
    assert details(root, "config", "WARNING") == [
        ("", "first-three.yaml was never recorded in the ledger, so the settings used cannot be shown to be the "
             "ones fixed in advance")]
    assert details(root, "config") == [
        ("", "the configuration used (first-three.yaml) differs from study.yaml as it was when the seal first opened "
             "(ledger line 2): hosts: H4, H5 left out; this run is a sensitivity run, not the pre-registered analysis")]
    config = summary(root)["config"]
    assert config["other_hosts"] == ["H4", "H5"]
    assert (config["sensitivity_run"], config["overrides"], config["config_differences"]) == (
        True, [], ["hosts: H4, H5 left out"])
    assert h1(root, "cmmi", "overall")["n"] == "3"
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert ("| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: first-three.yaml differs "
            "from study.yaml as recorded at ledger line 2, when the seal first opened: hosts: H4, H5 left out |") in text


def test_every_host_withdrawn_leaves_nothing_to_analyse(tmp_path, capsys):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.absent = ["H1"]
    root = builder.build()
    append_row(root, "2026-11-25T09:00:00Z", "H1", "protocol", root / formats.CONFIG_FILE, note="withdrawn: VM lost")
    assert run_agreement(root) == 2
    assert "every host in study.yaml is withdrawn in the ledger" in capsys.readouterr().err


# ------------------------------------------------------------------ outputs
def test_synthetic_prefix_and_banner(tmp_path):
    # Deliberately changed (BI-02): one worksheet flag still labels every output SYNTHETIC (fail-safe), but it no
    # longer silently overrides study.yaml synthetic: false; the disagreement is CRITICAL (exit 3, was 0 with
    # WARNINGs for the other hosts).
    builder = StudyBuilder(tmp_path / "study")
    builder.meta["H1"]["synthetic"] = "yes"
    root = builder.build()
    assert run_agreement(root) == 3
    names = sorted(p.name for p in (root / "analysis").iterdir())
    assert names and all(name.startswith("SYNTHETIC-") for name in names)
    text = out_file(root, "summary.md", synthetic=True).read_text(encoding="utf-8")
    assert text.startswith(formats.SYNTHETIC_BANNER + "\n\n" + agreement.INTEGRITY_BANNER)
    raw = out_file(root, "summary.json", synthetic=True).read_text(encoding="utf-8")
    assert list(json.loads(raw))[0] == "banner"
    assert json.loads(raw)["banner"] == formats.SYNTHETIC_BANNER
    assert details(root, "synthetic", synthetic=True) == [
        ("H1", "worksheet says synthetic=yes, but study.yaml says synthetic: false; every output is labelled "
               "SYNTHETIC, because any synthetic marker labels the whole study")]
    assert details(root, "synthetic", "WARNING", synthetic=True) == []


def test_synthetic_markers_that_agree_label_the_outputs_without_a_finding(tmp_path):
    builder = StudyBuilder(tmp_path / "study", synthetic=True)     # facts connectors "synthetic" too
    for host in HOSTS:
        builder.meta[host]["synthetic"] = "yes"
    root = builder.build()
    assert run_agreement(root) == 0
    names = sorted(p.name for p in (root / "analysis").iterdir())
    assert names and all(name.startswith("SYNTHETIC-") for name in names)
    data = summary(root, synthetic=True)
    assert data["integrity"]["status"] == "OK" and data["run"]["synthetic"] is True
    row = next(r for r in data["integrity"]["checks"] if r["check"] == "synthetic")
    assert (row["result"], row["detail"]) == (
        "OK", "synthetic: all 11 markers agree (study configuration, worksheets, facts files)")


def test_synthetic_markers_that_disagree_either_way_are_critical(tmp_path):
    # study.yaml copied from the synthetic kit into a real study: real worksheets and facts.
    builder = StudyBuilder(tmp_path / "copied", hosts=("H1", "H2"), synthetic=True)
    builder.connectors = {"H1": "ssh-osquery", "H2": "ssh-osquery"}
    root = builder.build()
    assert run_agreement(root) == 3
    found = details(root, "synthetic", synthetic=True)
    assert [host for host, _ in found] == ["H1", "H1", "H2", "H2"]
    assert found[0][1].startswith("worksheet says synthetic=no, but study.yaml says synthetic: true; ")
    assert found[1][1].startswith("outputs/H1-facts.json names connector 'ssh-osquery' (not synthetic), but "
                                  "study.yaml says synthetic: true; ")
    # Synthetic facts in a real study.
    builder = StudyBuilder(tmp_path / "facts", hosts=("H1", "H2"))
    builder.connectors["H2"] = "synthetic"
    root = builder.build()
    assert run_agreement(root) == 3
    assert [(h, d.split(";")[0]) for h, d in details(root, "synthetic", synthetic=True)] == [
        ("H2", "outputs/H2-facts.json names connector 'synthetic' (synthetic), but study.yaml says synthetic: false")]


def test_second_run_identical_except_timestamps(tmp_path):
    builder = StudyBuilder(tmp_path / "study", methodologies=("cmmi", "cisa-ztmm"))
    builder.levels["H1"][("cmmi", "monitored")] = "2"
    # Every entry judged: an entry left unjudged is now CRITICAL (exit 3), which is not what this test is about.
    for host in HOSTS:
        builder.judge_all(host, {"MON-02": ("Y", "Y", "Y")}, default=("Y", "N", "UNSURE"))
    root = builder.build()
    assert run_agreement(root) == 0
    assert run_agreement(root, "--out", str(root / "again")) == 0
    first = sorted(p.name for p in (root / "analysis").iterdir())
    assert first == sorted(p.name for p in (root / "again").iterdir())
    # Changed with the seal-opening rows: each run appends its own, so the second run's ledger has one row more.
    rows = len(ledger_rows(root))

    def same(line: str) -> bool:
        return "generated_at_utc" not in line and f"{rows - 1} rows in all" not in line \
            and f"{rows} rows in all" not in line and line.strip() not in (f'"rows": {rows - 1},', f'"rows": {rows},')

    for name in first:
        a = (root / "analysis" / name).read_text(encoding="utf-8").splitlines()
        b = (root / "again" / name).read_text(encoding="utf-8").splitlines()
        assert [l for l in a if same(l)] == [l for l in b if same(l)], name
    assert summary(root)["ledger"]["rows"] == rows - 1
    assert json.loads((root / "again" / "summary.json").read_text(encoding="utf-8"))["ledger"]["rows"] == rows


def test_refuses_to_overwrite_without_flag(tmp_path, capsys):
    root = StudyBuilder(tmp_path / "study").build()
    assert run_agreement(root) == 0
    target = out_file(root, "summary.md")
    before = target.read_bytes()
    assert run_agreement(root) == 2
    assert "refusing to replace" in capsys.readouterr().err
    assert target.read_bytes() == before
    assert run_agreement(root, "--overwrite") == 0


def test_headline_counts_can_be_recounted_from_host_levels(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H1"][("cmmi", "monitored")] = "2"
    builder.levels["H2"][("cmmi", "monitored")] = "UNASSESSED"
    root = builder.build()
    assert run_agreement(root) == 0
    rows = csv_rows(out_file(root, "host_levels.csv"))
    for scope in agreement.H1_SCOPES:
        mine = [r for r in rows if r["methodology"] == "cmmi" and r["scope"] == scope]
        n = sum(1 for r in mine if r["within_one"] in ("yes", "no"))
        k = sum(1 for r in mine if r["within_one"] == "yes")
        row = h1(root, "cmmi", scope)
        assert (row["k"], row["n"]) == (str(k), str(n))


def test_end_to_end_with_real_miccmac_cli_outputs(tmp_path):
    """Tool outputs written by the real CLI (facts replay with --as-of, so no
    connection is made) pass every CRITICAL check and reproduce their levels."""
    from miccmac.cli import main as miccmac_main

    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"), methodologies=("cmmi", "cisa-ztmm"))
    for i, host in enumerate(builder.hosts):
        # Past dates: the CLI stamps run_at_utc with the real clock, after the ledger time.
        builder.session[host] = dt.date(2026, 1, 15) + dt.timedelta(days=i)
    builder.skip_outputs = [(h, m) for h in builder.hosts for m in builder.methodologies]
    builder.levels["H1"][("cmmi", "monitored")] = "3"
    root = builder.build()
    inputs = root / formats.INPUTS_DIR
    inputs.mkdir(exist_ok=True)              # the builder wrote (and hashed) each host's input files there
    attestation = inputs / "attestation.json"
    attestation.write_text(json.dumps(ATTESTATION), encoding="utf-8")
    for host in builder.hosts:
        day = builder.session[host].isoformat()
        facts = root / formats.OUTPUTS_DIR / formats.facts_name(host)
        facts.parent.mkdir(parents=True, exist_ok=True)
        envelope = {"facts_format": formats.FACTS_FORMAT, "tool_version": "0.1.0", "tool_commit": None,
                    "connector": "ssh-osquery", "target": "192.0.2.10", "collected_at_utc": f"{day}T19:00:00Z",
                    "as_of": day, "facts": builder.facts[host]}
        facts.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        inventory = inputs / f"{host}-inventory.json"
        inventory.write_text(json.dumps(builder.inventory[host]), encoding="utf-8")
        for methodology in builder.methodologies:
            output = root / formats.OUTPUTS_DIR / formats.tool_output_name(host, methodology)
            assert miccmac_main(["assess", "--facts", str(facts), "--as-of", day, "--methodology", methodology,
                                 "--risk-register", "--format", "json", "--attestation", str(attestation),
                                 "--inventory-record", str(inventory), "--output", str(output)]) == 0
    assert run_agreement(root) == 0
    checks = summary(root)["integrity"]["checks"]
    assert [r for r in checks if r["result"] == "CRITICAL"] == []
    assert {r["check"]: r["result"] for r in checks}["reproduce"] == "OK"
    # The CLI ran with inputs/attestation.json and inputs/<H>-inventory.json, named otherwise than the hashed
    # inputs/<H>-attestation.json and <H>-inventory-record.json: matched by hash. These facts were never recorded.
    assert [(r["result"], r["host"], r["detail"]) for r in checks if r["check"] == "inputs"] == [
        ("WARNING", h, f"no facts row for {h} in the ledger, so the facts file the tool used cannot be checked")
        for h in ("H1", "H2")]
    row = level_row(root, "H1", "cmmi", "monitored")
    assert (row["tool_level_reported"], row["manual_level"], row["within_one"]) == ("4", "3", "yes")


# ------------------------------------------------------------------ register (H2)
def test_h2_with_a_partly_judged_review(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    # Seven entries per host: MON-02, INV-04, CLM-03, MIN-04, ASM-01, ASM-02, CUR-01.
    builder.reviews["H1"] = {
        "MON-02": ("Y", "Y", "Y"), "INV-04": ("Y", "Y", "Y"), "CLM-03": ("Y", "N", "N"),
        "MIN-04": ("Y", "Y", "UNSURE"), "ASM-01": ("N", "Y", "Y"), "ASM-02": ("Y", "Y", "Y"),
        "CUR-01": ("yes", "yes", "y"),
    }
    builder.reviews["H2"] = {"MON-02": ("Y", "Y", "Y"), "INV-04": ("Y", "", "Y"), "CLM-03": ("N", "N", "N")}
    builder.gaps["H2"] = ["SSH allows password logins", "", "Backup agent not reporting"]
    root = builder.build()
    # Deliberately changed (ST-04): entries not judged are now a CRITICAL integrity problem (exit 3, not 0),
    # because every entry must be judged before the final analysis. The counts are unchanged.
    assert run_agreement(root) == 3
    rows = {r["host"]: r for r in csv_rows(out_file(root, "register_h2.csv"))}
    assert list(rows) == ["H1", "H2", "TOTAL"]
    assert (rows["H1"]["entries"], rows["H1"]["judged"], rows["H1"]["k"]) == ("7", "7", "5")
    assert (rows["H2"]["entries"], rows["H2"]["judged"], rows["H2"]["k"], rows["H2"]["missed_gaps"]) == (
        "7", "2", "1", "2")
    assert (rows["H2"]["not_judged"], rows["TOTAL"]["not_judged"]) == ("5", "5")
    total = rows["TOTAL"]
    assert (total["k"], total["n"], total["meets_threshold"]) == ("6", "9", "no")
    assert (total["prioritized_y"], total["prioritized_n"], total["prioritized_unsure"]) == ("7", "2", "1")
    assert (total["prioritization_k"], total["prioritization_n"]) == ("7", "9")    # UNSURE left out of n
    assert rows["H1"]["meets_threshold"] == ""
    assert [f for f in findings(root, "WARNING") if f["check"] == "register"] == []
    critical = [f for f in findings(root, "CRITICAL") if f["check"] == "register"]
    assert [(f["host"], f["detail"]) for f in critical] == [
        ("H2", "5 of 7 entries not judged; every entry must be judged before the final analysis (judged = "
               "accurate and actionable both answered, or either answered N); not-judged entries are left out of n")]
    h2 = summary(root)["h2"]
    assert h2["available"] is True and (h2["total"]["k"], h2["total"]["n"]) == (6, 9)
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "5 entries are not judged and are left out of n (CRITICAL" in text


def test_register_review_row_without_entry_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.reviews["H1"] = {"MON-02": ("Y", "Y", "Y")}
    root = builder.build()
    review = root / formats.REGISTER_DIR / formats.register_review_name("H1")
    rows = csv_rows(review) + [{"host_code": "H1", "entry_no": "8", "check_id": "MON-01",
                                "accurate": "Y", "actionable": "Y", "prioritized": "Y"}]
    formats.write_csv(review, formats.REGISTER_REVIEW_COLUMNS, rows, overwrite=True)
    assert run_agreement(root) == 3
    assert any(f["check"] == "register" and "MON-01 has no register entry" in f["detail"]
               for f in findings(root, "CRITICAL"))


# ------------------------------------------------------------------ worksheet parsing
def test_parse_worksheet_reports_problems_without_raising(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.verdicts["H1"]["MON-01"] = ("PASSS", "")
    builder.verdicts["H1"]["MON-02"] = ("UNASSESSED", "")
    builder.levels["H1"][("cmmi", "overall_excl_input_driven")] = ""
    builder.levels["H1"][("cmmi", "claimed")] = "7"
    builder.meta["H1"]["host_code"] = "H9"
    root = builder.build()
    config = formats.load_study_config(root / formats.CONFIG_FILE)
    sheet = agreement.parse_worksheet(root / formats.WORKSHEETS_DIR / "H1-worksheet.csv", config)
    found = {(f.check, f.level, f.detail) for f in sheet.findings}
    assert ("verdicts", "CRITICAL", "MON-01: unrecognized verdict 'PASSS'") in found
    assert ("verdicts", "WARNING", "MON-02: UNASSESSED without an unassessed_reason") in found
    assert ("worksheet", "CRITICAL", "host_code is 'H9', expected 'H1'") in found
    assert any(f[0] == "levels" and f[1] == "CRITICAL" and "outside 1-5" in f[2] for f in found)
    assert sheet.session_date == SESSION
    assert sheet.unassessed == ["MON-02"]
    assert sheet.levels["cmmi"]["monitored"] == 4
    assert any("overall_excl_input_driven" in note for note in sheet.notes)


def test_blank_overall_excl_level_skips_only_that_comparison(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H2"][("cmmi", "overall_excl_input_driven")] = ""
    root = builder.build()
    assert run_agreement(root) == 0
    row = level_row(root, "H2", "cmmi", "overall_excl_input_driven")
    assert (row["within_one"], row["tool_level_reported"]) == ("", "")
    assert "skipped" in row["note"]
    assert h1(root, "cmmi", "overall_excl_input_driven")["n"] == "4"
    assert any("H2" in note for note in summary(root)["notes"])


def test_bad_threshold_option_is_a_usage_error(tmp_path, capsys):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    assert run_agreement(root, "--threshold", "1.5") == 2
    assert "at most 1" in capsys.readouterr().err
    assert run_agreement(tmp_path / "nowhere") == 2


# ------------------------------------------------------------------ level_rule in study.yaml
OVERALL_RULES = formats.LEVEL_RULE_VALUES["overall"]


def test_level_rule_defaults_keep_todays_analysis():
    config = formats.study_config_from_dict({"hosts": ["H1"]})
    assert config.level_rule == {"manual": None, "tool_side": "tool-cutoffs", "overall": None}
    assert (config.tool_max_level("cmmi"), config.manual_max("cmmi")) == (5, 5)
    assert (config.tool_max_level("cisa-ztmm"), config.manual_max("cisa-ztmm")) == (4, 4)
    for empty in (None, {}):
        assert formats.study_config_from_dict({"hosts": ["H1"], "level_rule": empty}).level_rule == config.level_rule


def test_config_template_declares_the_level_rule_block_with_todays_defaults():
    text = formats.config_template(["H1", "H2"])
    config = formats.study_config_from_dict(yaml.safe_load(text))
    assert config.level_rule == {"manual": None, "tool_side": "tool-cutoffs", "overall": None}
    assert text.count("DECISION (needs the advisor)") == 3
    for values in formats.LEVEL_RULE_VALUES.values():
        for value in values:
            assert value in text
    assert "20/40/70/90" not in text and "90.0" not in text      # no tool cutoffs in the study configuration


@pytest.mark.parametrize("level_rule, caps, expected", [
    ({"manual": "approved", "tool_side": "approved", "overall": "pooled-checks"}, {"cmmi": 4},
     ({"manual": "approved", "tool_side": "approved", "overall": "pooled-checks"}, 4, 4)),
    ({"manual": " Tool-Cutoffs ", "tool_side": None}, {"cmmi": 5},
     ({"manual": "tool-cutoffs", "tool_side": "tool-cutoffs", "overall": None}, 5, 5)),
    # The manual cap does not follow the tool side: without manual_max_level it stays 5.
    ({"tool_side": "approved", "overall": "step4-rounded"}, None,
     ({"manual": None, "tool_side": "approved", "overall": "step4-rounded"}, 4, 5)),
    ({"manual": "approved", "overall": "mean-of-property-ratios"}, {"cmmi": 4, "cisa-ztmm": 4},
     ({"manual": "approved", "tool_side": "tool-cutoffs", "overall": "mean-of-property-ratios"}, 5, 4)),
])
def test_level_rule_accepted_values(level_rule, caps, expected):
    data = {"hosts": ["H1"], "level_rule": level_rule}
    if caps:
        data["manual_max_level"] = caps
    config = formats.study_config_from_dict(data)
    assert (config.level_rule, config.tool_max_level("cmmi"), config.manual_max("cmmi")) == expected


@pytest.mark.parametrize("level_rule, caps, message", [
    ("approved", None, "'level_rule' must be a mapping"),
    ({"manual": "approved", "tool-side": "approved"}, {"cmmi": 4}, "unknown level_rule key(s): tool-side"),
    ({"manual": "aproved"}, None, "level_rule.manual 'aproved' is not recognized; use one of approved, tool-cutoffs"),
    ({"manual": 4}, None, "level_rule.manual must be one of approved, tool-cutoffs (or null), not 4"),
    ({"tool_side": "cutoffs"}, None, "level_rule.tool_side 'cutoffs' is not recognized"),
    ({"overall": "step4"}, None, "level_rule.overall 'step4' is not recognized"),
    ({"tool_side": "approved"}, None, "level_rule.tool_side approved needs level_rule.overall"),
    ({"tool_side": "approved", "overall": None}, None, "level_rule.tool_side approved needs level_rule.overall"),
    ({"manual": "approved"}, None,
     "level_rule.manual approved assigns manual cmmi levels 1-4, so manual_max_level must set cmmi: 4 "
     "(it is 5, the default when it is not set)"),
    ({"manual": "approved"}, {"cmmi": 5}, "manual_max_level must set cmmi: 4 (it is 5)"),
    ({"manual": "tool-cutoffs"}, {"cmmi": 4}, "manual_max_level must set cmmi: 5 (it is 4)"),
    ({"manual": "approved"}, {"cmmi": 4, "cisa-ztmm": 3}, "manual_max_level must set cisa-ztmm: 4 (it is 3)"),
])
def test_level_rule_rejects_unknown_values_and_contradictions(level_rule, caps, message):
    data = {"hosts": ["H1"], "level_rule": level_rule}
    if caps:
        data["manual_max_level"] = caps
    with pytest.raises(formats.StudyError) as info:
        formats.study_config_from_dict(data)
    assert message in str(info.value)


# ------------------------------------------------------------------ level-rule definitions
def verdict_map(**by_property):
    """check id -> verdict and check id -> property, from verdict lists per property."""
    verdicts, properties = {}, {}
    for prop, values in by_property.items():
        for number, value in enumerate(values, start=1):
            check_id = f"{prop}-{number}"
            verdicts[check_id] = value
            properties[check_id] = prop
    return verdicts, properties


def derive(rule: str, overall_rule: Optional[str], methodology: str = "cmmi", **by_property):
    verdicts, properties = verdict_map(**by_property)
    config = formats.study_config_from_dict({"hosts": ["H1"]})
    return agreement.derive_levels_from_verdicts(verdicts, methodology, rule, overall_rule, config,
                                                 check_properties=properties)


def test_approved_level_buckets_are_exact():
    cases = [(0, 1), (Fraction(1, 8), 2), (Fraction(49, 100), 2), (Fraction(1, 2), 3), (Fraction(7, 8), 3),
             (Fraction(99, 100), 3), (1, 4)]
    assert [agreement.approved_level(ratio) for ratio, _ in cases] == [level for _, level in cases]
    with pytest.raises(ValueError):
        agreement.approved_level(Fraction(3, 2))


# Hand-computed overall levels under the four overall rules. Property levels
# by the approved buckets; each example separates at least two rules.
OVERALL_EXAMPLES = [
    # monitored 0/4 (L1), controlled 1/1 with 3 N/A (L4), current 3/4 (L3):
    #   mean of ratios (0 + 1 + 3/4) / 3 = 7/12 -> 3; pooled 4 PASS of 9 = 4/9 -> 2;
    #   step4-buckets (0 + 1 + 2/3) / 3 = 5/9 -> 3; step4-rounded 1 + round((0 + 3 + 2) / 3 = 5/3) = 3.
    (dict(monitored=["FAIL"] * 4, controlled=["PASS"] + ["NOT_APPLICABLE"] * 3,
          current=["PASS", "PASS", "PASS", "FAIL"]),
     {"monitored": 1, "controlled": 4, "current": 3},
     {"mean-of-property-ratios": 3, "pooled-checks": 2, "step4-buckets": 3, "step4-rounded": 3}),
    # 2/2 (L4), 2/2 (L4), 1/2 (L3): mean of ratios 5/6 -> 3; pooled 5/6 -> 3;
    #   step4-buckets (1 + 1 + 2/3) / 3 = 8/9 -> 3; step4-rounded 1 + round(8/3 = 2.67) = 4.
    (dict(monitored=["PASS", "PASS"], inventoried=["PASS", "PASS"], controlled=["PASS", "FAIL"]),
     {"monitored": 4, "inventoried": 4, "controlled": 3},
     {"mean-of-property-ratios": 3, "pooled-checks": 3, "step4-buckets": 3, "step4-rounded": 4}),
    # 3/8 (L2), 3/8 (L2), 7/8 (L3): mean of ratios 13/24 -> 3; pooled (5 + 3/2) / 12 = 13/24 -> 3;
    #   step4-buckets (1/3 + 1/3 + 2/3) / 3 = 4/9 -> 2; step4-rounded 1 + round(4/3 = 1.33) = 2.
    (dict(monitored=["PASS", "PARTIAL", "FAIL", "FAIL"], inventoried=["PASS", "PARTIAL", "FAIL", "FAIL"],
          controlled=["PASS", "PASS", "PASS", "PARTIAL"]),
     {"monitored": 2, "inventoried": 2, "controlled": 3},
     {"mean-of-property-ratios": 3, "pooled-checks": 3, "step4-buckets": 2, "step4-rounded": 2}),
    # Ties for step4-rounded are rounded half up (Python's round() would give 1 and 3):
    #   L1 + L2: 1 + round(1/2) = 2; mean of ratios (0 + 1/4) / 2 = 1/8 -> 2; pooled 1/6 -> 2; step4 1/6 -> 2.
    (dict(monitored=["FAIL"], inventoried=["PARTIAL", "FAIL"]),
     {"monitored": 1, "inventoried": 2},
     {"mean-of-property-ratios": 2, "pooled-checks": 2, "step4-buckets": 2, "step4-rounded": 2}),
    #   L3 + L4: 1 + round(5/2) = 4; mean of ratios 3/4 -> 3; pooled 2/3 -> 3; step4 (2/3 + 1) / 2 = 5/6 -> 3.
    (dict(monitored=["PASS", "FAIL"], inventoried=["PASS"]),
     {"monitored": 3, "inventoried": 4},
     {"mean-of-property-ratios": 3, "pooled-checks": 3, "step4-buckets": 3, "step4-rounded": 4}),
]


@pytest.mark.parametrize("verdicts, property_levels, overall_levels", OVERALL_EXAMPLES)
def test_four_overall_rules_on_hand_computed_examples(verdicts, property_levels, overall_levels):
    for overall_rule, expected in overall_levels.items():
        levels = derive("approved", overall_rule, **verdicts)
        assert {k: levels[k] for k in property_levels} == property_levels
        assert all(levels[k] is None for k in formats.PROPERTY_KEYS if k not in property_levels)
        # No input-driven property in these examples, so overall_excl equals overall.
        assert (levels["overall"], levels["overall_excl_input_driven"]) == (expected, expected), overall_rule


def test_scorable_statuses_drops_and_missing_verdicts():
    verdicts = dict(monitored=["PASS", "ERROR"],                       # ERROR scores 0
                    inventoried=["NOT_APPLICABLE", "NOT_IMPLEMENTED"],   # nothing scorable: no level
                    controlled=["UNASSESSED", "PASS"],                  # UNASSESSED dropped
                    claimed=["PASS", None])                             # a blank verdict
    approved = derive("approved", "pooled-checks", **verdicts)
    assert (approved["monitored"], approved["inventoried"], approved["controlled"]) == (3, None, 4)   # 1/2, -, 1/1
    assert approved["claimed"] == approved["overall"] == agreement.MANUAL_MISSING
    # claimed is input-driven, so overall_excl does not depend on it: pooled 2 PASS of 3 scorable = 2/3 -> 3.
    assert approved["overall_excl_input_driven"] == 3
    cutoffs = derive("tool-cutoffs", None, **verdicts)
    # miccmac: PASS + ERROR = 50.0 -> 3 (40 <= 50 < 70); 100.0 -> 5; overall_excl mean(50, 100) = 75.0 -> 4.
    assert (cutoffs["monitored"], cutoffs["inventoried"], cutoffs["controlled"]) == (3, None, 5)
    assert cutoffs["claimed"] == cutoffs["overall"] == agreement.MANUAL_MISSING
    assert cutoffs["overall_excl_input_driven"] == 4
    assert derive("approved", None, current=["PARTIAL"])["current"] == 3    # 1/2 is exactly the L3 bound


def test_derive_without_an_overall_rule_and_bad_inputs():
    levels = derive("approved", None, monitored=["PASS"])
    assert levels["monitored"] == 4 and "overall" not in levels and "overall_excl_input_driven" not in levels
    for args in (("approved-ish", None), ("approved", "step4")):
        with pytest.raises(ValueError):
            derive(*args, monitored=["PASS"])
    with pytest.raises(ValueError):
        derive("approved", None, monitored=["N/A"])            # verdicts must be normalized first
    config = formats.study_config_from_dict({"hosts": ["H1"]})
    with pytest.raises(ValueError):
        agreement.derive_levels_from_verdicts({"X-1": "PASS"}, "cmmi", "approved", None, config,
                                              check_properties={"X-1": "observed"})
    with pytest.raises(formats.StudyError):
        derive("approved", None, methodology="nist-csf", monitored=["PASS"])


@pytest.mark.parametrize("forced", [False, True])
def test_tool_cutoffs_rule_on_verdicts_equals_miccmac_scoring(tmp_path, forced):
    builder = StudyBuilder(tmp_path, hosts=("H1",), methodologies=("cmmi", "cisa-ztmm"))
    if forced:
        builder.forced_statuses["H1"] = near_perfect_statuses()
    config = formats.study_config_from_dict(builder.config)
    for methodology in builder.methodologies:
        output = formats.ToolOutput(path=Path("H1.json"), assessment=builder.assessment("H1", methodology).to_dict(),
                                    risk_register=None)
        verdicts = {c["check_id"]: c["status"] for c in output.checks()}
        properties = {c["check_id"]: c["property_key"] for c in output.checks()}
        derived = agreement.derive_levels_from_verdicts(verdicts, methodology, "tool-cutoffs", None, config,
                                                        check_properties=properties)
        assert derived == agreement.recompute_levels(output, methodology, (), config.input_driven_properties)
        assert {scope: derived[scope] for scope in output.levels()} == output.levels()
        verdicts["MON-02"] = "UNASSESSED"
        dropped = agreement.derive_levels_from_verdicts(verdicts, methodology, "tool-cutoffs", None, config,
                                                        check_properties=properties)
        assert dropped == agreement.recompute_levels(output, methodology, ["MON-02"], config.input_driven_properties)


# ------------------------------------------------------------------ level-rule options end to end
NEAR_PERFECT_APPROVED = {   # the approved rule on near_perfect_statuses(), by hand
    "monitored": 3,         # 3/4
    "inventoried": 4, "controlled": 4, "claimed": 4, "minimized": 4, "assessed": 4, "current": 4,
}
NEAR_PERFECT_OVERALL = {    # (overall, overall_excl_input_driven) under the approved rule, by hand
    "mean-of-property-ratios": (3, 3),     # (3/4 + 6) / 7 = 27/28; (3/4 + 4) / 5 = 19/20
    "pooled-checks": (3, 3),               # 25 PASS of 26; 19 of 20
    "step4-buckets": (3, 3),               # (2/3 + 6) / 7 = 20/21; (2/3 + 4) / 5 = 14/15
    "step4-rounded": (4, 4),               # 1 + round(20/7 = 2.86) = 4; 1 + round(14/5 = 2.8) = 4
}
LEVEL_RULE_OPTIONS = ([("a", rule) for rule in OVERALL_RULES] + [("b", None)]
                      + [("c", rule) for rule in OVERALL_RULES])


@pytest.mark.parametrize("option, overall_rule", LEVEL_RULE_OPTIONS)
def test_near_perfect_host_under_each_level_rule_option(tmp_path, option, overall_rule):
    """Verdicts identical on both sides and a tool overall in [90, 100).
    (a) approved manual rule, tool cutoffs: the overall differs by 2 under
    three of the overall rules, purely from the rules, and rule_only says so.
    (b) tool cutoffs on both sides and (c) the approved rule on both sides
    agree exactly."""
    if option == "b":
        level_rule, caps = {"manual": "tool-cutoffs", "tool_side": "tool-cutoffs", "overall": None}, {"cmmi": 5}
    else:
        level_rule = {"manual": "approved", "tool_side": "approved" if option == "c" else "tool-cutoffs",
                      "overall": overall_rule}
        caps = {"cmmi": 4}
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",), manual_max_level=caps, level_rule=level_rule)
    builder.forced_statuses["H1"] = near_perfect_statuses()
    assert 90 <= builder.assessment("H1", "cmmi").overall_score < 100
    if option != "b":           # (b): the default manual levels are the tool's own, as the cutoffs give them
        overall, excl = NEAR_PERFECT_OVERALL[overall_rule]
        manual = dict(NEAR_PERFECT_APPROVED, overall=overall, overall_excl_input_driven=excl)
        for scope, level in manual.items():
            builder.levels["H1"][("cmmi", scope)] = str(level)
    root = builder.build()
    assert run_agreement(root) == 0
    assert {r["check"]: r["result"] for r in summary(root)["integrity"]["checks"]}["reproduce"] == "OK"
    row = level_row(root, "H1", "cmmi", "overall")
    assert row["tool_level_reported"] == "5"
    if option == "a":
        manual_overall = NEAR_PERFECT_OVERALL[overall_rule][0]
        assert (row["tool_level_used"], row["manual_level"], row["diff"]) == ("5", str(manual_overall),
                                                                             str(5 - manual_overall))
        assert row["within_one"] == ("yes" if manual_overall == 4 else "no")
        assert (row["exact"], row["rule_only"]) == ("no", "yes")
        assert row["l5_rule_only"] == ("yes" if manual_overall == 4 else "no")
        monitored = level_row(root, "H1", "cmmi", "monitored")
        assert (monitored["tool_level_used"], monitored["manual_level"], monitored["rule_only"]) == ("4", "3", "yes")
        log = csv_rows(out_file(root, "disagreements.csv"))
        assert len(log) == 9 and all(r["rule_only"] == "yes" for r in log)    # every scope, none from verdicts
    else:
        for scope in formats.LEVEL_SCOPES:
            mine = level_row(root, "H1", "cmmi", scope)
            assert (mine["exact"], mine["rule_only"]) == ("yes", ""), scope
        expected = "5" if option == "b" else str(NEAR_PERFECT_OVERALL[overall_rule][0])
        assert row["tool_level_used"] == expected
        assert csv_rows(out_file(root, "disagreements.csv")) == []


# The approved rule on the fixture statuses (every host), by hand: monitored and
# inventoried 3/4, controlled 1, claimed 5/6, minimized 7/8, assessed 1/2,
# current 5/6 (CUR-02 N/A left out); overall mean of ratios 19/24, overall_excl
# 101/120: all L3 except controlled L4.
APPROVED_FIXTURE_LEVELS = {"monitored": 3, "inventoried": 3, "controlled": 4, "claimed": 3, "minimized": 3,
                           "assessed": 3, "current": 3, "overall": 3, "overall_excl_input_driven": 3}


def test_tool_side_approved_end_to_end(tmp_path):
    rule = {"manual": "approved", "tool_side": "approved", "overall": "mean-of-property-ratios"}
    builder = StudyBuilder(tmp_path / "study", methodologies=("cmmi", "cisa-ztmm"),
                           manual_max_level={"cmmi": 4, "cisa-ztmm": 4}, level_rule=rule, weighted_kappa=True)
    for host in HOSTS:
        for methodology in builder.methodologies:
            for scope, level in APPROVED_FIXTURE_LEVELS.items():
                builder.levels[host][(methodology, scope)] = str(level)
    builder.levels["H2"][("cmmi", "controlled")] = "3"          # the one level mismatch; the verdicts give 4
    root = builder.build()
    assert run_agreement(root) == 0
    data = summary(root)
    # Deliberately changed (V2-N1): H2's controlled 3 does not follow the declared manual rule (approved: 1/1 -> 4),
    # so it is a levels WARNING and its rule_only is left blank (it was yes). The counts are unchanged.
    assert details(root, "levels", "WARNING") == [
        ("H2", "cmmi controlled: level 3 entered, but this worksheet's verdicts give level 4 under the declared manual "
               "rule (approved, overall mean-of-property-ratios)")]
    # The reported levels still reproduce with miccmac's own cutoffs.
    assert {r["check"]: r["result"] for r in data["integrity"]["checks"]}["reproduce"] == "OK"
    row = level_row(root, "H1", "cmmi", "controlled")
    assert (row["tool_level_reported"], row["tool_level_used"], row["manual_level"]) == ("5", "4", "4")
    assert (row["exact"], row["l5_rule_only"], row["rule_only"]) == ("yes", "no", "")
    ztmm = level_row(root, "H1", "cisa-ztmm", "assessed")       # ZTMM cutoffs: 50.0 -> 2; approved 1/2 -> 3
    assert (ztmm["tool_level_reported"], ztmm["tool_level_used"], ztmm["exact"]) == ("2", "3", "yes")
    for scope in agreement.H1_SCOPES:
        assert h1(root, "cisa-ztmm", scope, "exact")["k"] == "5"
        assert h1(root, "cmmi", scope, "exact")["k"] == ("4" if scope == "controlled" else "5")
    mismatch = level_row(root, "H2", "cmmi", "controlled")
    # l5_rule_only is blank too (round 3): an off-rule level is not classified as a Level 5 case either.
    assert (mismatch["tool_level_used"], mismatch["manual_level"], mismatch["within_one"], mismatch["l5_rule_only"],
            mismatch["rule_only"]) == ("4", "3", "yes", "", "")
    assert mismatch["note"] == agreement.OFF_RULE_NOTE == "typed level does not follow the declared manual rule"
    # Every scale-dependent part uses the approved scale of 4 levels.
    assert data["config"]["tool_max_level"] == {"cmmi": 4, "cisa-ztmm": 4}
    chance = {r["methodology"]: r for r in data["chance_baselines"]}
    assert (chance["cmmi"]["tool_levels"], chance["cmmi"]["within_one_fraction"]) == (4, "5/8")   # 10/16
    confusion = csv_rows(out_file(root, "confusion_levels_cmmi.csv"))
    assert [r["tool_level"] for r in confusion] == ["1", "2", "3", "4", "unassessed"]
    assert list(confusion[0]) == ["tool_level", "manual_1", "manual_2", "manual_3", "manual_4", "manual_unassessed",
                                  "manual_missing"]
    assert {r["methodology"]: r["categories"] for r in data["weighted_kappa"]} == {"cmmi": 4, "cisa-ztmm": 4}
    l5 = [r for r in data["l5_rule_only"] if r["methodology"] == "cmmi"]
    assert all(r["l5_rule_applies"] is False and r["l5_rule_only"] == 0 for r in l5)
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "Tool levels: the tool's check statuses scored with the approved rule" in text
    assert "| cmmi | 4 | 4 | 40 | 1 | not applicable | 0 (1 not classified) |" in text
    assert "| Level rule (study.yaml level_rule) | manual: approved; tool_side: approved; overall: " \
           "mean-of-property-ratios |" in text
    assert [(r["item"], r["rule_only"]) for r in csv_rows(out_file(root, "disagreements.csv"))] == [
        ("controlled", "")]


def test_rule_only_flag_yes_no_and_blank(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2", "H3", "H4"))
    builder.levels["H1"][("cmmi", "monitored")] = "3"           # verdicts as the tool's: rule only
    builder.verdicts["H2"]["MON-02"] = ("PASS", "")             # tool FAIL; verdicts give 100 -> 5 ...
    builder.levels["H2"][("cmmi", "monitored")] = "5"           # ... so the mismatch comes from a verdict
    builder.verdicts["H3"]["MON-03"] = ("", "")                 # blank verdict: cannot decide
    builder.levels["H3"][("cmmi", "monitored")] = "3"
    builder.verdicts["H4"]["MON-02"] = ("UNASSESSED", "no log access")   # dropped on both sides: tool 5
    builder.levels["H4"][("cmmi", "monitored")] = "4"
    root = builder.build()
    assert run_agreement(root) == 3                             # H3's missing verdict is CRITICAL
    flags = {h: level_row(root, h, "cmmi", "monitored") for h in builder.hosts}
    assert [(flags[h]["tool_level_used"], flags[h]["manual_level"], flags[h]["rule_only"]) for h in builder.hosts] == [
        ("4", "3", "yes"), ("4", "5", "no"), ("4", "3", ""), ("5", "4", "yes")]
    assert "rule_only not decided" in flags["H3"]["note"]
    assert level_row(root, "H1", "cmmi", "overall")["rule_only"] == ""    # no mismatch, no flag
    log = {(r["host"], r["item"]): r["rule_only"] for r in csv_rows(out_file(root, "disagreements.csv"))
           if r["kind"] == "level"}
    assert log == {("H1", "monitored"): "yes", ("H2", "monitored"): "no", ("H3", "monitored"): "",
                   ("H4", "monitored"): "yes"}
    l5 = {r["scope"]: r for r in summary(root)["l5_rule_only"] if r["methodology"] == "cmmi"}
    assert (l5["monitored"]["exact_mismatches"], l5["monitored"]["rule_only"], l5["monitored"]["rule_only_blank"],
            l5["monitored"]["l5_rule_only"], l5["monitored"]["l5_rule_applies"]) == (4, 2, 1, 0, False)
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "| monitored | 0/4 | 0.0000 | 0.0000 to 0.4899 | not applicable | 2 (1 not classified) |" in text
    assert "| cmmi | 5 | 5 | 32 | 4 | not applicable | 2 (1 not classified) |" in text
    assert "Rule only counts exact mismatches where the level derived from the worksheet's own verdicts" in text


# ------------------------------------------------------------------ sensitivity overrides of the level rule
def test_level_rule_overrides_are_a_recorded_sensitivity_run(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"), manual_max_level={"cmmi": 4})
    root = builder.build()
    assert run_agreement(root) == 0
    base = summary(root)["config"]
    assert (base["sensitivity_run"], base["overrides"], base["tool_max_level"]) == (False, [], {"cmmi": 5})
    assert base["config_differences"] == []
    assert run_agreement(root, "--tool-side-rule", "approved", "--overall-rule", "pooled-checks",
                         "--out", str(root / "sensitivity")) == 0
    config = json.loads((root / "sensitivity" / "summary.json").read_text(encoding="utf-8"))["config"]
    assert config["level_rule"] == {"manual": None, "tool_side": "approved", "overall": "pooled-checks"}
    assert config["config_level_rule"] == {"manual": None, "tool_side": "tool-cutoffs", "overall": None}
    assert config["sensitivity_run"] is True
    assert config["overrides"] == ["--tool-side-rule approved", "--overall-rule pooled-checks"]
    assert config["config_differences"] == []                  # command-line overrides alone: labelled, no finding
    assert config["level_rule_source"]["tool_side"] == "--tool-side-rule (sensitivity check)"
    assert config["tool_max_level"] == {"cmmi": 4}
    text = (root / "sensitivity" / "summary.md").read_text(encoding="utf-8")
    # The row's label changed on purpose: it now also lists configuration differences (V1-N3).
    assert "| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: --tool-side-rule approved, " \
           "--overall-rule pooled-checks |" in text
    assert "| Tool-side level rule used | approved, from --tool-side-rule (sensitivity check); the study " \
           "configuration has tool-cutoffs |" in text
    assert "Tool levels: the tool's check statuses scored with the approved rule" in text
    # Pooled checks on the fixture statuses: 18 PASS + 4 PARTIAL of 25 = 4/5 -> 3, against the manual 4.
    rows = {r["scope"]: r for r in csv_rows(root / "sensitivity" / "host_levels.csv") if r["host"] == "H1"}
    assert (rows["overall"]["tool_level_reported"], rows["overall"]["tool_level_used"]) == ("4", "3")
    assert (rows["controlled"]["tool_level_used"], rows["controlled"]["manual_level"]) == ("4", "4")
    base_text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | no |" in base_text
    sensitivity = json.loads((root / "sensitivity" / "summary.json").read_text(encoding="utf-8"))
    assert [r for r in sensitivity["integrity"]["checks"] if r["result"] != "OK"] == []
    assert "Tool levels: miccmac's own scoring and the cmmi cutoffs, as the tool reports them" in base_text


@pytest.mark.parametrize("args, message", [
    (("--tool-side-rule", "approved"), "the approved tool-side rule needs an overall rule"),
    (("--overall-rule", "pooled-checks"), "--overall-rule changes nothing while the tool side uses tool-cutoffs"),
    (("--tool-side-rule", "cutoffs"), "--tool-side-rule 'cutoffs' is not recognized"),
    (("--tool-side-rule", "approved", "--overall-rule", "step4"), "--overall-rule 'step4' is not recognized"),
    (("--tool-side-rule", " "), "--tool-side-rule needs a value"),
])
def test_bad_level_rule_overrides_are_usage_errors(tmp_path, capsys, args, message):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    assert run_agreement(root, *args, "--out", str(root / "never")) == 2
    assert message in capsys.readouterr().err
    assert not (root / "never").exists()


def test_override_back_to_tool_cutoffs_from_an_approved_configuration(tmp_path):
    rule = {"manual": "approved", "tool_side": "approved", "overall": "step4-buckets"}
    root = StudyBuilder(tmp_path / "study", hosts=("H1",), manual_max_level={"cmmi": 4}, level_rule=rule).build()
    assert run_agreement(root, "--tool-side-rule", "tool-cutoffs") == 0
    config = summary(root)["config"]
    assert config["level_rule"]["tool_side"] == "tool-cutoffs" and config["tool_max_level"] == {"cmmi": 5}
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "step4-buckets, from the study configuration (study.yaml); not used for the tool side" in text
    assert level_row(root, "H1", "cmmi", "controlled")["tool_level_used"] == "5"


# ------------------------------------------------------------------ H2 judged rules and prioritization
def test_h2_an_n_answer_makes_an_entry_judged(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.reviews["H1"] = {
        "CUR-01": ("N", "", "Y"),         # judged: accurate N decides it, whatever actionable says
        "ASM-01": ("", "N", "N"),         # judged
        "MIN-04": ("Y", "", "UNSURE"),    # not judged: Y + blank
        "MON-02": ("", "", "Y"),          # not judged: blank + blank
        "ASM-02": ("Y", "Y", "Y"),        # judged, k
        "CLM-03": ("Y", "N", ""),         # judged; prioritized blank
        "INV-04": ("N", "N", "N"),        # judged
    }
    root = builder.build()
    assert run_agreement(root) == 3
    rows = {r["host"]: r for r in csv_rows(out_file(root, "register_h2.csv"))}
    total = rows["TOTAL"]
    assert (total["entries"], total["judged"], total["not_judged"], total["k"], total["n"]) == ("7", "5", "2", "1", "5")
    assert (total["accurate_y"], total["actionable_y"], total["rate"]) == ("2", "1", "0.2000")
    critical = [f["detail"] for f in findings(root, "CRITICAL") if f["check"] == "register"]
    assert critical == ["2 of 7 entries not judged; every entry must be judged before the final analysis (judged = "
                        "accurate and actionable both answered, or either answered N); not-judged entries are left "
                        "out of n"]
    # Prioritization: Y = CUR-01, MON-02, ASM-02; N = ASM-01, INV-04; UNSURE = MIN-04 (left out of n).
    assert (total["prioritized_y"], total["prioritized_n"], total["prioritized_unsure"]) == ("3", "2", "1")
    assert (total["prioritization_k"], total["prioritization_n"], total["prioritization_rate"]) == ("3", "5", "0.6000")
    assert (total["prioritization_wilson_low"], total["prioritization_wilson_high"]) == ("0.2307", "0.8824")
    h2 = summary(root)["h2"]["total"]
    assert "meets_threshold" in h2 and "prioritization_meets_threshold" not in h2     # no threshold for it
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "| TOTAL | 3 | 2 | 1 | 3/5 | 0.6000 | 0.2307 to 0.8824 | 0 |" in text
    assert "An entry is judged when accurate and actionable are both answered, or when either is N" in text
    assert "n = judged entries (accurate and actionable both answered, or either answered N)" in text


def test_prioritization_rate_leaves_unsure_and_blank_out_of_n(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.judge_all("H1", {"MON-02": ("Y", "Y", "N"), "INV-04": ("Y", "Y", "UNSURE"), "CLM-03": ("Y", "Y", "")})
    builder.judge_all("H2")
    root = builder.build()
    assert run_agreement(root) == 0
    rows = {r["host"]: r for r in csv_rows(out_file(root, "register_h2.csv"))}
    # H1: 4 Y, 1 N, 1 UNSURE, 1 blank -> 4/5; H2: 7 Y -> 7/7; TOTAL 11/12.
    expected = {"H1": (4, 5), "H2": (7, 7), "TOTAL": (11, 12)}
    for host, (k, n) in expected.items():
        low, high = stats.wilson_interval(k, n)
        assert (rows[host]["prioritization_k"], rows[host]["prioritization_n"]) == (str(k), str(n))
        assert (rows[host]["prioritization_wilson_low"], rows[host]["prioritization_wilson_high"]) == (
            f"{low:.4f}", f"{high:.4f}")
    assert (rows["TOTAL"]["prioritized_unsure"], rows["TOTAL"]["prioritization_rate"]) == ("1", "0.9167")
    assert rows["TOTAL"]["k"] == rows["TOTAL"]["n"] == "14"       # H2 itself is unaffected by prioritization


def test_h2_unreadable_answer_with_an_n_is_judged_and_flagged(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.judge_all("H1", {"MON-02": ("N", "maybe", "Y"), "INV-04": ("perhaps", "Y", "Y")})
    root = builder.build()
    assert run_agreement(root) == 3
    total = {r["host"]: r for r in csv_rows(out_file(root, "register_h2.csv"))}["TOTAL"]
    assert (total["judged"], total["not_judged"], total["k"]) == ("6", "1", "5")
    details = [f["detail"] for f in findings(root, "CRITICAL") if f["check"] == "register"]
    assert any(d.startswith("MON-02 actionable: unrecognized answer 'maybe'") for d in details)
    assert any(d.startswith("INV-04 accurate: unrecognized answer 'perhaps'") for d in details)
    assert any(d.startswith("1 of 7 entries not judged") for d in details)


def test_missing_review_sheet_is_critical_once_h2_is_available(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.judge_all("H1")
    root = builder.build()
    assert run_agreement(root) == 3
    critical = [(f["host"], f["detail"]) for f in findings(root, "CRITICAL") if f["check"] == "register"]
    assert critical == [("H2", "no register review sheet: 7 of 7 entries not judged; every entry must be judged "
                               "before the final analysis (judged = accurate and actionable both answered, or "
                               "either answered N); not-judged entries are left out of n")]


# ------------------------------------------------------------------ host-cluster bootstrap (ST-06, ST-09)
def test_host_bootstrap_for_check_groups_and_the_h2_total(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.verdicts["H2"]["MIN-01"] = ("FAIL", "")            # tool PASS: H2 device 15 of 16
    builder.judge_all("H1", {"MON-02": ("Y", "Y", "Y"), "INV-04": ("Y", "Y", "Y")}, default=("N", "N", "N"))
    builder.judge_all("H2")
    root = builder.build()
    assert run_agreement(root) == 0
    # Device clusters (16, 16), (15, 16): resamples 32/32, 31/32, 31/32, 30/32;
    # 2.5%: 30/32 + 0.075 x 1/32 = 0.93984; 97.5%: 31/32 + 0.925 x 1/32 = 0.99766.
    device = next(r for r in csv_rows(out_file(root, "check_agreement.csv")) if r["group"] == "device")
    assert (device["k"], device["n"], device["boot_low"], device["boot_high"]) == ("31", "32", "0.9398", "0.9977")
    assert (device["boot_method"], device["boot_resamples"], device["boot_hosts"]) == ("exact", "4", "2")
    # H2 clusters (2, 7), (7, 7): resamples 4/14, 9/14, 9/14, 14/14;
    # 2.5%: 4/14 + 0.075 x 5/14 = 0.3125; 97.5%: 9/14 + 0.925 x 5/14 = 0.97321.
    total = {r["host"]: r for r in csv_rows(out_file(root, "register_h2.csv"))}["TOTAL"]
    assert (total["k"], total["n"], total["boot_low"], total["boot_high"]) == ("9", "14", "0.3125", "0.9732")
    assert {r["host"]: r["boot_low"] for r in csv_rows(out_file(root, "register_h2.csv"))}["H1"] == ""
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "Secondary: host-cluster bootstrap 95% CI 0.3125 to 0.9732 (exact, 4 resamples of 2 hosts with " \
           "judged entries)." in text
    assert "The Wilson interval treats the entries as independent" in text
    assert "| device | 16 | 31/32 | 0.9688 |" in text and "0.9398 to 0.9977 | exact, 4 resamples of 2 hosts |" in text


def test_hosts_without_comparisons_are_left_out_of_the_bootstrap(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2", "H3"))
    excl = ("monitored", "inventoried", "controlled", "minimized", "current")
    for check_id in enabled_ids():
        if check_id.split("-")[0] in ("MON", "INV", "CTL", "MIN", "CUR"):
            builder.verdicts["H1"][check_id] = ("UNASSESSED", "no access")
    for scope in excl + ("overall_excl_input_driven",):
        builder.levels["H1"][("cmmi", scope)] = "UNASSESSED"
    builder.levels["H2"][("cmmi", "minimized")] = "2"           # tool 4: not within one
    root = builder.build()
    assert run_agreement(root) == 0
    pooled = {(r["measure"], r["subset"]): r for r in csv_rows(out_file(root, "pooled.csv"))}
    # Clusters (0, 0), (4, 5), (5, 5): the empty H1 is left out, so the resamples of H2 and H3 are
    # 8/10, 9/10, 9/10, 10/10; 2.5%: 0.8 + 0.075 x 0.1 = 0.8075; 97.5%: 0.9 + 0.925 x 0.1 = 0.9925.
    row = pooled[("within_one", "excl_input_driven")]
    assert (row["k"], row["n"], row["boot_hosts"], row["boot_resamples"]) == ("9", "10", "2", "4")
    assert (row["boot_low"], row["boot_high"]) == ("0.8075", "0.9925")
    assert pooled[("within_one", "all_properties")]["boot_hosts"] == "3"
    data = summary(root)
    assert [r["clusters"] for r in data["pooled"] if r["subset"] == "excl_input_driven"][0] == [[0, 0], [4, 5], [5, 5]]
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "The number of hosts resampled differs by row" in text
    assert "Hosts with no comparable levels in a subset are left out of its resampling" in text


# ------------------------------------------------------------------ kappa notes and the confusion matrix
def test_kappa_notes_when_one_side_uses_one_category(tmp_path):
    builder = StudyBuilder(tmp_path / "study", weighted_kappa=True)
    builder.levels["H1"][("cmmi", "overall")] = "3"            # tool overall 4 on every host
    root = builder.build()
    assert run_agreement(root) == 0
    rows = {r["subset"]: r for r in summary(root)["weighted_kappa"]}
    assert rows["overall"]["linear_weighted_kappa"] == 0.0
    assert rows["overall"]["kappa_note"] == "one category on the tool side: kappa is 0 or undefined by construction"
    assert rows["pooled_all_properties"]["kappa_note"] == ""
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "| cmmi | overall | 5 | 0.0000 (one category on the tool side: kappa is 0 or undefined by " \
           "construction) |" in text
    root = StudyBuilder(tmp_path / "same", weighted_kappa=True).build()
    assert run_agreement(root) == 0
    overall = {r["subset"]: r for r in summary(root)["weighted_kappa"]}["overall"]
    assert overall["linear_weighted_kappa"] is None
    assert overall["kappa_note"].startswith("one category on the tool side and the manual side")
    assert all(r["kappa_note"] == "" for r in csv_rows(out_file(root, "check_agreement.csv")))


def test_confusion_matrix_separates_missing_from_unassessed(tmp_path):
    builder = StudyBuilder(tmp_path / "study")
    builder.levels["H1"][("cmmi", "claimed")] = ""             # missing (CRITICAL)
    builder.levels["H2"][("cmmi", "claimed")] = "UNASSESSED"   # tool 4: one side unassessed
    root = builder.build()
    assert run_agreement(root) == 3
    confusion = {r["tool_level"]: r for r in csv_rows(out_file(root, "confusion_levels_cmmi.csv"))}
    assert (confusion["4"]["manual_missing"], confusion["4"]["manual_unassessed"]) == ("1", "1")
    assert sum(int(v) for r in confusion.values() for k, v in r.items() if k != "tool_level") == 35
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "count every host x property row, including comparisons left out of n" in text


# ------------------------------------------------------------------ identical inputs (BI-04, RD-01)
def test_outputs_scored_with_another_hosts_inputs_are_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.inputs_of["H1"] = "H2"              # a copy-paste slip in steps 5-6: H1 scored with H2's files
    root = builder.build()
    assert run_agreement(root) == 3
    # Every host has the same attestation bytes here, so only the inventory record gives the slip away.
    # The message is ledger.check_run_inputs' (V1-N4), the rule health uses; it used to add "or that file changed".
    sha = formats.sha256_file(root / "inputs" / "H2-inventory-record.json")
    assert details(root, "inputs") == [
        ("H1", f"H1-cmmi.json: the inventory record the tool used (sha256 {sha[:12]}...) is not one of the input "
               "files recorded for H1 in the ledger")]


def test_a_run_without_inputs_is_critical_when_the_host_has_input_rows(tmp_path):
    # Changed with ledger.check_run_inputs (V1-N4): one finding per input the ledger holds for the host by role.
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.provenance["H2"]["cmmi"] = {"inputs": {"attestation": None, "inventory_record": None, "config": None}}
    root = builder.build()
    assert run_agreement(root) == 3
    assert details(root, "inputs") == [
        ("H2", "H2-cmmi.json: the run had no --attestation, although the ledger holds H2's attestation "
               "inputs/H2-attestation.json"),
        ("H2", "H2-cmmi.json: the run had no --inventory-record, although the ledger holds H2's inventory record "
               "inputs/H2-inventory-record.json")]


def test_a_run_without_inputs_is_accepted_when_no_input_driven_check_is_enabled(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",), input_driven_checks=[])
    builder.provenance["H1"]["cmmi"] = {"inputs": {"attestation": None, "inventory_record": None, "config": None}}
    root = builder.build()
    assert run_agreement(root) == 0
    assert details(root, "inputs") == details(root, "inputs", "WARNING") == []


def test_inputs_without_ledger_rows_are_a_warning(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.ledger_inputs = False                # the inputs were never hashed at setup
    root = builder.build()
    assert run_agreement(root) == 0
    assert details(root, "inputs", "WARNING") == [
        (h, f"no input rows for {h} in the ledger, so the input files the tool used cannot be checked against the "
            "ones the assessor used") for h in ("H1", "H2")]


def test_an_input_file_changed_after_it_was_hashed(tmp_path):
    # Deliberately changed (V1-N4, V1-N5): the identical-inputs rule now asks whether the tool used the version
    # the assessor had (ledger.check_run_inputs). Here it did (its hash is the recorded one): no inputs CRITICAL
    # (it was one). The file edited afterwards stays a ledger_rows WARNING.
    root = StudyBuilder(tmp_path / "study", hosts=("H1", "H2")).build()
    inventory = root / "inputs" / "H2-inventory-record.json"
    inventory.write_text(json.dumps({"device_id": "synthetic-H2", "tracked": False}), encoding="utf-8")
    assert run_agreement(root) == 0
    assert details(root, "inputs") == []
    changed = details(root, "ledger_rows", "WARNING")
    assert [h for h, _ in changed] == ["H2"]
    assert changed[0][1].startswith("inputs/H2-inventory-record.json changed after it was hashed (input, ledger line ")


def test_a_miccmac_config_must_be_hashed_in_the_ledger(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    (tmp_path / "study" / "inputs").mkdir(parents=True)
    hashed = tmp_path / "study" / "inputs" / "miccmac-config.yaml"
    hashed.write_bytes(b"checks: {}\n")
    unhashed = tmp_path / "study" / "inputs" / "miccmac-config-v2.yaml"
    unhashed.write_bytes(b"checks: {disabled: []}\n")
    builder.study_files = [hashed]               # recorded at setup as a STUDY row
    builder.miccmac_config = {"H1": hashed, "H2": unhashed}
    root = builder.build()
    assert run_agreement(root) == 3
    sha = formats.sha256_file(unhashed)
    assert details(root, "inputs") == [
        ("H2", f"H2-cmmi.json: the miccmac config the tool used (sha256 {sha[:12]}...) is not one of the input files "
               "recorded for H2 or as a STUDY row in the ledger, or that file changed since")]


def test_a_facts_file_other_than_the_recorded_one_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2", "H3"))
    builder.provenance["H1"]["cmmi"] = {"facts_file": {"path": "outputs\\H1-facts.json", "sha256": "e" * 64,
                                                       "role": "replayed"}}
    builder.provenance["H2"]["cmmi"] = {"facts_file": None}
    root = builder.build()
    write_ledger(root, [r for r in ledger_rows(root) if not (r["host_code"] == "H3" and r["kind"] == "facts")])
    assert run_agreement(root) == 3
    assert details(root, "inputs") == [
        ("H1", "H1-cmmi.json: the facts file the tool used (sha256 eeeeeeeeeeee...) is not the one recorded in H1's "
               "facts row"),
        ("H2", "H2-cmmi.json: provenance names no facts file, although the ledger holds a facts row for H2")]
    assert details(root, "inputs", "WARNING") == [
        ("H3", "no facts row for H3 in the ledger, so the facts file the tool used cannot be checked")]


def test_enabled_checks_must_equal_the_list_checks_file_hashed_at_setup(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.list_checks = [c for c in enabled_ids() if c != "CUR-04"]
    root = builder.build()
    assert run_agreement(root) == 3
    assert details(root, "list_checks") == [
        (h, f"{h}-cmmi.json: enabled checks differ from inputs/list-checks.json, the list-checks file hashed at "
            "setup: only on the tool output: CUR-04") for h in ("H1", "H2")]


def test_a_list_checks_file_changed_after_setup_is_not_compared(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    (root / "inputs" / "list-checks.json").write_text(json.dumps(enabled_ids()), encoding="utf-8")   # re-saved
    assert run_agreement(root) == 0
    assert details(root, "list_checks", "WARNING") == [
        ("", "inputs/list-checks.json (ledger line 3) is CHANGED, so the tool's enabled checks are not compared "
             "with it")]
    assert details(root, "ledger_rows", "WARNING")[0][1].startswith(
        "inputs/list-checks.json changed after it was hashed (list-checks, ledger line 3)")


# ------------------------------------------------------------------ ledger evidence (BI-05, BI-03, BI-07)
def test_register_sheets_forced_before_the_seal_opened_are_critical(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    append_row(root, "2026-11-24T08:00:00Z", "STUDY", "other", root / formats.CONFIG_FILE,
               note=ledger.FORCE_NOTE_PREFIX + "checking the pipeline early")
    line = len(ledger_rows(root)) + 1        # before the run, which appends its own seal-opening row
    assert run_agreement(root) == 3
    assert details(root, "seal") == [
        ("", f"register sheets were generated before every worksheet was hashed (--force-before-unseal, ledger line "
             f"{line}, recorded 2026-11-24T08:00:00Z); reason given: checking the pipeline early")]
    assert "reason given: checking the pipeline early" in out_file(root, "summary.md").read_text(encoding="utf-8")


def test_register_sheets_changed_or_missing_after_hashing_are_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.ledger_register = True
    builder.judge_all("H1")
    builder.judge_all("H2")
    root = builder.build()
    assert run_agreement(root, "--out", str(root / "before")) == 0
    review = root / formats.REGISTER_DIR / formats.register_review_name("H1")
    rows = csv_rows(review)
    rows[0]["accurate"] = "N"                    # a hashed H2 judgment changed afterwards
    formats.write_csv(review, formats.REGISTER_REVIEW_COLUMNS, rows, overwrite=True)
    (root / formats.REGISTER_DIR / formats.missed_gaps_name("H2")).unlink()
    assert run_agreement(root) == 3
    found = details(root, "ledger_hash")
    assert [h for h, _ in found] == ["H1", "H2"]
    assert found[0][1].startswith("register/H1-register-review.csv changed after it was hashed (register-review, "
                                  "ledger line ")
    assert found[1][1].startswith("register/H2-missed-gaps.csv is missing or unreadable (missed-gaps, ledger line ")


def test_a_register_sheet_recorded_under_another_kind_is_still_frozen(tmp_path):
    """V1-N6: register/<H>-register-review.csv and <H>-missed-gaps.csv are sealed files whatever kind their rows
    were given, so a change is CRITICAL (it was a ledger_rows WARNING)."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.judge_all("H1")
    root = builder.build()
    review = root / formats.REGISTER_DIR / formats.register_review_name("H1")
    gaps = root / formats.REGISTER_DIR / formats.missed_gaps_name("H1")
    append_row(root, "2026-11-25T10:00:00Z", "H1", "other", review, note="judged")
    line = len(ledger_rows(root)) + 1
    append_row(root, "2026-11-25T10:00:00Z", "H1", "other", gaps, note="judged")
    rows = csv_rows(review)
    rows[0]["actionable"] = "N"
    formats.write_csv(review, formats.REGISTER_REVIEW_COLUMNS, rows, overwrite=True)
    gaps.unlink()
    assert run_agreement(root) == 3
    found = details(root, "ledger_hash")
    assert [h for h, _ in found] == ["H1", "H1"]
    assert found[0][1].startswith(f"register/H1-register-review.csv changed after it was hashed (other, ledger line "
                                  f"{line})")
    assert found[1][1].startswith(f"register/H1-missed-gaps.csv is missing or unreadable (other, ledger line "
                                  f"{line + 1})")
    assert details(root, "ledger_rows", "WARNING") == []


def test_a_ledger_row_out_of_time_order_is_critical(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    append_row(root, "2026-11-23T18:30:00Z", "H1", "other", root / "inputs" / "list-checks.json",
               note="dated back by hand")
    line = len(ledger_rows(root)) + 1        # before the run, which appends its own seal-opening row
    assert run_agreement(root) == 3
    assert details(root, "ledger_order") == [
        ("H1", f"ledger line {line} (inputs/list-checks.json, other) is out of order: recorded 2026-11-23T18:30:00Z, "
               "earlier than 2026-11-23T19:10:00Z above it")]
    rows = ledger_rows(root)
    rows[line - 2]["recorded_at_utc"] = "11/24/2026 10:00"     # an Excel-style time is no proof of order either
    write_ledger(root, rows)
    assert run_agreement(root, "--overwrite") == 3
    assert details(root, "ledger_order") == [
        ("H1", f"ledger line {line} (inputs/list-checks.json, other) is out of order: recorded_at_utc "
               "'11/24/2026 10:00' is not a timestamp")]


def test_superseded_rows_are_information_and_other_changed_rows_a_warning(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    rows = ledger_rows(root)
    assert (rows[0]["path"], rows[0]["kind"]) == ("study.yaml", "other")
    # study.yaml as first hashed, corrected and recorded again before any tool run: SUPERSEDED.
    draft = dict(rows[0], recorded_at_utc="2026-11-22T09:00:00Z", sha256="0" * 64, note="first draft")
    write_ledger(root, [draft] + rows)
    assert run_agreement(root) == 0
    data = summary(root)
    assert data["ledger"]["not_ok"] == [
        {"line": 2, "host_code": "STUDY", "kind": "other", "path": "study.yaml", "state": "SUPERSEDED",
         "out_of_order": False, "recorded_at_utc": "2026-11-22T09:00:00Z"}]
    assert [r for r in data["integrity"]["checks"] if r["result"] != "OK"] == []
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "- line 2: SUPERSEDED study.yaml (other, STUDY, recorded 2026-11-22T09:00:00Z)" in text


def record(root: Path, host: str, kind: str, *paths: Path, note: str = "") -> int:
    """`ledger record` as the guide runs it (at the pinned ledger clock)."""
    extra = ["--note", note] if note else []
    return main(["ledger", "record", "--ledger", str(root / formats.LEDGER_FILE), "--host", host, "--kind", kind,
                 *extra, *(str(p) for p in paths)])


def edit_threshold(path: Path, value: str) -> None:
    path.write_text(path.read_text(encoding="utf-8").replace("threshold: 0.8", f"threshold: {value}"),
                    encoding="utf-8")


def test_the_study_configuration_must_match_its_latest_ledger_row(tmp_path, capsys):
    # Deliberately changed (V1-N3, task 2c). Editing study.yaml after its last row now closes the seal (the ledger
    # checks it), so the config CRITICAL is shown with a --config file; its advice no longer says "record the one
    # used": recording it again after the first tool run does not make it pre-registered.
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    config = root / formats.CONFIG_FILE
    original = config.read_bytes()
    edit_threshold(config, "0.6")
    assert run_agreement(root) == 2
    assert "STUDY (study.yaml changed since it was last recorded (ledger line 2" in capsys.readouterr().err
    config.write_bytes(original)                                    # restored: the bytes are the recorded ones
    other = root / "study-copy.yaml"
    other.write_bytes(config.read_bytes())
    assert record(root, "STUDY", "other", other, note="a copy of the configuration") == 0
    recorded = formats.sha256_file(other)
    line = len(ledger_rows(root)) + 1
    edit_threshold(other, "0.6")
    edited = formats.sha256_file(other)
    assert run_agreement(root, "--config", str(other)) == 3
    assert details(root, "config") == [
        ("", f"study-copy.yaml changed after it was last recorded in the ledger (line {line}, {LEDGER_NOW}): ledger "
             f"{recorded[:12]}..., file now {edited[:12]}...; restore the recorded file from "
             f"ledger-archive/{recorded}.yaml; recording it again after the first tool run does not make it "
             "pre-registered"),
        ("", "the configuration used (study-copy.yaml) differs from study.yaml as it was when the seal first opened "
             "(ledger line 2): threshold 0.80 -> 0.60; this run is a sensitivity run, not the pre-registered "
             "analysis")]
    assert details(root, "ledger_rows", "WARNING")[0][1].startswith(
        f"study-copy.yaml changed after it was hashed (other, ledger line {line})")


def test_a_config_with_another_threshold_after_unsealing_is_critical_and_labelled(tmp_path):
    """V1-N3 (c): a separate configuration with threshold 0.60, recorded after the seal opened."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1", "H2")).build()
    assert run_agreement(root) == 0                                 # the seal opens
    final = root / "study-final.yaml"
    final.write_bytes((root / formats.CONFIG_FILE).read_bytes())
    edit_threshold(final, "0.60")
    assert record(root, "STUDY", "other", final, note="final configuration") == 0
    assert run_agreement(root, "--config", str(final), "--out", str(root / "final")) == 3
    data = json.loads((root / "final" / "summary.json").read_text(encoding="utf-8"))
    critical = [(r["check"], r["detail"]) for r in data["integrity"]["checks"] if r["result"] == "CRITICAL"]
    assert critical == [
        ("config", "the configuration used (study-final.yaml) differs from study.yaml as it was when the seal first "
                   "opened (ledger line 2): threshold 0.80 -> 0.60; this run is a sensitivity run, not the "
                   "pre-registered analysis")]
    assert (data["config"]["sensitivity_run"], data["config"]["overrides"], data["config"]["config_differences"]) == (
        True, [], ["threshold 0.80 -> 0.60"])
    assert data["config"]["threshold"] == 0.6                       # the run still uses the configuration given
    text = (root / "final" / "summary.md").read_text(encoding="utf-8")
    assert text.startswith(agreement.INTEGRITY_BANNER)
    assert ("| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: study-final.yaml differs "
            "from study.yaml as recorded at ledger line 2, when the seal first opened: threshold 0.80 -> 0.60 |") in text
    # With a --threshold override on top, both are listed.
    assert run_agreement(root, "--config", str(final), "--threshold", "0.75", "--out", str(root / "both")) == 3
    text = (root / "both" / "summary.md").read_text(encoding="utf-8")
    assert ("| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: --threshold 0.75; "
            "study-final.yaml differs from study.yaml as recorded at ledger line 2, when the seal first opened: "
            "threshold 0.80 -> 0.60 |") in text


def test_study_yaml_recorded_again_after_unsealing_is_a_sensitivity_run(tmp_path, ledger_clock):
    """V1-N3 (d), V3-N3: study.yaml's threshold changed and recorded again after the seal opened. Following the
    old advice ("record the one used") no longer gives a clean-looking exit 0."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1", "H2")).build()
    assert run_agreement(root) == 0                                 # the seal opens; its row archives study.yaml
    config = root / formats.CONFIG_FILE
    edit_threshold(config, "0.6")
    ledger_clock["now"] = "2026-12-02T09:00:00Z"
    assert record(root, "STUDY", "other", config, note="threshold corrected") == 0
    assert run_agreement(root, "--out", str(root / "again")) == 3
    data = json.loads((root / "again" / "summary.json").read_text(encoding="utf-8"))
    found = [(r["result"], r["detail"]) for r in data["integrity"]["checks"] if r["check"] == "config"]
    assert found == [
        ("CRITICAL", "the configuration used (study.yaml) differs from study.yaml as it was when the seal first "
                     "opened (ledger line 2): threshold 0.80 -> 0.60; this run is a sensitivity run, not the "
                     "pre-registered analysis")]
    assert data["config"]["sensitivity_run"] is True and data["config"]["config_differences"] == [
        "threshold 0.80 -> 0.60"]
    changed = [r["detail"] for r in data["integrity"]["checks"] if r["check"] == "ledger_rows"]
    assert changed[0].startswith("study.yaml changed after it was hashed (other, ledger line 2)")


def test_study_yaml_changed_after_the_first_tool_run_is_a_labelled_deviation(tmp_path):
    """Deliberately changed (round 3, V3-N3 residual): study.yaml recorded again after the first tool run but before
    the seal opened. The settings were fixed before the first tool run (protocol section 6), so a run with the
    changed settings is a WARNING (the change was made blind) and is labelled a sensitivity run; the pre-registered
    analysis is the run with the earlier version (its archive copy), which is clean and not labelled."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    config = root / formats.CONFIG_FILE
    recorded = formats.sha256_file(config)
    archive = root / "ledger-archive" / f"{recorded}.yaml"           # what `ledger record` keeps at Setup
    archive.parent.mkdir()
    archive.write_bytes(config.read_bytes())
    edit_threshold(config, "0.6")
    append_row(root, "2026-11-24T09:00:00Z", "STUDY", "other", config, note="threshold corrected")
    line = len(ledger_rows(root)) + 1
    changed = (f"study.yaml changed after the first tool run (version at the first tool run: ledger line 2; version "
               f"when the seal opened: line {line}): threshold 0.80 -> 0.60; record this deviation in the protocol log")
    assert run_agreement(root) == 0
    assert details(root, "config", "WARNING") == [
        ("", f"{changed}; this run is labelled a sensitivity run: the pre-registered analysis uses the settings of "
             f"ledger line 2 (--config ledger-archive/{recorded}.yaml)")]
    assert details(root, "config") == []
    data = summary(root)["config"]
    assert (data["sensitivity_run"], data["config_differences"], data["threshold"]) == (
        True, ["threshold 0.80 -> 0.60"], 0.6)
    assert data["config_reference"] == ("the pre-registered settings (study.yaml as recorded at ledger line 2, in "
                                        "force at the first tool run)")
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert ("| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: "
            "study.yaml differs from the pre-registered settings (study.yaml as recorded at ledger line 2, in force at "
            "the first tool run): threshold 0.80 -> 0.60 |") in text
    # The pre-registered analysis: the archive copy of the version in force at the first tool run.
    assert run_agreement(root, "--config", str(archive), "--out", str(root / "pre")) == 0
    pre = json.loads((root / "pre" / "summary.json").read_text(encoding="utf-8"))
    assert (pre["config"]["sensitivity_run"], pre["config"]["config_differences"], pre["config"]["threshold"]) == (
        False, [], 0.8)
    found = [(r["result"], r["detail"]) for r in pre["integrity"]["checks"] if r["check"] == "config"]
    assert found == [("WARNING", f"{changed}; this run uses the settings in force at the first tool run, as "
                                 "pre-registered")]
    assert {r["check"]: r["result"] for r in pre["integrity"]["checks"]}["config"] == "WARNING"
    # Without the archive copy the version at the first tool run cannot be read; the seal stays closed then too.
    archive.unlink()
    assert run_agreement(root, "--out", str(root / "again")) == 2


def test_with_study_yaml_never_recorded_the_first_opening_is_the_reference(tmp_path, ledger_clock):
    """V2 (round 3): with the Setup record skipped, a --config with other settings was neither CRITICAL nor
    labelled, although the first seal-opening row holds study.yaml's bytes and its archive copy."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.ledger_setup = False
    root = builder.build()
    assert run_agreement(root) == 0                                  # the first opening records study.yaml
    opened = next(i for i, r in enumerate(ledger_rows(root)) if r["note"].startswith("seal opened by")) + 2
    other = root / "study-t060.yaml"
    other.write_bytes((root / formats.CONFIG_FILE).read_bytes())
    edit_threshold(other, "0.60")
    ledger_clock["now"] = "2026-12-02T09:00:00Z"
    assert run_agreement(root, "--config", str(other), "--out", str(root / "t060")) == 3
    data = json.loads((root / "t060" / "summary.json").read_text(encoding="utf-8"))
    assert [r["detail"] for r in data["integrity"]["checks"] if r["check"] == "config" and r["result"] == "CRITICAL"] == [
        f"the configuration used (study-t060.yaml) differs from the one recorded when the seal first opened (ledger "
        f"line {opened}): threshold 0.80 -> 0.60; this run is a sensitivity run, not the pre-registered analysis"]
    assert (data["config"]["sensitivity_run"], data["config"]["config_differences"]) == (
        True, ["threshold 0.80 -> 0.60"])
    text = (root / "t060" / "summary.md").read_text(encoding="utf-8")
    assert (f"yes: study-t060.yaml differs from the configuration recorded when the seal first opened (ledger line "
            f"{opened}): threshold 0.80 -> 0.60 |") in text
    # study.yaml itself, unchanged, is still clean (only the 'never recorded' WARNING).
    assert run_agreement(root, "--out", str(root / "plain")) == 0


def test_a_mid_study_change_of_settings_and_hosts_names_how_to_build_the_preregistered_file(tmp_path):
    """V1, V2 (round 3): when study.yaml changed a setting and its hosts after the first tool run, the archive copy
    alone is not the pre-registered analysis (its hosts differ from those in force when the seal opened)."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    root = builder.build()
    config = root / formats.CONFIG_FILE
    recorded = formats.sha256_file(config)
    (root / "ledger-archive").mkdir()
    (root / "ledger-archive" / f"{recorded}.yaml").write_bytes(config.read_bytes())
    changed = yaml.safe_dump(dict(builder.config, hosts=["H1"], threshold="0.60"), sort_keys=False)
    config.write_text(changed, encoding="utf-8")
    append_row(root, "2026-11-25T09:00:00Z", "STUDY", "other", config, note="threshold and hosts changed")
    line = len(ledger_rows(root)) + 1
    assert run_agreement(root) == 0
    [warning] = details(root, "config", "WARNING")
    assert warning[1].endswith(
        f"; this run is labelled a sensitivity run: the pre-registered analysis uses the settings of ledger line 2 "
        f"(--config ledger-archive/{recorded}.yaml, with the hosts of ledger line {line}: copy that file, set its "
        f"hosts to those of line {line}, and record the copy with ledger record --kind other)")
    data = summary(root)["config"]
    assert data["config_reference"] == ("the pre-registered settings (study.yaml as recorded at ledger line 2, in "
                                        f"force at the first tool run, with the hosts of ledger line {line})")
    assert data["config_differences"] == ["threshold 0.80 -> 0.60"]


def test_a_setting_changed_mid_study_and_again_after_unsealing_is_critical_against_the_opening(tmp_path,
                                                                                               ledger_clock):
    """Round 3: 0.80 at the first tool run, 0.75 when the seal opened, then a --config with 0.60. The CRITICAL
    compares with the version in force when the seal opened; the label compares with the pre-registered 0.80."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    config = root / formats.CONFIG_FILE
    recorded = formats.sha256_file(config)
    (root / "ledger-archive").mkdir()
    (root / "ledger-archive" / f"{recorded}.yaml").write_bytes(config.read_bytes())
    edit_threshold(config, "0.75")
    append_row(root, "2026-11-24T09:00:00Z", "STUDY", "other", config, note="threshold changed")
    line = len(ledger_rows(root)) + 1
    assert run_agreement(root) == 0                                  # the seal opens
    late = root / "study-t060.yaml"
    late.write_text(config.read_text(encoding="utf-8").replace("threshold: 0.75", "threshold: 0.60"), encoding="utf-8")
    assert run_agreement(root, "--config", str(late), "--out", str(root / "late")) == 3
    data = json.loads((root / "late" / "summary.json").read_text(encoding="utf-8"))
    assert [r["detail"] for r in data["integrity"]["checks"] if r["check"] == "config" and r["result"] == "CRITICAL"] == [
        f"the configuration used (study-t060.yaml) differs from study.yaml as it was when the seal first opened "
        f"(ledger line {line}): threshold 0.75 -> 0.60; this run is a sensitivity run, not the pre-registered analysis"]
    assert data["config"]["config_differences"] == ["threshold 0.80 -> 0.60"]
    # Putting the setting back to its value at the first tool run is no change after unsealing.
    back = root / "study-t080.yaml"
    back.write_text(config.read_text(encoding="utf-8").replace("threshold: 0.75", "threshold: 0.80"), encoding="utf-8")
    assert run_agreement(root, "--config", str(back), "--out", str(root / "back")) == 0
    data = json.loads((root / "back" / "summary.json").read_text(encoding="utf-8"))
    assert (data["config"]["sensitivity_run"], data["config"]["config_differences"]) == (False, [])


def test_configuration_differences_name_every_setting():
    base = formats.study_config_from_dict({"hosts": ["H1", "H2", "H3"]})
    other = formats.study_config_from_dict({
        "hosts": ["H1", "H2", "H4"], "threshold": "3/4", "primary_methodology": "cisa-ztmm",
        "secondary_methodologies": ["cmmi"], "manual_max_level": {"cmmi": 4, "cisa-ztmm": 4},
        "input_driven_checks": ["INV-01"], "input_driven_properties": ["claimed", "assessed", "current"],
        "bootstrap": {"iterations": 2000, "seed": 1, "exact_limit": 0}, "weighted_kappa": True, "synthetic": True,
        "level_rule": {"manual": "approved", "tool_side": "approved", "overall": "pooled-checks"}})
    assert agreement._config_differences(base, other) == [
        "hosts: H3 left out", "hosts: H4 added",
        "input_driven_checks: INV-04, CTL-03, CLM-01, CLM-02, CLM-03, ASM-01, ASM-02, ASM-03, CUR-03 removed",
        "input_driven_properties: current added", "threshold 0.80 -> 0.75", "primary_methodology cmmi -> cisa-ztmm",
        "secondary_methodologies [] -> [cmmi]", "manual_max_level cmmi 5 -> 4", "bootstrap.iterations 10000 -> 2000",
        "bootstrap.seed 20261122 -> 1", "bootstrap.exact_limit 1000000 -> 0", "weighted_kappa false -> true",
        "synthetic false -> true", "level_rule.manual null -> approved", "level_rule.tool_side tool-cutoffs -> approved",
        "level_rule.overall null -> pooled-checks"]
    assert agreement._config_differences(base, base) == []
    # Hosts compare as a set, and a cap written out equals the same cap left at its default.
    same = formats.study_config_from_dict({"hosts": ["H3", "H1", "H2"], "manual_max_level": {"cmmi": 5}})
    assert agreement._config_differences(base, same) == []
    assert agreement._config_differences(base, dataclasses.replace(base, threshold=Fraction(2, 3))) == [
        "threshold 0.80 -> 2/3"]
    # Every StudyConfig setting is compared by name (a new one would be compared generically).
    assert {item.name for item in dataclasses.fields(formats.StudyConfig)} == agreement._COMPARED_FIELDS


def test_a_recorded_version_that_cannot_be_read_is_critical(tmp_path, monkeypatch):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    assert run_agreement(root) == 0
    rows = ledger_rows(root)
    # As if the configuration had been hashed with other bytes and its archive copy were lost: the seal (whose own
    # check is the ledger's) is let through here, so that agreement's comparison is reached.
    rows[0]["sha256"] = "a" * 64
    write_ledger(root, rows)
    real = ledger.seal_status

    def without_problems(*args, **kwargs):
        status = real(*args, **kwargs)
        return ledger.SealStatus(hosts=status.hosts, withdrawn=status.withdrawn, problems=[])

    monkeypatch.setattr(ledger, "seal_status", without_problems)
    assert run_agreement(root, "--out", str(root / "again")) == 3
    found = json.loads((root / "again" / "summary.json").read_text(encoding="utf-8"))["integrity"]["checks"]
    assert ("CRITICAL", "cannot load study.yaml as recorded at ledger line 2 (archive copy missing): the "
                        "configuration used cannot be compared with the pre-registered one") in [
        (r["result"], r["detail"]) for r in found if r["check"] == "config"]


def test_study_yaml_first_recorded_after_the_first_tool_run_is_a_warning(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.ledger_setup = False
    root = builder.build()
    append_row(root, "2026-11-24T09:00:00Z", "STUDY", "other", root / formats.CONFIG_FILE, note="recorded late")
    line = len(ledger_rows(root)) + 1
    tool = next(i for i, r in enumerate(ledger_rows(root)) if r["kind"] == "facts") + 2
    assert run_agreement(root) == 0
    assert details(root, "config", "WARNING") == [
        ("", f"study.yaml was first recorded at ledger line {line}, after the first tool run (ledger line {tool}), so "
             "the version in force at the first tool run is unknown; record this deviation in the protocol log")]
    assert details(root, "config") == [] and summary(root)["config"]["sensitivity_run"] is False


def test_rows_of_study_yaml_recorded_only_after_the_seal_opened_are_a_warning(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.ledger_setup = False
    root = builder.build()
    assert run_agreement(root) == 0                                 # never recorded: the WARNING of today
    assert record(root, "STUDY", "other", root / formats.CONFIG_FILE, note="recorded late") == 0
    assert run_agreement(root, "--out", str(root / "again")) == 0
    found = json.loads((root / "again" / "summary.json").read_text(encoding="utf-8"))["integrity"]["checks"]
    lines = [r["detail"] for r in found if r["check"] == "config" and r["result"] == "WARNING"]
    rows = ledger_rows(root)
    late = next(i for i, r in enumerate(rows) if r["note"] == "recorded late") + 2
    opened = next(i for i, r in enumerate(rows) if r["note"].startswith(ledger.SEAL_OPENED_NOTE_PREFIX)) + 2
    assert lines == [f"study.yaml was first recorded at ledger line {late}, after the seal was first opened (ledger "
                     f"line {opened}), so the settings used cannot be shown to be the ones fixed in advance"]


def test_a_configuration_never_recorded_is_a_warning(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.ledger_setup = False
    root = builder.build()
    assert run_agreement(root) == 0
    assert details(root, "config", "WARNING") == [
        ("", "study.yaml was never recorded in the ledger, so the settings used cannot be shown to be the ones fixed "
             "in advance")]
    row = next(r for r in summary(root)["integrity"]["checks"] if r["check"] == "list_checks")
    assert (row["result"], row["detail"]) == ("OK", "no STUDY list-checks row in the ledger, so nothing to compare")


# ------------------------------------------------------------------ the seal-opening row (RD-03, V1-N2)
def test_every_run_that_opens_the_seal_records_it_in_the_ledger(tmp_path, ledger_clock):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2", "H3"))
    builder.absent = ["H3"]
    root = builder.build()
    before = ledger_rows(root)
    assert run_agreement(root) == 2                       # sealed (H3 neither hashed nor withdrawn): no row
    assert ledger_rows(root) == before
    append_row(root, "2026-11-29T09:00:00Z", "H3", "protocol", root / formats.CONFIG_FILE, note="withdrawn: VM lost")
    assert run_agreement(root) == 0
    rows = ledger_rows(root)
    config = root / formats.CONFIG_FILE
    assert len(rows) == len(before) + 2
    assert rows[-1] == {"recorded_at_utc": LEDGER_NOW, "host_code": "STUDY", "kind": "protocol", "path": "study.yaml",
                        "sha256": formats.sha256_file(config), "bytes": str(config.stat().st_size),
                        "note": "seal opened by agreement: hosts H1, H2; withdrawn: H3"}
    assert (root / "ledger-archive" / f"{rows[-1]['sha256']}.yaml").read_bytes() == config.read_bytes()
    assert summary(root)["ledger"]["rows"] == len(rows)    # the run reports the ledger with its own row
    assert run_agreement(root) == 2                       # refused (its outputs exist): no row
    assert len(ledger_rows(root)) == len(rows)
    ledger_clock["now"] = "2026-12-02T09:00:00Z"
    assert run_agreement(root, "--out", str(root / "again")) == 0     # every opening is a row of its own
    assert [(r["recorded_at_utc"], r["note"]) for r in ledger_rows(root)[len(rows) - 1:]] == [
        (LEDGER_NOW, rows[-1]["note"]), ("2026-12-02T09:00:00Z", rows[-1]["note"])]


def test_a_seal_opening_that_cannot_be_recorded_stops_the_run_before_any_tool_output_is_read(tmp_path, capsys,
                                                                                             monkeypatch):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    before = (root / formats.LEDGER_FILE).read_bytes()

    def locked(ledger_file, rows):
        raise formats.StudyError(f"cannot write ledger {ledger_file}: [Errno 13] Permission denied")

    monkeypatch.setattr(ledger, "_append_rows", locked)
    monkeypatch.setattr(agreement, "load_tool_output", lambda path: pytest.fail("a tool output was read"))
    assert run_agreement(root) == 2
    err = capsys.readouterr().err
    assert ("error: cannot record the seal opening in the ledger (cannot write ledger ledger.csv: [Errno 13] "
            "Permission denied); no tool output was read and no analysis file was written") in err
    assert not (root / formats.ANALYSIS_DIR).exists()
    assert (root / formats.LEDGER_FILE).read_bytes() == before


def test_a_host_added_and_hashed_after_the_seal_opened_is_critical(tmp_path):
    """V1-N2 (b): the seal opened (register-sheet) while study.yaml listed H1-H3; H4 was then added to study.yaml,
    recorded, and its worksheet hashed. Its blind pass came after tool results were available."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2", "H3", "H4"))
    root = builder.build()
    config = root / formats.CONFIG_FILE
    first = yaml.safe_dump(dict(builder.config, hosts=["H1", "H2", "H3"]), sort_keys=False).encode("utf-8")
    first_sha = hashlib.sha256(first).hexdigest()
    (root / "ledger-archive").mkdir()
    (root / "ledger-archive" / f"{first_sha}.yaml").write_bytes(first)      # as `ledger record` kept it
    rows = [row for row in ledger_rows(root) if not (row["host_code"] == "H4" and row["kind"] == "input")]
    rows[0].update(sha256=first_sha, bytes=str(len(first)))                    # study.yaml at Setup: H1-H3
    write_ledger(root, rows)
    insert_rows(root,
                dict(rows[0], recorded_at_utc="2026-11-26T08:00:00Z", kind="protocol",
                     note="seal opened by register-sheet: hosts H1, H2, H3; withdrawn: none"),
                row_for(root, "2026-11-26T09:00:00Z", "STUDY", "other", config, note="H4 added"))
    opened = next(i for i, r in enumerate(ledger_rows(root)) if r["note"].startswith("seal opened by")) + 2
    assert run_agreement(root) == 3
    assert details(root, "ledger_order") == [
        ("H4", f"H4's worksheet was hashed at 2026-11-26T18:00:00Z, after the seal was first opened at "
               f"2026-11-26T08:00:00Z (ledger line {opened}): its blind pass may have seen tool results")]
    assert details(root, "config") == [
        ("", "the configuration used (study.yaml) differs from study.yaml as it was when the seal first opened (ledger "
             "line 2): hosts: H4 added; this run is a sensitivity run, not the pre-registered analysis")]
    assert summary(root)["config"]["config_differences"] == ["hosts: H4 added"]


def test_a_withdrawal_after_the_seal_opened_is_a_post_hoc_exclusion(tmp_path, capsys, ledger_clock):
    """V1-N3 (a): a host withdrawn once its results were available."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1", "H2", "H3")).build()
    assert run_agreement(root) == 0
    opened = len(ledger_rows(root)) + 1                      # that run's seal-opening row, the last one
    ledger_clock["now"] = "2026-12-02T09:00:00Z"
    withdraw = ["ledger", "withdraw", "--ledger", str(root / formats.LEDGER_FILE), "--host", "H3",
                "--reason", "results looked odd"]
    assert main(withdraw) == 2 and "add --after-unseal" in capsys.readouterr().err
    assert main(withdraw + ["--after-unseal"]) == 0
    assert run_agreement(root, "--out", str(root / "again")) == 3
    data = json.loads((root / "again" / "summary.json").read_text(encoding="utf-8"))
    assert [(r["result"], r["host"], r["detail"]) for r in data["integrity"]["checks"] if r["check"] == "hosts"] == [
        ("CRITICAL", "H3", f"H3 was withdrawn at 2026-12-02T09:00:00Z, after the seal was first opened at {LEDGER_NOW} "
                           f"(ledger line {opened}): a post-hoc exclusion; the pre-registered analysis includes H3")]
    assert data["config"]["hosts"] == ["H1", "H2"]
    assert data["config"]["withdrawn"]["H3"]["reason"] == "(after the seal was opened) results looked odd"
    # Round 3 (V1, V2): the run is also labelled a sensitivity run, as a --config with fewer hosts is.
    assert (data["config"]["sensitivity_run"], data["config"]["post_hoc_exclusions"]) == (
        True, ["H3 withdrawn after the seal first opened (a post-hoc exclusion)"])
    text = (root / "again" / "summary.md").read_text(encoding="utf-8")
    assert ("| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: H3 "
            "withdrawn after the seal first opened (a post-hoc exclusion) |") in text


def test_a_withdrawal_after_the_hosts_tool_outputs_were_hashed_says_so(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1", "H2")).build()
    append_row(root, "2026-11-25T09:00:00Z", "H2", "protocol", root / formats.CONFIG_FILE,
               note="withdrawn: VM lost after the run")
    assert run_agreement(root) == 0                          # before the seal opened: a WARNING, worded so
    assert details(root, "hosts", "WARNING") == [
        ("H2", "withdrawn after its tool outputs were hashed (2026-11-24T19:10:00Z), in the ledger at "
               "2026-11-25T09:00:00Z: VM lost after the run; left out of the analysis")]
    assert details(root, "hosts") == []


# ------------------------------------------------------------------ inputs by role (V1-N4, V1-N5)
def test_swapped_input_files_are_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.run_inputs["H1"] = {"attestation": "inventory_record", "inventory_record": "attestation"}
    root = builder.build()
    assert run_agreement(root) == 3
    attestation = formats.sha256_file(root / "inputs" / "H1-attestation.json")
    inventory = formats.sha256_file(root / "inputs" / "H1-inventory-record.json")
    setup = "2026-11-22T10:00:00Z"
    assert details(root, "inputs") == [
        ("H1", f"H1-cmmi.json: the attestation the tool used (sha256 {inventory[:12]}...) is "
               f"inputs/H1-inventory-record.json, H1's inventory record as recorded at {setup}: the two input files "
               "were swapped or mixed up"),
        ("H1", f"H1-cmmi.json: the inventory record the tool used (sha256 {attestation[:12]}...) is "
               f"inputs/H1-attestation.json, H1's attestation as recorded at {setup}: the two input files were "
               "swapped or mixed up")]


def test_the_same_input_file_given_twice_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.run_inputs["H1"] = {"inventory_record": "attestation"}
    root = builder.build()
    assert run_agreement(root) == 3
    attestation = formats.sha256_file(root / "inputs" / "H1-attestation.json")
    assert details(root, "inputs") == [
        ("H1", f"H1-cmmi.json: the run was given the same file (sha256 {attestation[:12]}...) as --attestation and as "
               "--inventory-record: inputs/H1-attestation.json as recorded at 2026-11-22T10:00:00Z")]


def test_an_input_recorded_again_after_the_worksheet_hash_and_used_by_the_tool_is_critical(tmp_path):
    """V1-N5: the assessor and the tool used different versions of the attestation."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    attestation = root / "inputs" / "H1-attestation.json"
    attestation.write_text(json.dumps(dict(ATTESTATION, identity_aware_access={"enabled": False})), encoding="utf-8")
    insert_rows(root, row_for(root, "2026-11-23T18:30:00Z", "H1", "input", attestation, note="corrected"))
    point_outputs_at(root, "H1", "attestation", attestation)
    assert run_agreement(root) == 3
    assert details(root, "inputs") == [
        ("H1", "H1-cmmi.json: the tool used inputs/H1-attestation.json as recorded at 2026-11-23T18:30:00Z, after "
               "H1's worksheet was hashed at 2026-11-23T18:00:00Z; the assessor had the version recorded at "
               "2026-11-22T10:00:00Z")]


def test_an_input_recorded_again_during_the_blind_pass_is_a_warning(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    inventory = root / "inputs" / "H1-inventory-record.json"
    inventory.write_text(json.dumps({"device_id": "synthetic-H1", "tracked": True, "owner": "lab"}), encoding="utf-8")
    insert_rows(root, row_for(root, "2026-11-23T12:00:00Z", "H1", "input", inventory, note="owner added"))
    point_outputs_at(root, "H1", "inventory_record", inventory)
    assert run_agreement(root) == 0
    assert details(root, "inputs") == []                        # the assessor's version, as the tool used
    assert details(root, "inputs", "WARNING") == [
        ("H1", "inputs/H1-inventory-record.json was recorded again at 2026-11-23T12:00:00Z, during H1's blind pass "
               "(sheet generated 2026-11-23T09:00:00Z, hashed 2026-11-23T18:00:00Z): check that the whole pass used "
               "this version")]
    assert [r["state"] for r in summary(root)["ledger"]["not_ok"]] == ["SUPERSEDED"]     # corrected in time


def test_an_input_whose_name_gives_no_role_is_a_warning(tmp_path):
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    named = root / "inputs" / "H1-inventory.json"
    named.write_bytes((root / "inputs" / "H1-inventory-record.json").read_bytes())
    rows = ledger_rows(root)
    for row in rows:
        if row["path"] == "inputs/H1-inventory-record.json":
            row["path"] = "inputs/H1-inventory.json"
    write_ledger(root, rows)
    assert run_agreement(root) == 0
    assert details(root, "inputs") == []
    assert details(root, "inputs", "WARNING") == [
        ("H1", "H1-cmmi.json: cannot tell whether inputs/H1-inventory.json is an attestation or an inventory record: "
               "name it H1-attestation.json or H1-inventory-record.json")]


# ------------------------------------------------------------------ forced worksheets and typed levels (V1-N7, V2-N1)
def test_a_worksheet_recorded_with_force_is_reported_with_its_findings(tmp_path, capsys, ledger_clock):
    builder = approved_builder(tmp_path / "study", hosts=("H1", "H2"))
    builder.levels["H2"][("cmmi", "monitored")] = "4"            # the verdicts give 3/4 -> 3
    root = builder.build()
    sheet = root / formats.WORKSHEETS_DIR / formats.worksheet_name("H2")
    # Step 3 for H2 by the command line: the ledger without H2's worksheet and facts rows, then the record
    # (refused, then forced), then the facts row.
    rows = ledger_rows(root)
    facts = next(r for r in rows if r["host_code"] == "H2" and r["kind"] == "facts")
    write_ledger(root, [r for r in rows if r is not facts and not (r["host_code"] == "H2" and r["kind"] == "worksheet")])
    ledger_clock["now"] = "2026-11-24T18:00:00Z"
    assert record(root, "H2", "worksheet", sheet) == 2
    assert "nothing was recorded" in capsys.readouterr().err
    assert main(["ledger", "record", "--ledger", str(root / formats.LEDGER_FILE), "--host", "H2", "--kind",
                 "worksheet", "--force", str(sheet)]) == 0
    insert_rows(root, facts)
    line = next(i for i, r in enumerate(ledger_rows(root)) if r["host_code"] == "H2" and r["kind"] == "worksheet") + 2
    ledger_clock["now"] = LEDGER_NOW
    assert run_agreement(root) == 0
    finding = ("cmmi monitored: level 4 entered, but this worksheet's verdicts give level 3 under the declared manual "
               "rule (approved, overall pooled-checks)")
    assert details(root, "worksheet", "WARNING") == [
        ("H2", f"worksheets/H2-worksheet.csv was recorded with --force despite lint findings (ledger line {line}, "
               f"2026-11-24T18:00:00Z): WARNING {finding}")]
    assert details(root, "levels", "WARNING") == [("H2", finding)]


def test_a_forced_worksheet_with_a_critical_finding_is_critical(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.verdicts["H1"]["MON-03"] = ("", "")
    listed = f"CRITICAL MON-03: missing verdict; WARNING {agreement.NO_MANUAL_RULE}"
    builder.sheet_notes["H1"] = f"manual pass done; {ledger.LINT_NOTE_PREFIX}{listed}"     # with --note too
    root = builder.build()
    line = next(i for i, r in enumerate(ledger_rows(root)) if r["kind"] == "worksheet") + 2
    assert run_agreement(root) == 3
    assert details(root, "worksheet") == [
        ("H1", f"worksheets/H1-worksheet.csv was recorded with --force despite lint findings (ledger line {line}, "
               f"2026-11-23T18:00:00Z): {listed}")]


def test_a_typed_level_that_does_not_follow_the_declared_manual_rule_is_flagged(tmp_path, monkeypatch):
    """V2-N1: H2's cmmi overall typed 4 and controlled typed 1, where its verdicts give 3 and 4 under the declared
    manual rule. A WARNING each; rule_only is left blank, noted; every other column and statistic is unchanged."""
    builder = approved_builder(tmp_path / "study", hosts=("H1", "H2"))
    builder.levels["H2"][("cmmi", "overall")] = "4"
    builder.levels["H2"][("cmmi", "controlled")] = "1"
    root = builder.build()
    assert run_agreement(root) == 0
    named = "the declared manual rule (approved, overall pooled-checks)"
    assert details(root, "levels", "WARNING") == [
        ("H2", f"cmmi controlled: level 1 entered, but this worksheet's verdicts give level 4 under {named}"),
        ("H2", f"cmmi overall: level 4 entered, but this worksheet's verdicts give level 3 under {named}")]
    controlled = level_row(root, "H2", "cmmi", "controlled")
    assert (controlled["tool_level_used"], controlled["manual_level"], controlled["diff"], controlled["exact"],
            controlled["within_one"], controlled["rule_only"], controlled["note"]) == (
        "5", "1", "4", "no", "no", "", agreement.OFF_RULE_NOTE)
    overall = level_row(root, "H2", "cmmi", "overall")               # the tool's 4 too: no mismatch, still noted
    assert (overall["exact"], overall["rule_only"], overall["note"]) == ("yes", "", agreement.OFF_RULE_NOTE)
    assert level_row(root, "H1", "cmmi", "controlled")["rule_only"] == "yes"     # 4 by the rule; the tool says 5
    monkeypatch.setattr(agreement, "_declared_manual_rule", lambda study: None)  # the check left out
    assert run_agreement(root, "--out", str(root / "unchecked")) == 0
    checked, unchecked = csv_rows(out_file(root, "host_levels.csv")), csv_rows(root / "unchecked" / "host_levels.csv")
    strip = lambda rows: [{k: v for k, v in r.items() if k not in ("l5_rule_only", "rule_only", "note")}  # noqa: E731
                          for r in rows]
    assert strip(checked) == strip(unchecked)
    assert [r["rule_only"] for r in unchecked if r["host"] == "H2" and r["scope"] == "controlled"] == ["yes"]
    for name in ("agreement_h1.csv", "pooled.csv", "check_agreement.csv", "confusion_levels_cmmi.csv"):
        assert out_file(root, name).read_bytes() == (root / "unchecked" / name).read_bytes(), name


def test_an_off_rule_level_at_the_cap_is_not_a_level_5_case():
    """V2 (round 2): tool at its top level 5, manual typed 4 (the cap) where the verdicts give 3 under the declared
    rule. That mismatch is not caused by the Level 5 rule alone, so l5_rule_only is left blank as rule_only is."""
    args = ("H1", "cmmi", "overall", {"overall": 5}, {"overall": 5}, 4, "4", 5, 4, ())
    on_rule = agreement._level_comparison(*args, from_verdicts=4)
    assert (on_rule.l5_rule_only, on_rule.note) == (True, "Level 5 rule only: tool at top level 5, manual at cap 4")
    off_rule = agreement._level_comparison(*args, from_verdicts=3, off_rule=True)
    assert (off_rule.l5_rule_only, off_rule.rule_only, off_rule.note) == (None, None, agreement.OFF_RULE_NOTE)
    assert (off_rule.counted, off_rule.exact, off_rule.within_one) == (True, False, True)


# ------------------------------------------------------------------ the disagreement log is never lost (BI-09)
def test_overwrite_never_replaces_a_disagreement_log_with_entries(tmp_path, capsys):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.levels["H2"][("cmmi", "monitored")] = "3"
    root = builder.build()
    assert run_agreement(root) == 0
    log = out_file(root, "disagreements.csv")
    rows = csv_rows(log)
    rows[0]["root_cause"] = "genuine judgment difference"
    formats.write_csv(log, agreement.DISAGREEMENT_COLUMNS, rows, overwrite=True)
    before = log.read_bytes()
    assert run_agreement(root, "--overwrite") == 2
    err = capsys.readouterr().err
    assert "holds the researcher's entries (data row 1: root_cause is filled in)" in err and "--out" in err
    assert log.read_bytes() == before
    assert run_agreement(root, "--out", str(root / "second")) == 0


def test_overwrite_guard_covers_the_synthetic_prefix(tmp_path, capsys):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",), synthetic=True)
    builder.meta["H1"]["synthetic"] = "yes"
    builder.levels["H1"][("cmmi", "monitored")] = "3"
    root = builder.build()
    assert run_agreement(root) == 0
    log = out_file(root, "disagreements.csv", synthetic=True)
    rows = csv_rows(log)
    rows[0]["assessor_error_note"] = "level typed from the wrong row"
    formats.write_csv(log, agreement.DISAGREEMENT_COLUMNS, rows, overwrite=True)
    assert run_agreement(root, "--overwrite") == 2
    assert "data row 1: assessor_error_note is filled in" in capsys.readouterr().err


# ------------------------------------------------------------------ order checks: same-second ties (RD-18)
def test_a_same_second_tie_is_reported_as_not_after_the_worksheet_hash(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.provenance["H1"]["cmmi"] = {"run_at_utc": "2026-11-23T18:00:00Z"}   # the worksheet hash's own second
    builder.hashed_at["H2"] = "T19:10:00Z"           # the facts row's second (and after the 19:05 run)
    root = builder.build()
    assert run_agreement(root) == 3
    found = details(root, "ledger_order")
    assert ("H1", "tool run not after the worksheet hash (same second): H1-cmmi.json run_at_utc "
                  "2026-11-23T18:00:00Z, worksheet hashed 2026-11-23T18:00:00Z") in found
    assert not any("before" in d for h, d in found if h == "H1")
    assert ("H2", "outputs/H2-facts.json was recorded in the ledger at 2026-11-24T19:10:00Z, not after the worksheet "
                  "hash (same second)") in found
    assert ("H2", "tool run before the worksheet was hashed: H2-cmmi.json run_at_utc 2026-11-24T19:05:00Z, "
                  "worksheet hashed 2026-11-24T19:10:00Z") in found


# ------------------------------------------------------------------ analysis code provenance
class FakeGit:
    """Stands in for subprocess.run: records the call, answers like git."""

    def __init__(self, returncode=0, stdout=b"", error=None):
        self.returncode, self.stdout, self.error = returncode, stdout, error
        self.calls: List[tuple] = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.stdout, stderr=b"")


@pytest.mark.parametrize("returncode, stdout, error, expected", [
    (0, b"", None, True),
    (0, b"?? miccmac_study/new_module.py\n", None, False),      # an untracked file counts
    (0, b" M miccmac_study/agreement.py\n", None, False),
    (128, b"", None, None),                                     # not a repository
    (0, b"", FileNotFoundError("git"), None),                   # git not installed
    (0, b"", subprocess.TimeoutExpired("git", 60), None),
])
def test_analysis_tree_clean_asks_git_status_without_taking_locks(monkeypatch, returncode, stdout, error, expected):
    fake = FakeGit(returncode, stdout, error)
    monkeypatch.setattr(agreement.subprocess, "run", fake)
    package = Path(agreement.__file__).resolve().parent
    assert REAL_ANALYSIS_TREE_CLEAN(package) is expected
    argv, kwargs = fake.calls[0]
    assert argv == ["git", "status", "--porcelain", "--untracked-files=normal", "--", "miccmac_study"]
    assert kwargs["cwd"] == str(package.parent) and kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"


def test_every_module_of_the_analysis_package_is_hashed(tmp_path):
    """V1-N9: the seal, the ledger and the readers are analysis code too."""
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    assert run_agreement(root) == 0
    files = summary(root)["run"]["analysis_code"]["files_sha256"]
    package = Path(agreement.__file__).resolve().parent
    names = sorted(p.name for p in package.glob("*.py"))
    assert list(files) == [f"miccmac_study/{name}" for name in names]
    assert {"agreement.py", "formats.py", "ledger.py", "stats.py", "worksheet.py"} <= set(names)
    lf = {name: hashlib.sha256((package / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in names}
    assert all(files[f"miccmac_study/{name}"] == lf[name] for name in names)
    assert summary(root)["run"]["analysis_code"]["files_sha256_method"] == agreement.CODE_HASH_METHOD
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert f"miccmac_study/ledger.py {files['miccmac_study/ledger.py'][:16]}" in text


def test_the_analysis_code_hash_does_not_depend_on_line_endings(tmp_path):
    """V2 (round 2): a Windows checkout (CRLF) and a Linux one (LF) of the same commit give the same values."""
    lf, crlf = tmp_path / "lf.py", tmp_path / "crlf.py"
    lf.write_bytes(b"a = 1\nb = 2\n")
    crlf.write_bytes(b"a = 1\r\nb = 2\r\n")
    assert agreement.code_sha256(lf) == agreement.code_sha256(crlf) == hashlib.sha256(b"a = 1\nb = 2\n").hexdigest()


@pytest.mark.parametrize("clean, shown", [
    (True, "yes"), (False, "no: uncommitted changes or untracked files in miccmac_study"),
    (None, "unknown (git not available)")])
def test_analysis_tree_clean_is_reported_and_warned_about(tmp_path, monkeypatch, clean, shown):
    monkeypatch.setattr(agreement, "_analysis_tree_clean", lambda package_dir: clean)
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    assert run_agreement(root) == 0
    assert summary(root)["run"]["analysis_code"]["analysis_tree_clean"] is clean
    # Deliberately changed: git not being available is a WARNING too (it gave none).
    expected = {
        True: [],
        False: [("", "miccmac_study has uncommitted changes or untracked files (git status --porcelain -- "
                     "miccmac_study), so the analysis code commit does not hold the code that ran")],
        None: [("", "git is not available here, so it could not be checked that the analysis code is committed")],
    }[clean]
    assert details(root, "analysis_code", "WARNING") == expected
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert f"| Analysis code committed (analysis_tree_clean) | {shown} |" in text


# ------------------------------------------------------------------ pre-hash worksheet lint (ST-03)
APPROVED_POOLED = {"manual": "approved", "tool_side": "tool-cutoffs", "overall": "pooled-checks"}


def lint(root: Path, host: str, as_host: Optional[str] = None) -> List[tuple]:
    config = formats.load_study_config(root / formats.CONFIG_FILE)
    return agreement.lint_worksheet(root / formats.WORKSHEETS_DIR / formats.worksheet_name(host), config,
                                    as_host or host)


def approved_builder(root: Path, hosts=("H1",), rule=None) -> StudyBuilder:
    """Manual levels typed by the approved rule on the fixture verdicts (APPROVED_FIXTURE_LEVELS; with
    pooled-checks, overall 4/5 -> 3 and overall_excl 16/19 -> 3, the same levels)."""
    builder = StudyBuilder(root, hosts=hosts, manual_max_level={"cmmi": 4}, level_rule=rule or APPROVED_POOLED)
    for host in hosts:
        for scope, level in APPROVED_FIXTURE_LEVELS.items():
            builder.levels[host][("cmmi", scope)] = str(level)
    return builder


def test_lint_finds_nothing_on_a_complete_worksheet(tmp_path):
    # Changed with the decision-4 lint finding: a complete sheet lints clean once level_rule.manual is declared.
    # Here the tool-cutoffs manual rule, which the default levels (the tool's own) follow.
    root = StudyBuilder(tmp_path / "study", methodologies=("cmmi", "cisa-ztmm"),
                        level_rule={"manual": "tool-cutoffs"}).build()
    assert all(lint(root, host) == [] for host in HOSTS)
    root = approved_builder(tmp_path / "approved", hosts=("H1", "H2")).build()
    assert lint(root, "H1") == lint(root, "H2") == []


def test_lint_reports_what_agreement_would_report_while_the_sheet_can_be_corrected(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.verdicts["H1"]["MON-01"] = ("PASSS", "")
    builder.verdicts["H1"]["MON-03"] = ("", "")
    builder.verdicts["H1"]["MON-02"] = ("UNASSESSED", "")
    builder.levels["H1"][("cmmi", "claimed")] = "7"
    builder.levels["H1"][("cmmi", "current")] = ""
    builder.meta["H1"]["synthetic"] = "yes"
    builder.meta["H1"]["enabled_checks_fingerprint"] = "0123456789abcdef"
    root = builder.build()
    # Changed with the decision-4 lint finding: this study.yaml declares no level_rule.manual.
    assert sorted(lint(root, "H1")) == sorted([
        ("CRITICAL", "MON-01: unrecognized verdict 'PASSS'"),
        ("WARNING", "MON-02: UNASSESSED without an unassessed_reason"),
        ("CRITICAL", "MON-03: missing verdict"),
        ("CRITICAL", "cmmi claimed: level '7' is outside 1-5"),
        ("CRITICAL", "missing level(s) for cmmi: current"),
        ("CRITICAL", "synthetic is yes, but the study configuration says synthetic: false"),
        ("WARNING", "enabled_checks_fingerprint does not match the check rows (rows edited, removed or reordered?)"),
        ("WARNING", agreement.NO_MANUAL_RULE),
    ])
    assert ("CRITICAL", "host_code is 'H1', expected 'H2'") in lint(root, "H1", as_host="H2")
    other = root / "inputs" / "H1-attestation.json"
    config = formats.load_study_config(root / formats.CONFIG_FILE)
    found = agreement.lint_worksheet(other, config, "H1")
    assert len(found) == 1 and found[0][0] == "CRITICAL"
    assert found[0][1].startswith("not a worksheet this command can read: H1-attestation.json")


def test_lint_checks_levels_against_the_declared_manual_rule(tmp_path):
    builder = approved_builder(tmp_path / "study", hosts=("H1", "H2"))
    builder.levels["H2"][("cmmi", "monitored")] = "4"            # the verdicts give 3/4 -> 3
    builder.levels["H2"][("cmmi", "overall")] = "2"              # pooled 4/5 -> 3
    builder.levels["H2"][("cmmi", "assessed")] = "UNASSESSED"    # 1/2 -> 3
    root = builder.build()
    assert lint(root, "H1") == []
    named = "the declared manual rule (approved, overall pooled-checks)"
    assert lint(root, "H2") == [
        ("WARNING", f"cmmi monitored: level 4 entered, but this worksheet's verdicts give level 3 under {named}"),
        ("WARNING", f"cmmi assessed: UNASSESSED entered, but this worksheet's verdicts give level 3 under {named}"),
        ("WARNING", f"cmmi overall: level 2 entered, but this worksheet's verdicts give level 3 under {named}")]


def test_lint_checks_the_overall_level_only_when_the_rule_defines_one(tmp_path):
    rule = {"manual": "approved", "tool_side": "tool-cutoffs", "overall": None}
    builder = approved_builder(tmp_path / "approved", rule=rule)
    builder.levels["H1"][("cmmi", "overall")] = "1"                       # not checked: no overall rule
    builder.levels["H1"][("cmmi", "overall_excl_input_driven")] = "1"     # not checked either
    builder.levels["H1"][("cmmi", "current")] = "4"                       # 5/6 -> 3
    root = builder.build()
    # Changed with the decision-4 lint finding: without level_rule.overall the lint now says so (V2-N2).
    assert lint(root, "H1") == [
        ("WARNING", "overall levels not checked: level_rule.overall is not declared, and the approved rule defines no "
                    "overall level (decision 4)"),
        ("WARNING", "cmmi current: level 4 entered, but this worksheet's verdicts give level 3 under the declared "
                    "manual rule (approved)")]
    # tool-cutoffs defines its own overall level, so it is checked; the default levels are the tool's own.
    rule = {"manual": "tool-cutoffs", "tool_side": "tool-cutoffs", "overall": None}
    builder = StudyBuilder(tmp_path / "cutoffs", hosts=("H1",), level_rule=rule)
    builder.levels["H1"][("cmmi", "overall")] = "3"                       # miccmac's cutoffs give 4
    root = builder.build()
    assert lint(root, "H1") == [
        ("WARNING", "cmmi overall: level 3 entered, but this worksheet's verdicts give level 4 under the declared "
                    "manual rule (tool-cutoffs)")]


def test_lint_accepts_unassessed_where_nothing_can_be_scored_and_skips_missing_verdicts(tmp_path):
    builder = approved_builder(tmp_path / "study", hosts=("H1", "H2", "H3"))
    for host in ("H1", "H2"):
        for check in ("CLM-01", "CLM-02", "CLM-03"):
            builder.verdicts[host][check] = ("UNASSESSED", "owner records not available")
    builder.levels["H1"][("cmmi", "claimed")] = "UNASSESSED"     # nothing scorable: agrees (overall 35/44 -> 3)
    builder.levels["H2"][("cmmi", "claimed")] = "2"
    builder.verdicts["H3"]["MON-03"] = ("", "")                   # monitored and both overall scopes: not derived
    builder.levels["H3"][("cmmi", "monitored")] = "1"
    root = builder.build()
    assert lint(root, "H1") == []
    assert lint(root, "H2") == [
        ("WARNING", "cmmi claimed: level 2 entered, but no verdict of this scope can be scored (all N/A or "
                    "UNASSESSED), so the declared manual rule (approved, overall pooled-checks) gives no level; "
                    "enter UNASSESSED")]
    assert lint(root, "H3") == [("CRITICAL", "MON-03: missing verdict")]


def test_lint_says_when_the_level_rule_is_not_declared(tmp_path):
    """V2-N2, V3-N1: with level_rule.manual null (the template's default) no level is checked, and the lint says
    so; with the approved rule but no level_rule.overall, the overall levels are not checked."""
    root = StudyBuilder(tmp_path / "none", hosts=("H1",)).build()
    assert lint(root, "H1") == [
        ("WARNING", "levels not checked: the study configuration declares no level_rule.manual (decision 4); declare it before "
                    "hashing a worksheet")]
    root = approved_builder(tmp_path / "no-overall", rule={"manual": "approved", "tool_side": "tool-cutoffs",
                                                            "overall": None}).build()
    assert lint(root, "H1") == [
        ("WARNING", "overall levels not checked: level_rule.overall is not declared, and the approved rule defines no "
                    "overall level (decision 4)")]


def test_lint_reports_blank_procedure_cells_and_a_blank_assessor_or_level_rule(tmp_path):
    """V3-N9: on a check that is not UNASSESSED, a blank pass_criterion, evidence_procedure or procedure_source
    (one finding per column, listing the checks); a blank assessor or level_rule meta value."""
    builder = approved_builder(tmp_path / "study")
    for check, column in (("MON-02", "procedure_source"), ("CTL-01", "procedure_source"), ("MON-01", "pass_criterion"),
                          ("INV-01", "evidence_procedure")):
        builder.cell_edits["H1"].setdefault(check, {})[column] = ""
    builder.verdicts["H1"]["MON-03"] = ("UNASSESSED", "no access to the log host")      # blank cells allowed here
    builder.cell_edits["H1"]["MON-03"] = {"pass_criterion": "", "evidence_procedure": "", "procedure_source": ""}
    builder.meta["H1"]["assessor"] = ""
    builder.meta["H1"]["level_rule"] = " "
    root = builder.build()
    assert lint(root, "H1") == [
        ("WARNING", "meta assessor is blank: write who filled in this sheet"),
        ("WARNING", "meta level_rule is blank: write the manual level rule you applied (protocol section 6)"),
        ("WARNING", "pass_criterion is blank for MON-01: write what had to be true for a pass"),
        ("WARNING", "evidence_procedure is blank for INV-01: write the steps you followed"),
        ("WARNING", "procedure_source is blank for MON-02, CTL-01: write NONE when no external procedure exists")]
    builder = approved_builder(tmp_path / "none-written")
    builder.cell_edits["H1"]["MON-02"] = {"procedure_source": "NONE"}                 # protocol section 6
    assert lint(builder.build(), "H1") == []


def test_ledger_record_refuses_a_sheet_with_the_new_lint_findings_unless_forced(tmp_path, capsys):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.cell_edits["H1"]["MON-02"] = {"procedure_source": ""}
    builder.ledger = False
    root = builder.build()
    sheet = root / formats.WORKSHEETS_DIR / formats.worksheet_name("H1")
    blank = "procedure_source is blank for MON-02: write NONE when no external procedure exists"
    assert record(root, "H1", "worksheet", sheet) == 2
    err = capsys.readouterr().err.splitlines()
    assert f"lint WARNING {sheet}: {blank}" in err and f"lint WARNING {sheet}: {agreement.NO_MANUAL_RULE}" in err
    assert not (root / formats.LEDGER_FILE).exists()
    assert main(["ledger", "record", "--ledger", str(root / formats.LEDGER_FILE), "--host", "H1", "--kind",
                 "worksheet", "--force", str(sheet)]) == 0
    assert ledger_rows(root)[0]["note"] == f"{ledger.LINT_NOTE_PREFIX}WARNING {blank}; WARNING {agreement.NO_MANUAL_RULE}"


def test_lint_reads_only_the_worksheet_and_the_configuration(tmp_path):
    root = approved_builder(tmp_path / "study").build()
    config = formats.load_study_config(root / formats.CONFIG_FILE)
    sheet = root / formats.WORKSHEETS_DIR / formats.worksheet_name("H1")
    opened: List[Path] = []
    read_bytes, read_text, real_open = Path.read_bytes, Path.read_text, open

    def spy_open(file, *args, **kwargs):
        opened.append(Path(file))
        return real_open(file, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "read_bytes", lambda self: opened.append(self) or read_bytes(self))
        patch.setattr(Path, "read_text", lambda self, *a, **k: opened.append(self) or read_text(self, *a, **k))
        patch.setattr("builtins.open", spy_open)
        patch.setattr(agreement, "load_tool_output", lambda path: pytest.fail("a tool output was read"))
        assert agreement.lint_worksheet(sheet, config, "H1") == []
    assert sheet in opened
    assert [p for p in opened if formats.OUTPUTS_DIR in p.parts] == []


# ------------------------------------------------------------------ study.yaml encodings (BI-11, RD-07)
CONFIG_TEXT = "# study configuration – encoding test\nhosts: [H1, H2]\nthreshold: 0.80\n"


@pytest.mark.parametrize("data", [
    CONFIG_TEXT.encode("utf-8"),
    CONFIG_TEXT.encode("utf-8-sig"),                       # Notepad's UTF-8 with a byte-order mark
    CONFIG_TEXT.encode("utf-16"),                          # PowerShell 5.1 '>' or Out-File: UTF-16 with a mark
    b"\xfe\xff" + CONFIG_TEXT.encode("utf-16-be"),
    CONFIG_TEXT.encode("cp1252"),                          # ANSI: the en dash is byte 0x96
])
def test_study_yaml_saved_as_utf8_utf16_or_ansi_is_read(tmp_path, data):
    path = tmp_path / "study.yaml"
    path.write_bytes(data)
    config = formats.load_study_config(path)
    assert (config.hosts, config.threshold) == (["H1", "H2"], Fraction(4, 5))


@pytest.mark.parametrize("data", [
    b"hosts: [H1]\n# \x81\x8d\x8f\x90\x9d\n",             # neither UTF-8 nor Windows-1252
    "hosts: [H1]\n".encode("utf-16-le"),                  # UTF-16 without a byte-order mark
    b"\xef\xbb\xbfhosts: [H1]\n# caf\xe9\n",               # a UTF-8 mark, then an ANSI byte
    b"\xff\xfeh",                                         # UTF-16 cut short
])
def test_a_study_yaml_that_cannot_be_decoded_asks_for_utf8(tmp_path, capsys, data):
    path = tmp_path / "study.yaml"
    path.write_bytes(data)
    with pytest.raises(formats.StudyError, match="save study.yaml as UTF-8"):
        formats.load_study_config(path)
    root = StudyBuilder(tmp_path / "study", hosts=("H1",)).build()
    (root / formats.CONFIG_FILE).write_bytes(data)
    assert run_agreement(root) == 2                        # an error message, not a traceback
    assert "save study.yaml as UTF-8" in capsys.readouterr().err


# ------------------------------------------------------------------ H2 by entry type (missing-data entries)

def _register(root: Path) -> Dict[str, Dict[str, str]]:
    return {r["host"]: r for r in csv_rows(out_file(root, "register_h2.csv"))}


def test_h2_counts_missing_data_entries_and_reports_them_apart(tmp_path):
    """H1 has no inventory record (its file holds null): INV-01 and INV-04
    become missing-data entries; an ERROR (MON-01, forced) is one too. Every
    entry counts in H2's n; the split adds up."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.inventory["H1"] = None
    builder.forced_statuses["H1"] = {"MON-01": "ERROR"}
    builder.judge_all("H1", {"INV-01": ("Y", "Y", "Y"), "INV-04": ("Y", "N", "N"), "MON-01": ("N", "Y", "Y")})
    builder.judge_all("H2")
    root = builder.build()
    kinds = {e.check_id: e.entry_type for e in build_risk_register(builder.assessment("H1", "cmmi"))}
    assert {c for c, k in kinds.items() if k == "missing-data"} == {"INV-01", "INV-04", "MON-01"}
    assert run_agreement(root) == 0
    rows = _register(root)
    h1, total = rows["H1"], rows["TOTAL"]
    assert (h1["entries"], h1["judged"], h1["k"]) == (str(len(kinds)), str(len(kinds)), str(len(kinds) - 2))
    assert (h1["missing_data_entries"], h1["missing_data_judged"], h1["missing_data_k"]) == ("3", "3", "1")
    assert (h1["finding_entries"], h1["finding_judged"], h1["finding_k"]) == (
        str(len(kinds) - 3), str(len(kinds) - 3), str(len(kinds) - 3))
    for row in rows.values():
        assert int(row["finding_k"]) + int(row["missing_data_k"]) == int(row["k"])
        assert int(row["finding_judged"]) + int(row["missing_data_judged"]) == int(row["n"])
    assert total["h2_unit"] == "all-entries" and h1["h2_unit"] == ""
    assert total["meets_threshold"] in ("yes", "no") and total["finding_meets_threshold"] in ("yes", "no")
    assert h1["finding_meets_threshold"] == ""                    # per-host rows carry no threshold
    text = " ".join(out_file(root, "summary.md").read_text(encoding="utf-8").split())
    assert "### 4.1 By entry type" in text
    assert ("Unit pre-registered for the threshold (study.yaml h2_unit): all-entries. The threshold result above "
            "(TOTAL, all entries) is the H2 test; the findings row below is descriptive.") in text
    assert f"Of the {total['entries']} entries, 3 are missing-data entries (k = 1 of 3 judged)." in text
    h2 = summary(root)["h2"]
    assert h2["h2_unit"] == "all-entries" and h2["total"]["missing_data_entries"] == 3


def test_h2_unit_findings_puts_the_threshold_on_the_findings_row(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",), h2_unit="findings")
    builder.inventory["H1"] = None
    builder.judge_all("H1", default=("Y", "Y", "Y"))
    root = builder.build()
    assert run_agreement(root) == 0
    total = _register(root)["TOTAL"]
    assert total["h2_unit"] == "findings"
    assert total["finding_meets_threshold"] == "yes" and total["finding_k"] == total["finding_judged"]
    text = " ".join(out_file(root, "summary.md").read_text(encoding="utf-8").split())
    assert "The findings row below is the H2 test; the TOTAL row above (all entries) is descriptive." in text
    assert "Findings only (the pre-registered H2 test): k/n = " in text
    assert summary(root)["config"]["h2_unit"] == "findings"


def test_h2_unit_findings_labels_every_statement_of_the_threshold_result(tmp_path):
    """Verifier findings: with h2_unit findings, section 4 still said that the
    threshold applies to the TOTAL row and printed its result as the test,
    summary.json named no test, section 1 did not show the unit, and the
    hand-check pointed at the TOTAL k/n."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",), h2_unit="findings")
    builder.inventory["H1"] = None                                   # INV-01, INV-04: missing-data entries
    builder.judge_all("H1", {"INV-01": ("N", "Y", "Y")})
    root = builder.build()
    assert run_agreement(root) == 0
    text = " ".join(out_file(root, "summary.md").read_text(encoding="utf-8").split())
    assert "the threshold applies to the TOTAL row" not in text
    assert ("Per-host rows are descriptive, and with h2_unit findings so is the TOTAL row's threshold result: the "
            "threshold test is the findings row of section 4.1.") in text
    assert "TOTAL (all entries, descriptive with h2_unit findings): k/n = " in text
    assert "| H2 threshold unit (study.yaml h2_unit) | findings (findings only; all entries descriptive) |" in text
    assert ("H2 threshold test (h2_unit findings, section 4.1): the TOTAL row's finding_k / finding_judged and "
            "finding_meets_threshold") in text
    total = _register(root)["TOTAL"]
    test = summary(root)["h2"]["test"]
    assert (test["unit"], test["preregistered_unit"], test["unit_is_preregistered"]) == ("findings", "findings", True)
    assert (test["k"], test["n"]) == (int(total["finding_k"]), int(total["finding_judged"]))
    assert test["meets_threshold"] is (total["finding_meets_threshold"] == "yes") is True
    assert int(total["k"]) < int(total["n"])                         # all entries: INV-01 is not k


def test_the_h2_test_block_and_section_1_for_the_default_unit(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.judge_all("H1", {"MON-02": ("N", "Y", "Y")})
    root = builder.build()
    assert run_agreement(root) == 0
    total = _register(root)["TOTAL"]
    test = summary(root)["h2"]["test"]
    assert (test["unit"], test["k"], test["n"]) == ("all-entries", int(total["k"]), int(total["n"]))
    assert test["meets_threshold"] is (total["meets_threshold"] == "yes")
    assert (test["needed"], test["threshold"]) == (summary(root)["h2"]["total"]["needed"], 0.8)
    text = out_file(root, "summary.md").read_text(encoding="utf-8")
    assert "| H2 threshold unit (study.yaml h2_unit) | all-entries (every register entry) |" in text
    assert "Per-host rows are descriptive; the threshold applies to the TOTAL row." in " ".join(text.split())
    assert "H2 threshold test (h2_unit findings" not in text


def test_a_sensitivity_run_with_another_h2_unit_names_the_preregistered_one(tmp_path):
    """Verifier finding: a --config run with h2_unit findings, after the seal
    opened with all-entries, called findings the pre-registered unit."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.judge_all("H1")
    root = builder.build()
    assert run_agreement(root) == 0                                  # the seal opens with all-entries
    other = root / "study-h2f.yaml"
    other.write_text(yaml.safe_dump(dict(builder.config, h2_unit="findings"), sort_keys=False), encoding="utf-8")
    assert record(root, "STUDY", "other", other, note="h2 unit sensitivity") == 0
    assert run_agreement(root, "--config", str(other), "--out", str(root / "h2f")) == 3
    md = " ".join((root / "h2f" / "summary.md").read_text(encoding="utf-8").split())
    assert "Unit pre-registered for the threshold" not in md
    assert ("Unit used for the threshold in this run (study-h2f.yaml h2_unit): findings; the pre-registered unit is "
            "all-entries (") in md
    assert "The findings row below is this run's threshold test;" in md
    assert "Findings only (this run's threshold test, a sensitivity run): k/n = " in md
    assert ("findings (findings only; all entries descriptive); the pre-registered unit is all-entries "
            "(sensitivity run)") in md
    data = json.loads((root / "h2f" / "summary.json").read_text(encoding="utf-8"))
    assert (data["h2"]["test"]["unit"], data["h2"]["test"]["preregistered_unit"],
            data["h2"]["test"]["unit_is_preregistered"]) == ("findings", "all-entries", False)


def test_findings_only_studies_give_the_same_counts_in_both_units(tmp_path):
    """The StudyBuilder's own register has findings only (every input
    given): the split changes nothing in the old columns."""
    builder = StudyBuilder(tmp_path / "study", hosts=("H1", "H2"))
    builder.judge_all("H1", {"MON-02": ("N", "Y", "Y")})
    builder.judge_all("H2")
    root = builder.build()
    assert run_agreement(root) == 0
    for row in _register(root).values():
        assert (row["finding_k"], row["finding_judged"]) == (row["k"], row["n"])
        assert row["missing_data_entries"] == "0"
    total = _register(root)["TOTAL"]
    assert (total["finding_rate"], total["finding_wilson_low"]) == (total["rate"], total["wilson_low"])
    assert (total["finding_boot_low"], total["finding_boot_high"]) == (total["boot_low"], total["boot_high"])


def test_the_optional_judgments_are_counted_and_never_enter_k(tmp_path):
    builder = StudyBuilder(tmp_path / "study", hosts=("H1",))
    builder.judge_all("H1")
    builder.optional_reviews["H1"] = {"MON-02": {"next_level_accurate": "Y", "threat_plausible": "N"},
                                      "INV-04": {"next_level_accurate": "no", "threat_plausible": ""},
                                      "CLM-03": {"next_level_accurate": "maybe"}}
    root = builder.build()
    assert run_agreement(root) == 0                    # an unreadable optional answer is only a WARNING
    total = _register(root)["TOTAL"]
    assert (total["next_level_accurate_y"], total["next_level_accurate_n"]) == ("1", "1")
    assert (total["threat_plausible_y"], total["threat_plausible_n"]) == ("0", "1")
    assert total["k"] == total["n"] == total["entries"]
    warnings = [f["detail"] for f in findings(root, "WARNING") if f["check"] == "register"]
    assert any(d.startswith("CLM-03 next_level_accurate: unrecognized answer 'maybe'") for d in warnings)


def test_h2_unit_is_a_study_setting(tmp_path):
    assert formats.study_config_from_dict({"hosts": ["H1"]}).h2_unit == "all-entries"
    assert formats.study_config_from_dict({"hosts": ["H1"], "h2_unit": " Findings "}).h2_unit == "findings"
    with pytest.raises(formats.StudyError, match="h2_unit must be one of all-entries, findings"):
        formats.study_config_from_dict({"hosts": ["H1"], "h2_unit": "everything"})
    text = formats.config_template(["H1"])
    assert "h2_unit: all-entries" in text and formats.study_config_from_dict(yaml.safe_load(text)).h2_unit == (
        "all-entries")
    reference = formats.study_config_from_dict({"hosts": ["H1"]})
    used = formats.study_config_from_dict({"hosts": ["H1"], "h2_unit": "findings"})
    assert agreement._config_differences(reference, used) == ["h2_unit all-entries -> findings"]
