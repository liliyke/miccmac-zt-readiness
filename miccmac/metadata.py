"""Loads and indexes the per-check CIS Implementation Group / FAIR-inspired
risk metadata from data/control-mappings.yaml's `checks:` section, and
derives the canonical built-in check-id manifest from it.

This module never imports miccmac.checks.* -- it is the single source of
truth for "what built-in check ids exist and what property they belong to",
read from data, not from the check modules themselves.

The file's optional `threats:` section adds, per check, the NIST SP 800-30
Rev. 1 threat-source type and a short threat event that the risk register
shows (load_threat_metadata). It is read only for the register
(load_register_metadata): the check manifest (builtin_check_ids_by_property,
all_builtin_check_ids) and load_check_metadata read `checks:` alone, so an
error in `threats:` never stops `list-checks`, an assessment without
--risk-register, or the study's worksheet and input checks.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from miccmac.model import PROPERTY_KEYS

DEFAULT_MAPPINGS_PATH = Path(__file__).resolve().parent.parent / "data" / "control-mappings.yaml"

VALID_IGS = ("IG1", "IG2", "IG3")
VALID_FAIR_LEVELS = ("LOW", "MEDIUM", "HIGH")
# NIST SP 800-30 Rev. 1 Appendix D threat-source types.
VALID_THREAT_SOURCE_TYPES = ("adversarial", "accidental", "structural", "environmental")
# Review state of a check's drafted threat fields: drafted (not yet
# confirmed) or confirmed by the researcher.
VALID_REVIEW_STATES = ("drafted", "confirmed")


class MappingsError(RuntimeError):
    """Raised for a missing/unreadable file, invalid YAML, or a checks: entry
    that fails schema validation."""


@dataclass(frozen=True)
class CheckMetadata:
    check_id: str
    property_key: str
    cis_ig: str
    fair_frequency: str
    fair_magnitude: str
    # Recommended fix for a FAIL/PARTIAL result, shown in the risk register.
    # Optional (defaults to None) so existing custom-check plugins that don't
    # declare one keep working -- see miccmac/config.py.
    remediation: Optional[str] = None
    # NIST SP 800-30 Rev. 1 fields from the `threats:` section (None when the
    # file has none, and for a custom check that declares none): the Appendix
    # D threat-source type, a short generic threat event, and the review
    # state of those two (drafted/confirmed; always None for custom checks).
    threat_source_type: Optional[str] = None
    threat_event: Optional[str] = None
    sp800_30_review: Optional[str] = None


def load_raw_mappings(path: Path | str = DEFAULT_MAPPINGS_PATH) -> dict:
    """Load and parse control-mappings.yaml, wrapping I/O and parse errors."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MappingsError(f"cannot read control mappings file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise MappingsError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MappingsError(f"{path}: expected a top-level mapping, got {type(data).__name__}")
    return data


def load_check_metadata(path: Path | str = DEFAULT_MAPPINGS_PATH) -> Dict[str, CheckMetadata]:
    """Validate and index the top-level `checks:` list into check_id -> CheckMetadata."""
    path = Path(path)
    data = load_raw_mappings(path)
    entries = data.get("checks")
    if not isinstance(entries, list) or not entries:
        raise MappingsError(f"{path}: missing or empty top-level 'checks:' list")

    result: Dict[str, CheckMetadata] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise MappingsError(f"{path}: checks[{i}] is not a mapping")

        check_id = entry.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            raise MappingsError(f"{path}: checks[{i}] missing a valid check_id")
        if check_id in result:
            raise MappingsError(f"{path}: duplicate check_id {check_id!r}")

        property_key = entry.get("property_key")
        if property_key not in PROPERTY_KEYS:
            raise MappingsError(
                f"{path}: {check_id} has unknown property_key {property_key!r}; "
                f"must be one of {PROPERTY_KEYS}"
            )

        cis_ig = entry.get("cis_ig")
        if cis_ig not in VALID_IGS:
            raise MappingsError(
                f"{path}: {check_id} has invalid cis_ig {cis_ig!r}; must be one of {VALID_IGS}"
            )

        fair_frequency = entry.get("fair_frequency")
        fair_magnitude = entry.get("fair_magnitude")
        if fair_frequency not in VALID_FAIR_LEVELS:
            raise MappingsError(
                f"{path}: {check_id} has invalid fair_frequency {fair_frequency!r}; "
                f"must be one of {VALID_FAIR_LEVELS}"
            )
        if fair_magnitude not in VALID_FAIR_LEVELS:
            raise MappingsError(
                f"{path}: {check_id} has invalid fair_magnitude {fair_magnitude!r}; "
                f"must be one of {VALID_FAIR_LEVELS}"
            )

        remediation = entry.get("remediation")
        if not isinstance(remediation, str) or not remediation.strip():
            raise MappingsError(
                f"{path}: {check_id} missing a non-empty remediation string -- every "
                f"built-in check must recommend a fix for its risk register entry"
            )

        result[check_id] = CheckMetadata(
            check_id=check_id,
            property_key=property_key,
            cis_ig=cis_ig,
            fair_frequency=fair_frequency,
            fair_magnitude=fair_magnitude,
            remediation=remediation,
        )
    return result


def load_threat_metadata(path: Path | str = DEFAULT_MAPPINGS_PATH,
                         check_ids: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, str]]:
    """Validate and index the optional top-level `threats:` list into
    check_id -> {"threat_source_type", "threat_event", "review"}; {} when the
    file has no `threats:` section.

    When present it must be a list of mappings, each with a check_id of the
    `checks:` section (``check_ids``; default: read from the same file), no
    duplicates, a threat_source_type of VALID_THREAT_SOURCE_TYPES, a
    non-empty threat_event and a review of VALID_REVIEW_STATES, and it must
    cover every check of `checks:`, so that a half-filled section cannot
    leave some entries without these fields. Raises MappingsError naming the
    file and the check ids."""
    path = Path(path)
    data = load_raw_mappings(path)
    if "threats" not in data:
        return {}
    entries = data["threats"]
    if not isinstance(entries, list):
        raise MappingsError(f"{path}: 'threats:' must be a list of per-check entries")
    known = list(check_ids) if check_ids is not None else list(load_check_metadata(path))
    result: Dict[str, Dict[str, str]] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise MappingsError(f"{path}: threats[{i}] is not a mapping")
        check_id = entry.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            raise MappingsError(f"{path}: threats[{i}] missing a valid check_id")
        if check_id not in known:
            raise MappingsError(f"{path}: threats[{i}] names {check_id!r}, which is not in the 'checks:' section")
        if check_id in result:
            raise MappingsError(f"{path}: duplicate threats entry for {check_id!r}")
        source_type = entry.get("threat_source_type")
        if source_type not in VALID_THREAT_SOURCE_TYPES:
            raise MappingsError(f"{path}: {check_id} has invalid threat_source_type {source_type!r}; "
                                f"must be one of {VALID_THREAT_SOURCE_TYPES}")
        event = entry.get("threat_event")
        if not isinstance(event, str) or not event.strip():
            raise MappingsError(f"{path}: {check_id} missing a non-empty threat_event string")
        review = entry.get("review")
        if review not in VALID_REVIEW_STATES:
            raise MappingsError(f"{path}: {check_id} has invalid review {review!r}; "
                                f"must be one of {VALID_REVIEW_STATES}")
        unknown = set(entry) - {"check_id", "threat_source_type", "threat_event", "review"}
        if unknown:
            raise MappingsError(f"{path}: {check_id} threats entry has unknown key(s) {sorted(unknown)}")
        result[check_id] = {"threat_source_type": source_type, "threat_event": " ".join(event.split()),
                            "review": review}
    missing = [check_id for check_id in known if check_id not in result]
    if missing:
        raise MappingsError(f"{path}: the 'threats:' section has no entry for {', '.join(missing)}; when "
                            f"present it must cover every check of 'checks:'")
    return result


def load_register_metadata(path: Path | str = DEFAULT_MAPPINGS_PATH) -> Dict[str, CheckMetadata]:
    """load_check_metadata with the `threats:` fields filled in (they stay
    None when the file has no `threats:` section): what the risk register
    reads. Raises MappingsError for either section."""
    metadata = load_check_metadata(path)
    threats = load_threat_metadata(path, check_ids=list(metadata))
    for check_id, fields in threats.items():
        metadata[check_id] = dataclasses.replace(
            metadata[check_id], threat_source_type=fields["threat_source_type"],
            threat_event=fields["threat_event"], sp800_30_review=fields["review"])
    return metadata


def builtin_check_ids_by_property(path: Path | str = DEFAULT_MAPPINGS_PATH) -> Dict[str, List[str]]:
    """property_key -> sorted [check_id, ...]."""
    by_property: Dict[str, List[str]] = {key: [] for key in PROPERTY_KEYS}
    for meta in load_check_metadata(path).values():
        by_property[meta.property_key].append(meta.check_id)
    for ids in by_property.values():
        ids.sort()
    return by_property


def all_builtin_check_ids(path: Path | str = DEFAULT_MAPPINGS_PATH) -> List[str]:
    """Flat sorted list of every built-in check_id."""
    return sorted(load_check_metadata(path).keys())
