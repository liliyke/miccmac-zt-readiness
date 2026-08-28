"""Loads and indexes the per-check CIS Implementation Group / FAIR-inspired
risk metadata from data/control-mappings.yaml's `checks:` section, and
derives the canonical built-in check-id manifest from it.

This module never imports miccmac.checks.* -- it is the single source of
truth for "what built-in check ids exist and what property they belong to",
read from data, not from the check modules themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import yaml

from miccmac.model import PROPERTY_KEYS

DEFAULT_MAPPINGS_PATH = Path(__file__).resolve().parent.parent / "data" / "control-mappings.yaml"

VALID_IGS = ("IG1", "IG2", "IG3")
VALID_FAIR_LEVELS = ("LOW", "MEDIUM", "HIGH")


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

        result[check_id] = CheckMetadata(
            check_id=check_id,
            property_key=property_key,
            cis_ig=cis_ig,
            fair_frequency=fair_frequency,
            fair_magnitude=fair_magnitude,
        )
    return result


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
