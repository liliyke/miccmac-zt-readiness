"""Loads run configuration: excluded built-in check IDs and custom check
plugins.

A config file (YAML, so a hand-written .json config also parses since JSON
is a YAML subset) looks like:

    excluded_checks:
      - check_id: MON-02
        reason: "No centralized SIEM in this pilot's environment."
      - check_id: CUR-04
        reason: "Certificate lifecycle is managed by a separate PKI audit."
    custom_checks_dir: ./my_checks

Every exclusion requires a recorded reason -- excluded checks are never
silently dropped. They still appear in the report, with status
NOT_APPLICABLE and detail "Excluded: <reason>", and are removed from that
property's scoring denominator rather than counted as a pass or fail.

Custom-check plugin interface: a single .py file dropped in
custom_checks_dir must define, at module scope:
  - CHECK_IDS: list[str]      -- non-empty; must not collide with a built-in
                                  id or another plugin's id.
  - ATTACH_TO: str             -- exactly one of miccmac.model.PROPERTY_KEYS.
                                  This is what structurally prevents an
                                  eighth property from ever appearing: the
                                  engine only ever iterates the fixed 7
                                  PROPERTY_MODULES and merges matching plugin
                                  output into the existing PropertyResult.
  - run_checks(target, context) -> list[CheckResult]
                                  Same shape as the built-in modules'
                                  _run_checks. Returned check_ids must
                                  exactly match CHECK_IDS.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

from miccmac.metadata import all_builtin_check_ids
from miccmac.model import PROPERTY_KEYS, CheckResult


class ConfigError(RuntimeError):
    """Raised for a malformed config file, an excluded_checks entry that
    names an unknown check_id, or a custom-check plugin that fails interface
    validation. Always names the offending file/id in the message."""


@dataclass(frozen=True)
class LoadedPlugin:
    module_name: str
    check_ids: List[str]
    attach_to: str
    run_checks: Callable[[str, dict], List[CheckResult]]


@dataclass
class Config:
    excluded_checks: Dict[str, str] = field(default_factory=dict)  # check_id -> reason
    custom_checks_dir: Optional[Path] = None
    _plugin_cache: Optional[Dict[str, List[LoadedPlugin]]] = field(
        default=None, init=False, repr=False, compare=False,
    )

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in config file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: expected a top-level mapping, got {type(data).__name__}")

        excluded = cls._parse_excluded_checks(data.get("excluded_checks", []), path)

        custom_dir_raw = data.get("custom_checks_dir")
        custom_dir: Optional[Path] = None
        if custom_dir_raw is not None:
            if not isinstance(custom_dir_raw, str):
                raise ConfigError(f"{path}: custom_checks_dir must be a string")
            custom_dir = Path(custom_dir_raw)
            if not custom_dir.is_absolute():
                custom_dir = (path.parent / custom_dir).resolve()

        return cls(excluded_checks=excluded, custom_checks_dir=custom_dir)

    @staticmethod
    def _parse_excluded_checks(raw, path: Path) -> Dict[str, str]:
        if not isinstance(raw, list):
            raise ConfigError(f"{path}: excluded_checks must be a list")
        excluded: Dict[str, str] = {}
        for i, entry in enumerate(raw):
            if not isinstance(entry, dict) or "check_id" not in entry or "reason" not in entry:
                raise ConfigError(
                    f"{path}: excluded_checks[{i}] must be a mapping with 'check_id' and "
                    f"'reason' (a plain check-id string is not enough -- every exclusion "
                    f"requires a recorded reason), got {entry!r}"
                )
            check_id, reason = entry["check_id"], entry["reason"]
            if not isinstance(check_id, str) or not check_id:
                raise ConfigError(f"{path}: excluded_checks[{i}].check_id must be a non-empty string")
            if not isinstance(reason, str) or not reason.strip():
                raise ConfigError(f"{path}: excluded_checks[{i}].reason must be a non-empty string")
            if check_id in excluded:
                raise ConfigError(f"{path}: duplicate excluded_checks entry for {check_id!r}")
            excluded[check_id] = reason
        return excluded

    def load_custom_checks(self) -> Dict[str, List[LoadedPlugin]]:
        """Discover, import, and validate every plugin under custom_checks_dir.
        Returns {} if custom_checks_dir is None. Result is grouped by
        attach_to property key and cached on first call."""
        if self._plugin_cache is not None:
            return self._plugin_cache
        if self.custom_checks_dir is None:
            self._plugin_cache = {}
            return self._plugin_cache

        directory = Path(self.custom_checks_dir)
        if not directory.is_dir():
            raise ConfigError(f"custom_checks_dir {directory} is not a directory")

        builtin_ids = set(all_builtin_check_ids())
        seen_plugin_ids: set[str] = set()
        by_property: Dict[str, List[LoadedPlugin]] = {}

        for py_file in sorted(directory.glob("*.py")):
            plugin = self._load_plugin_file(py_file, builtin_ids, seen_plugin_ids)
            seen_plugin_ids.update(plugin.check_ids)
            by_property.setdefault(plugin.attach_to, []).append(plugin)

        self._plugin_cache = by_property
        return by_property

    @staticmethod
    def _load_plugin_file(py_file: Path, builtin_ids: set, seen_plugin_ids: set) -> LoadedPlugin:
        module_name = f"miccmac_custom_check_{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"could not build an import spec for {py_file}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            raise ConfigError(f"failed to import custom check plugin {py_file}: {exc}") from exc

        check_ids = getattr(module, "CHECK_IDS", None)
        if not isinstance(check_ids, list) or not check_ids or not all(isinstance(c, str) for c in check_ids):
            raise ConfigError(f"{py_file}: must define a non-empty CHECK_IDS: list[str]")

        attach_to = getattr(module, "ATTACH_TO", None)
        if attach_to not in PROPERTY_KEYS:
            raise ConfigError(
                f"{py_file}: ATTACH_TO {attach_to!r} must be one of {PROPERTY_KEYS}"
            )

        run_checks = getattr(module, "run_checks", None)
        if not callable(run_checks):
            raise ConfigError(f"{py_file}: must define a callable run_checks(target, context)")

        collisions = set(check_ids) & builtin_ids
        if collisions:
            raise ConfigError(
                f"{py_file}: CHECK_IDS {sorted(collisions)} collide with built-in check ids"
            )
        collisions = set(check_ids) & seen_plugin_ids
        if collisions:
            raise ConfigError(
                f"{py_file}: CHECK_IDS {sorted(collisions)} collide with another custom check plugin"
            )

        return LoadedPlugin(
            module_name=module_name,
            check_ids=list(check_ids),
            attach_to=attach_to,
            run_checks=run_checks,
        )
