"""Saved facts files: ``assess --save-facts FILE`` writes the facts a
connector collected, and ``assess --facts FILE`` scores them again later
without connecting to the target (for example under a second methodology,
or to re-test fixed check logic against the same raw data).

Format "miccmac-facts/1": UTF-8 JSON, indented by 2, ending in a newline,
with these keys in this order:

    facts_format       "miccmac-facts/1"
    tool_version       miccmac version that collected the facts
    tool_commit        git commit of that miccmac (40 hex characters) or null
    connector          the connector used, e.g. "ssh-osquery"
    target             the target as given on the command line
    collected_at_utc   when collection finished, "YYYY-MM-DDTHH:MM:SSZ"
    as_of              the run's --as-of date "YYYY-MM-DD", or null
    facts              the facts the checks read (context["facts"]), including
                       facts["extra"], the extended facts (connectors/base.py)

A saved facts file is raw study data, so it is never overwritten: saving
refuses an existing path, and the file is written whole or not at all (a
temporary file in the same folder, then os.replace).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from miccmac import clock
from miccmac.config import ConfigError

FACTS_FORMAT = "miccmac-facts/1"
ENVELOPE_KEYS = (
    "facts_format", "tool_version", "tool_commit", "connector", "target",
    "collected_at_utc", "as_of", "facts",
)


class FactsFileError(ConfigError):
    """A saved facts file cannot be written, read, or is not a valid
    miccmac-facts/1 file. A ConfigError, so the CLI reports it as
    'error: ...' and exits with status 2."""


@dataclass(frozen=True)
class SavedFacts:
    """What save_envelope wrote."""
    path: str
    sha256: str
    # The facts exactly as a later --facts replay will read them back.
    facts: dict


@dataclass(frozen=True)
class LoadedFacts:
    """A validated facts file, as read by load_envelope."""
    path: str
    sha256: str
    envelope: dict

    @property
    def facts(self) -> dict:
        return self.envelope["facts"]

    @property
    def target(self) -> str:
        return self.envelope["target"]

    @property
    def connector(self) -> Optional[str]:
        return self.envelope.get("connector")

    @property
    def collected_at_utc(self) -> str:
        return self.envelope["collected_at_utc"]

    @property
    def collected_date(self) -> datetime.date:
        """The UTC calendar date on which collection finished."""
        return clock.parse_utc(self.collected_at_utc).date()

    @property
    def as_of(self) -> Optional[datetime.date]:
        raw = self.envelope.get("as_of")
        return None if raw is None else clock.parse_as_of(raw)


def build_envelope(facts: dict, *, tool_version: str, tool_commit: Optional[str],
                   connector: str, target: str, collected_at_utc: str,
                   as_of: Optional[datetime.date]) -> dict:
    """The envelope dict, keys in ENVELOPE_KEYS order."""
    return {
        "facts_format": FACTS_FORMAT,
        "tool_version": tool_version,
        "tool_commit": tool_commit,
        "connector": connector,
        "target": target,
        "collected_at_utc": collected_at_utc,
        "as_of": None if as_of is None else as_of.isoformat(),
        "facts": facts,
    }


def encode_envelope(envelope: dict) -> bytes:
    """The exact bytes of a facts file: JSON indented by 2, newline-terminated, UTF-8."""
    return (json.dumps(envelope, indent=2) + "\n").encode("utf-8")


def check_can_save(path: str) -> None:
    """Refuse a --save-facts path that already exists or whose folder does
    not exist. Called before connecting, so nothing is collected in vain."""
    target = Path(path)
    if target.exists():
        raise FactsFileError(
            f"--save-facts file already exists: {path}; refusing to overwrite saved facts "
            f"(raw study data is never replaced; choose a new file name)"
        )
    folder = target.parent
    if not folder.is_dir():
        raise FactsFileError(f"--save-facts folder does not exist: {folder}")


def save_envelope(path: str, envelope: dict) -> SavedFacts:
    """Write a facts file atomically (a temporary file in the same folder,
    then os.replace) and return its SHA-256 and the facts as written.
    Refuses an existing path."""
    data = encode_envelope(envelope)
    check_can_save(path)
    target = Path(path)
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp",
                                        dir=str(target.parent))
    except OSError as exc:
        raise FactsFileError(f"cannot write --save-facts file {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        check_can_save(path)  # once more, in case the file appeared meanwhile
        os.replace(tmp_name, str(target))
    except BaseException as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        if isinstance(exc, OSError):
            raise FactsFileError(f"cannot write --save-facts file {path}: {exc}") from exc
        raise
    written = json.loads(data.decode("utf-8"))
    return SavedFacts(path=path, sha256=hashlib.sha256(data).hexdigest(), facts=written["facts"])


def load_envelope(path: str) -> LoadedFacts:
    """Read and validate a facts file; FactsFileError if it is not usable."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise FactsFileError(f"cannot read --facts file: {exc}") from exc
    try:
        envelope = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FactsFileError(f"--facts file {path} is not valid UTF-8 JSON: {exc}") from exc
    validate_envelope(envelope, path)
    return LoadedFacts(path=path, sha256=hashlib.sha256(data).hexdigest(), envelope=envelope)


def validate_envelope(envelope: object, source: str) -> None:
    """Check the parts of an envelope that a replay relies on."""
    prefix = f"--facts file {source}"
    if not isinstance(envelope, dict):
        raise FactsFileError(f"{prefix} is not a miccmac facts file (expected a JSON object)")
    facts_format = envelope.get("facts_format")
    if facts_format != FACTS_FORMAT:
        raise FactsFileError(f"{prefix}: facts_format is {facts_format!r}, expected {FACTS_FORMAT!r}")
    facts = envelope.get("facts")
    if not isinstance(facts, dict) or "os" not in facts:
        raise FactsFileError(f"{prefix}: 'facts' must be an object containing 'os'")
    if not isinstance(facts["os"], dict):
        raise FactsFileError(f"{prefix}: facts['os'] must be an object")
    target = envelope.get("target")
    if not isinstance(target, str) or not target:
        raise FactsFileError(f"{prefix}: 'target' must be a non-empty string")
    try:
        clock.parse_utc(envelope.get("collected_at_utc"))
    except ValueError as exc:
        raise FactsFileError(f"{prefix}: collected_at_utc: {exc}") from None
    as_of = envelope.get("as_of")
    if as_of is not None:
        try:
            clock.parse_as_of(as_of)
        except ValueError as exc:
            raise FactsFileError(f"{prefix}: as_of: {exc}") from None
