"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Provenance block: which tool build, inputs, facts and reference date
produced an assessment, so a result file can be traced and run again.

The CLI adds it to the JSON output as assessment["provenance"] whenever
--connector, --facts, --as-of or --save-facts is used (a plain run without
them is unchanged). Text and markdown reports never show it. Format
"miccmac-provenance/1", keys in this order:

    provenance_format       "miccmac-provenance/1"
    tool_version            miccmac version
    tool_commit             `git rev-parse HEAD` of the repository holding this
                            miccmac package (40 hex characters), or null
    tool_tree_clean         true when git shows nothing uncommitted under
                            miccmac/ or data/: no change to a tracked file and
                            no untracked file (files that .gitignore ignores,
                            such as __pycache__/, do not count); false when it
                            does, null when that cannot be determined
    python_version          platform.python_version()
    platform                platform.platform() of the machine running the tool
    run_at_utc              when this run started, real clock (never as_of)
    as_of                   reference date "YYYY-MM-DD" for the date-dependent
                            checks, or null when the real clock was used
    as_of_source            "cli", "facts-file", "facts-collected-date" or null
    methodology             --methodology, or null
    risk_register           whether --risk-register was used
    target                  the target this run reports on
    facts_source            "connector", "facts-file" or "none"
    connector               --connector used by this run, or null
    facts_collected_at_utc  when the facts were collected, or null
    facts_file              {path, sha256, role "saved"|"replayed"} or null
    inputs                  {attestation, inventory_record, config}: each
                            {path, sha256} or null
    enabled_check_ids       the enabled check ids, as `miccmac list-checks` prints them
    enabled_check_ids_fingerprint  first 16 hex characters of SHA-256 over those
                            ids joined by "," (the study instruments use the same formula)
    os                      {platform, name, version, build} from the facts
    osquery_version         from the extended facts' osquery_info, or null
    extended_facts          whether the facts include extended facts ("extra")

File paths are recorded exactly as given on the command line, never made
absolute (that would put local folder names in a shared result file),
together with the SHA-256 of the file's bytes.
"""
from __future__ import annotations

import datetime
import functools
import hashlib
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import List, Mapping, Optional, Sequence

from miccmac import __version__

PROVENANCE_FORMAT = "miccmac-provenance/1"
INPUT_KEYS = ("attestation", "inventory_record", "config")
FACTS_SOURCES = ("connector", "facts-file", "none")
AS_OF_SOURCES = ("cli", "facts-file", "facts-collected-date")

# The repository that holds this package: miccmac/ sits at its top level.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_GIT_TIMEOUT_SECONDS = 5
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# Only the tool's own files decide whether the working tree is "clean".
_TOOL_PATHS = ("miccmac", "data")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(path: str, data: bytes) -> dict:
    """{"path": path as given, "sha256": SHA-256 of data}."""
    return {"path": path, "sha256": sha256_bytes(data)}


def check_ids_fingerprint(ids: Sequence[str]) -> str:
    """First 16 hex characters of SHA-256 over the ids joined by ','.
    Must stay identical to miccmac_study.formats.check_ids_fingerprint."""
    return hashlib.sha256(",".join(ids).encode("utf-8")).hexdigest()[:16]


def _run_git(*args: str) -> Optional[str]:
    """stdout of `git <args>` run in the repository root, or None on any
    failure (git missing, not a repository, non-zero exit, timeout).
    GIT_OPTIONAL_LOCKS=0 keeps `git status` from writing the index."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    try:
        proc = subprocess.run(
            ["git", *args], cwd=str(_REPO_ROOT), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def _same_folder(a: str, b: Path) -> bool:
    try:
        return os.path.samefile(a, str(b))
    except (OSError, ValueError):
        return False


@functools.lru_cache(maxsize=None)
def tool_commit() -> Optional[str]:
    """The commit this miccmac package was run from, or None. Only trusted
    when git's top-level folder is the one holding the miccmac package, so a
    copy installed inside some other repository is never misattributed.
    Cached for the life of the process."""
    out = _run_git("rev-parse", "--show-toplevel", "HEAD")
    if out is None:
        return None
    lines = out.strip().splitlines()
    if len(lines) != 2 or not _same_folder(lines[0].strip(), _REPO_ROOT):
        return None
    commit = lines[1].strip().lower()
    return commit if _COMMIT_RE.fullmatch(commit) else None


@functools.lru_cache(maxsize=None)
def tool_tree_clean() -> Optional[bool]:
    """True when `git status --porcelain --untracked-files=normal -- miccmac
    data` prints nothing, False when it prints anything, None when it cannot
    run (including when tool_commit() is None). Cached for the life of the
    process.

    Untracked files count: a new module that the commit does not contain
    (for example one added for a fix and never `git add`-ed) means the
    recorded commit cannot reproduce the run. Ignored files (.gitignore:
    __pycache__/, *.py[cod]) stay hidden. The flag is passed explicitly so a
    status.showUntrackedFiles setting cannot change the answer."""
    if tool_commit() is None:
        return None
    out = _run_git("status", "--porcelain", "--untracked-files=normal", "--", *_TOOL_PATHS)
    if out is None:
        return None
    return out.strip() == ""


def _extra_data(facts: Mapping, name: str) -> object:
    """facts["extra"][name]["data"] when that extended item succeeded, else None."""
    extra = facts.get("extra")
    if not isinstance(extra, Mapping):
        return None
    item = extra.get(name)
    if not isinstance(item, Mapping) or item.get("ok") is not True:
        return None
    return item.get("data")


def _first_row(data: object) -> Mapping:
    if isinstance(data, list) and data and isinstance(data[0], Mapping):
        return data[0]
    return {}


def _text_or_none(value: object) -> Optional[str]:
    if value is None or value == "":
        return None
    return str(value)


def os_summary(facts: Mapping) -> dict:
    """{platform, name, version, build}: the first three from facts["os"],
    build from the extended os_version_full row when present, else null."""
    os_facts = facts.get("os")
    if not isinstance(os_facts, Mapping):
        os_facts = {}
    build_row = _first_row(_extra_data(facts, "os_version_full"))
    return {
        "platform": os_facts.get("platform"),
        "name": os_facts.get("name"),
        "version": os_facts.get("version"),
        "build": _text_or_none(build_row.get("build")),
    }


def osquery_version(facts: Mapping) -> Optional[str]:
    """osquery's version from the extended osquery_info item when it succeeded."""
    return _text_or_none(_first_row(_extra_data(facts, "osquery_info")).get("version"))


def build_provenance(*, run_at_utc: str, as_of: Optional[datetime.date],
                     as_of_source: Optional[str], methodology: Optional[str],
                     risk_register: bool, target: str, facts_source: str,
                     connector: Optional[str], facts_collected_at_utc: Optional[str],
                     facts_file: Optional[Mapping], inputs: Mapping[str, Optional[Mapping]],
                     enabled_check_ids: Sequence[str], facts: Optional[Mapping]) -> dict:
    """The provenance dict, keys in the documented order (module docstring)."""
    if facts_source not in FACTS_SOURCES:
        raise ValueError(f"facts_source must be one of {FACTS_SOURCES}, got {facts_source!r}")
    if as_of_source is not None and as_of_source not in AS_OF_SOURCES:
        raise ValueError(f"as_of_source must be one of {AS_OF_SOURCES} or None, got {as_of_source!r}")
    ids: List[str] = list(enabled_check_ids)
    facts = facts or {}
    return {
        "provenance_format": PROVENANCE_FORMAT,
        "tool_version": __version__,
        "tool_commit": tool_commit(),
        "tool_tree_clean": tool_tree_clean(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "run_at_utc": run_at_utc,
        "as_of": None if as_of is None else as_of.isoformat(),
        "as_of_source": as_of_source,
        "methodology": methodology,
        "risk_register": bool(risk_register),
        "target": target,
        "facts_source": facts_source,
        "connector": connector,
        "facts_collected_at_utc": facts_collected_at_utc,
        "facts_file": None if facts_file is None else {
            "path": facts_file["path"], "sha256": facts_file["sha256"], "role": facts_file["role"],
        },
        "inputs": {
            key: None if inputs.get(key) is None else {
                "path": inputs[key]["path"], "sha256": inputs[key]["sha256"],
            }
            for key in INPUT_KEYS
        },
        "enabled_check_ids": ids,
        "enabled_check_ids_fingerprint": check_ids_fingerprint(ids),
        "os": os_summary(facts),
        "osquery_version": osquery_version(facts),
        "extended_facts": "extra" in facts,
    }
