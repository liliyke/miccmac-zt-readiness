"""Assessment engine: runs property checks, scores them, builds the Assessment."""
from __future__ import annotations

from typing import List, Optional

from miccmac import metadata
from miccmac import methodology as methodology_mod
from miccmac.checks import (
    monitored, inventoried, controlled, claimed,
    minimized, assessed, current,
)
from miccmac.config import Config, ConfigError
from miccmac.model import PROPERTY_KEYS, Assessment, PropertyResult, SCORE_MAP

# MICCMAC property order is meaningful: it spells the framework name.
PROPERTY_MODULES = [
    monitored, inventoried, controlled, claimed,
    minimized, assessed, current,
]
assert [m.KEY for m in PROPERTY_MODULES] == list(PROPERTY_KEYS), (
    "PROPERTY_MODULES must stay in sync with model.PROPERTY_KEYS -- the fixed "
    "seven MICCMAC properties. This guards against ever growing an eighth."
)

# Overall readiness tiers. Thresholds are intentionally simple and can be
# tuned in line with the methodology described in docs/methodology.md.
READINESS_TIERS = [
    (90.0, "Zero Trust Ready"),
    (70.0, "Defensible"),
    (40.0, "Developing"),
    (0.0,  "Not Ready"),
]


def score_property(prop: PropertyResult) -> Optional[float]:
    """Average score of all *scorable* checks (PASS/PARTIAL/FAIL/ERROR).

    NOT_IMPLEMENTED and NOT_APPLICABLE checks are excluded so that an
    incomplete scaffold does not produce a misleadingly low score.
    Returns None when nothing is scorable.
    """
    scorable = [c for c in prop.checks if c.status in SCORE_MAP]
    if not scorable:
        return None
    return round(sum(SCORE_MAP[c.status] for c in scorable) / len(scorable), 1)


def overall_score(properties: List[PropertyResult]) -> Optional[float]:
    """Mean of the property scores that could be computed."""
    scored = [p.score for p in properties if p.score is not None]
    if not scored:
        return None
    return round(sum(scored) / len(scored), 1)


def readiness_tier(score: Optional[float]) -> str:
    if score is None:
        return "Unassessed"
    for threshold, label in READINESS_TIERS:
        if score >= threshold:
            return label
    return "Not Ready"


def _known_check_ids(config: Config) -> set:
    """Union of every built-in check id and every loaded custom plugin's ids."""
    known = set(metadata.all_builtin_check_ids())
    for plugins in config.load_custom_checks().values():
        for plugin in plugins:
            known.update(plugin.check_ids)
    return known


def _validate_exclusions(excluded: set, known: set) -> None:
    """Fail fast on a typo'd exclusion: it must never silently no-op, since
    that would break the fairness guarantee of enabled_check_ids()."""
    unknown = excluded - known
    if unknown:
        raise ConfigError(
            f"excluded_checks names unknown check id(s): {sorted(unknown)}"
        )


def enabled_check_ids(config: Optional[Config] = None) -> List[str]:
    """The 'fairness control' contract: for a given config, the check_ids
    that WOULD be scored -- all built-ins in canonical property order, minus
    excluded_checks, plus every custom plugin's ids (grouped under its
    ATTACH_TO property, sorted by check_id within each group). Requires no
    live target/context. config=None is equivalent to Config()."""
    config = config or Config()
    excluded = set(config.excluded_checks)
    _validate_exclusions(excluded, _known_check_ids(config))

    plugins_by_property = config.load_custom_checks()
    by_property = metadata.builtin_check_ids_by_property()

    ids: List[str] = []
    for module in PROPERTY_MODULES:
        prop_ids = list(by_property.get(module.KEY, []))
        for plugin in plugins_by_property.get(module.KEY, []):
            prop_ids.extend(plugin.check_ids)
        for check_id in sorted(prop_ids):
            if check_id not in excluded:
                ids.append(check_id)
    return ids


def run_assessment(
    target: str,
    context: dict | None = None,
    config: Optional[Config] = None,
    methodology_name: Optional[str] = None,
) -> Assessment:
    """Run every MICCMAC property check against ``target``.

    ``context`` is a free-form dict passed to each check module. Use it to
    supply connection details, collected device facts, API clients, etc.

    With config=None and methodology_name=None (the defaults), this
    reproduces the original scaffold behavior exactly.

    ``config`` (miccmac.config.Config) adds check exclusion and custom-check
    merging. ``methodology_name`` (e.g. "cmmi", "cisa-ztmm") additionally
    attaches a MethodologyResult; the flat overall_score/readiness_tier are
    always computed regardless.
    """
    context = context or {}
    config = config or Config()

    excluded = set(config.excluded_checks)
    _validate_exclusions(excluded, _known_check_ids(config))
    plugins_by_property = config.load_custom_checks()

    assessment = Assessment(target=target)

    for module in PROPERTY_MODULES:
        prop: PropertyResult = module.evaluate(target, context)

        for plugin in plugins_by_property.get(module.KEY, []):
            plugin_checks = plugin.run_checks(target, context)
            returned_ids = {c.check_id for c in plugin_checks}
            if returned_ids != set(plugin.check_ids):
                raise ConfigError(
                    f"custom check plugin {plugin.module_name!r} declared "
                    f"CHECK_IDS={plugin.check_ids} but run_checks() returned "
                    f"{sorted(returned_ids)}"
                )
            prop.checks.extend(plugin_checks)

        if excluded:
            prop.checks = [c for c in prop.checks if c.check_id not in excluded]

        prop.score = score_property(prop)
        assessment.properties.append(prop)

    assessment.overall_score = overall_score(assessment.properties)
    assessment.readiness_tier = readiness_tier(assessment.overall_score)
    assessment.excluded_check_ids = sorted(excluded)

    if methodology_name is not None:
        assessment.methodology = methodology_mod.apply_methodology(assessment, methodology_name)

    return assessment
