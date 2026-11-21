"""Tests for the risk register's next-level hints (miccmac.risk_register.
next_level_hint): the worked examples of the design (A-I, plus two
with-others cases and the one-of cases the verifiers found) with their exact
text and fields under CMMI and CISA ZTMM; an exhaustive sweep over every
status mix of 1- to 5-check properties that checks each hint against a
brute-force search (the fewest fixes, which checks a route needs, the
effect, and for a check not scored whether its result can change the level
at all); and, on the synthetic kit's five host plans, that every hint's
current level is the level the assessment reports.

Properties are built directly from statuses (no target, no network); the
kit's plans are made-up data."""
from __future__ import annotations

import datetime as dt
import itertools
import json

import pytest

from miccmac import clock
from miccmac.engine import run_assessment, score_property, score_statuses
from miccmac.methodology import REGISTRY, apply_methodology
from miccmac.model import Assessment, CheckResult, MissingData, PropertyResult, Status
from miccmac.risk_register import NEXT_LEVEL_EFFECTS, build_risk_register, next_level_hint

MISSING = "NA_MISSING"     # NOT_APPLICABLE because an input was not supplied
GENUINE = "NA"             # NOT_APPLICABLE: does not apply
OPEN = (Status.FAIL, Status.PARTIAL, Status.ERROR)


def _check(check_id: str, kind: str) -> CheckResult:
    if kind == MISSING:
        return CheckResult(check_id, check_id, Status.NOT_APPLICABLE, "Not supplied.",
                           missing_data=MissingData("attestation", "missing-field", "entry", "{}"))
    if kind == GENUINE:
        return CheckResult(check_id, check_id, Status.NOT_APPLICABLE, "Does not apply.")
    return CheckResult(check_id, check_id, Status(kind), "Detail.")


def _assessment(title: str, statuses, methodology: str):
    """(assessment, property) for one property, `statuses` = [(check id, kind)]."""
    checks = [_check(check_id, kind) for check_id, kind in statuses]
    prop = PropertyResult(key=title.lower(), letter=title[0], title=title, checks=checks)
    prop.score = score_property(prop)
    assessment = Assessment(target="t", properties=[prop], overall_score=prop.score)
    assessment.methodology = apply_methodology(assessment, methodology)
    return assessment, prop


def hint(title: str, statuses, methodology: str, check_id: str):
    assessment, prop = _assessment(title, statuses, methodology)
    return next_level_hint(assessment, prop, next(c for c in prop.checks if c.check_id == check_id))


A = [("CTL-01", "FAIL"), ("CTL-02", "PARTIAL"), ("CTL-03", "PASS"), ("CTL-04", "PASS")]
B = [("CLM-01", "FAIL"), ("CLM-02", "PASS"), ("CLM-03", "PARTIAL")]
C = [("CUR-01", "FAIL"), ("CUR-02", GENUINE), ("CUR-03", "FAIL"), ("CUR-04", "FAIL")]
D = [("ASM-01", "PASS"), ("ASM-02", "PASS"), ("ASM-03", "FAIL")]
E = [("ASM-01", "ERROR"), ("ASM-02", "PASS"), ("ASM-03", "FAIL")]
F = [("CUR-01", "FAIL"), ("CUR-02", GENUINE), ("CUR-03", MISSING), ("CUR-04", "FAIL")]
G = [("CLM-01", MISSING), ("CLM-02", MISSING), ("CLM-03", MISSING)]
H = [("INV-01", MISSING), ("INV-02", "PASS"), ("INV-03", "PASS"), ("INV-04", MISSING)]
I = [(f"MON-{n:02d}", "PASS") for n in range(1, 10)] + [("MON-10", "FAIL")]
J = [("MON-01", "PASS"), ("MON-02", "PASS"), ("MON-03", "PARTIAL"), ("MON-04", "PARTIAL")]
K = [("MON-01", "PARTIAL"), ("MON-02", "PARTIAL"), ("MON-03", "PARTIAL"), ("MON-04", "PARTIAL"), ("MON-05", "FAIL")]


# ------------------------------------------------------------------ worked examples
def test_a_two_single_fixes():
    ctl01 = hint("Controlled", A, "cmmi", "CTL-01")
    assert ctl01.text == ("Fixing this check alone raises Controlled from CMMI level 3 (Defined) to level 4 "
                          "(Quantitatively Managed): score 62.5 -> 87.5 (level 4 needs 70).")
    assert (ctl01.effect, ctl01.fixes_needed, ctl01.with_check_ids, ctl01.fewest_fixes) == ("alone", 1, (), 1)
    assert (ctl01.target_reachable_without_this, ctl01.without_check_ids) == (True, ("CTL-02",))
    ctl02 = hint("Controlled", A, "cmmi", "CTL-02")
    assert ctl02.effect == "alone" and "score 62.5 -> 75.0 (level 4 needs 70)" in ctl02.text
    assert hint("Controlled", A, "cisa-ztmm", "CTL-01").text == (
        "Fixing this check alone raises Controlled from CISA ZTMM stage 2 (Initial) to stage 3 (Advanced): score "
        "62.5 -> 87.5 (stage 3 needs 70).")


def test_b_a_fix_the_next_level_does_not_need():
    """Critique (high): the next level is reachable without CLM-03, so its hint
    must not call it needed."""
    assert hint("Claimed", B, "cmmi", "CLM-01").text == (
        "Fixing this check alone raises Claimed from CMMI level 3 (Defined) to level 4 (Quantitatively Managed): "
        "score 50.0 -> 83.3 (level 4 needs 70).")
    clm03 = hint("Claimed", B, "cmmi", "CLM-03")
    assert clm03.effect == "not-needed"
    assert clm03.text == (
        "Claimed is at CMMI level 3 (Defined), score 50.0; level 4 (Quantitatively Managed) needs 70. Fixing this "
        "check alone gives 66.7. Level 4 does not need this check: fixing CLM-01 reaches it (score 83.3). Together "
        "with CLM-01, this check gives 100.0.")
    assert "needed for" not in clm03.text and "one of" not in clm03.text
    assert (clm03.score_if_fixed, clm03.level_if_fixed, clm03.fixes_needed, clm03.with_check_ids) == (
        66.7, 3, 2, ("CLM-01",))
    assert (clm03.fewest_fixes, clm03.target_reachable_without_this, clm03.without_check_ids) == (1, True, ("CLM-01",))


def test_c_the_same_statuses_under_another_lens():
    for check_id in ("CUR-01", "CUR-03", "CUR-04"):
        assert hint("Current", C, "cmmi", check_id).text == (
            "Fixing this check alone raises Current from CMMI level 1 (Initial) to level 2 (Managed): score 0.0 -> "
            "33.3 (level 2 needs 20).")
    cur01 = hint("Current", C, "cisa-ztmm", "CUR-01")
    # Verifier finding (deliberately changed): any two of the three FAILs reach stage 2, so each is one of
    # several interchangeable fixes ("one-of"), not a fix stage 2 does not need ("not-needed").
    assert (cur01.effect, cur01.fixes_needed, cur01.fewest_fixes) == ("one-of", 2, 2)
    assert cur01.text == (
        "Current is at CISA ZTMM stage 1 (Traditional), score 0.0; stage 2 (Initial) needs 40. Fixing this check "
        "alone gives 33.3. Stage 2 takes at least 2 fixes, and this check can be one of them: together with CUR-03, "
        "it takes Current to stage 2 (Initial), score 66.7. Other sets of 2 fixes reach stage 2 without this check, "
        "for example CUR-03 and CUR-04 (score 66.7).")
    for check_id in ("CUR-03", "CUR-04"):
        other = hint("Current", C, "cisa-ztmm", check_id)
        assert other.effect == "one-of" and "does not need this check" not in other.text


def test_one_of_when_every_open_check_is_partial():
    """Verifier finding: four PARTIALs (50.0, CMMI level 3); level 4 needs any
    two of them, so every entry is one of the fixes, none is 'not needed'."""
    statuses = [(f"MON-0{n}", "PARTIAL") for n in range(1, 5)]
    mon01 = hint("Monitored", statuses, "cmmi", "MON-01")
    assert mon01.text == (
        "Monitored is at CMMI level 3 (Defined), score 50.0; level 4 (Quantitatively Managed) needs 70. Fixing this "
        "check alone gives 62.5. Level 4 takes at least 2 fixes, and this check can be one of them: together with "
        "MON-02, it takes Monitored to level 4 (Quantitatively Managed), score 75.0. Other sets of 2 fixes reach "
        "level 4 without this check, for example MON-02 and MON-03 (score 75.0).")
    assert (mon01.fixes_needed, mon01.fewest_fixes, mon01.with_check_ids, mon01.without_check_ids) == (
        2, 2, ("MON-02",), ("MON-02", "MON-03"))
    for check_id in ("MON-02", "MON-03", "MON-04"):
        assert hint("Monitored", statuses, "cmmi", check_id).effect == "one-of"


def test_d_a_jump_of_two_levels_cites_the_level_reached():
    assert hint("Assessed", D, "cmmi", "ASM-03").text == (
        "Fixing this check alone raises Assessed from CMMI level 3 (Defined) to level 5 (Optimizing): score 66.7 "
        "-> 100.0 (level 5 needs 90).")
    ztmm = hint("Assessed", D, "cisa-ztmm", "ASM-03")
    assert ztmm.text == ("Fixing this check alone raises Assessed from CISA ZTMM stage 2 (Initial) to stage 4 "
                         "(Optimal): score 66.7 -> 100.0 (stage 4 needs 90).")
    assert (ztmm.target_level, ztmm.target_min_score, ztmm.level_if_fixed) == (3, 70.0, 4)


def test_e_an_error_is_worded_conditionally():
    assert hint("Assessed", E, "cmmi", "ASM-01").text == (
        "If this check passes once it can be evaluated, Assessed rises from CMMI level 2 (Managed) to level 3 "
        "(Defined): score 33.3 -> 66.7 (level 3 needs 40).")
    assert hint("Assessed", E, "cmmi", "ASM-03").text.startswith("Fixing this check alone raises Assessed")


def test_f_a_check_not_scored_gets_no_arithmetic():
    cur03 = hint("Current", F, "cmmi", "CUR-03")
    assert cur03.text == ("Current is at CMMI level 1 (Initial) without this check, which is not scored until its "
                          "data is supplied; its result can then change that level.")
    assert cur03.effect == "not-scored"
    assert all(getattr(cur03, name) is None for name in (
        "target_level", "target_label", "target_min_score", "score_if_fixed", "level_if_fixed",
        "level_if_fixed_label", "fixes_needed", "with_check_ids", "fewest_fixes", "target_reachable_without_this",
        "without_check_ids"))
    # Missing data changes the denominator: with CUR-03 not scored, one fix gives 50.0.
    assert hint("Current", F, "cmmi", "CUR-01").text == (
        "Fixing this check alone raises Current from CMMI level 1 (Initial) to level 3 (Defined): score 0.0 -> "
        "50.0 (level 3 needs 40).")


def test_f_a_check_whose_result_cannot_change_the_level_says_so():
    """Verifier finding: under CISA ZTMM, CUR-03 as PASS gives 33.3, below
    stage 2's 40, so Current stays at stage 1 whatever CUR-03's result (the
    synthetic kit's H3)."""
    cur03 = hint("Current", F, "cisa-ztmm", "CUR-03")
    assert cur03.effect == "not-scored"
    assert cur03.text == ("Current is at CISA ZTMM stage 1 (Traditional) without this check, which is not scored "
                          "until its data is supplied; Current stays at stage 1 whatever its result.")
    assert "can then change" not in cur03.text


def test_g_an_unassessed_property():
    assert hint("Claimed", G, "cmmi", "CLM-01").text == (
        "Claimed has no CMMI level yet: none of its checks could be scored. Supplying this data lets the tool "
        "score it.")
    ztmm = hint("Claimed", G, "cisa-ztmm", "CLM-02")
    assert ztmm.text.startswith("Claimed has no CISA ZTMM stage yet")
    assert (ztmm.current_level, ztmm.current_label, ztmm.current_score) == (None, "Unassessed", None)


def test_h_not_scored_at_the_top_level():
    assert hint("Inventoried", H, "cmmi", "INV-01").text == (
        "Inventoried is at CMMI level 5 (Optimizing) without this check, which is not scored until its data is "
        "supplied; its result can then change that level.")
    assert hint("Inventoried", H, "cisa-ztmm", "INV-04").text.startswith(
        "Inventoried is at CISA ZTMM stage 4 (Optimal) without this check")


def test_i_already_at_the_top_level():
    cmmi = hint("Monitored", I, "cmmi", "MON-10")
    assert cmmi.text == "Monitored is already at the top CMMI level, level 5 (Optimizing); there is no next level."
    assert (cmmi.effect, cmmi.target_level, cmmi.current_level, cmmi.max_level) == ("top-level", None, 5, 5)
    assert hint("Monitored", I, "cisa-ztmm", "MON-10").text == (
        "Monitored is already at the top CISA ZTMM stage, stage 4 (Optimal); there is no next stage.")


def test_with_others_when_the_next_level_cannot_be_reached_without_the_check():
    mon03 = hint("Monitored", J, "cmmi", "MON-03")
    assert mon03.effect == "with-others"
    assert mon03.text == (
        "Monitored is at CMMI level 4 (Quantitatively Managed), score 75.0; level 5 (Optimizing) needs 90. Fixing "
        "this check alone gives 87.5. Together with MON-04 (2 fixes), it takes Monitored to level 5 (Optimizing), "
        "score 100.0; level 5 cannot be reached without this check.")
    assert (mon03.fixes_needed, mon03.fewest_fixes, mon03.target_reachable_without_this) == (2, 2, False)


def test_with_others_when_a_longer_route_avoids_the_check():
    mon05 = hint("Monitored", K, "cmmi", "MON-05")
    assert mon05.effect == "with-others"
    assert mon05.text == (
        "Monitored is at CMMI level 3 (Defined), score 40.0; level 4 (Quantitatively Managed) needs 70. Fixing "
        "this check alone gives 60.0. Together with MON-01 (2 fixes), it takes Monitored to level 4 (Quantitatively "
        "Managed), score 70.0; every way to reach level 4 with 2 fixes includes this check, and without it level 4 "
        "takes 3 fixes (MON-01, MON-02 and MON-03).")
    assert mon05.without_check_ids == ("MON-01", "MON-02", "MON-03")


def test_the_json_shape_of_a_hint():
    """Spec section 5, example 1: CTL-01 in synthetic H1's facts-only run."""
    statuses = [("CTL-01", "FAIL"), ("CTL-02", "PARTIAL"), ("CTL-03", MISSING), ("CTL-04", "PASS")]
    data = hint("Controlled", statuses, "cmmi", "CTL-01").to_dict()
    assert data == {
        "methodology": "cmmi", "effect": "alone", "current_level": 3, "current_label": "Defined",
        "current_score": 50.0, "max_level": 5, "target_level": 4, "target_label": "Quantitatively Managed",
        "target_min_score": 70.0, "score_if_fixed": 83.3, "level_if_fixed": 4,
        "level_if_fixed_label": "Quantitatively Managed", "fixes_needed": 1, "with_check_ids": [],
        "fewest_fixes": 1, "target_reachable_without_this": False, "without_check_ids": None,
        "text": "Fixing this check alone raises Controlled from CMMI level 3 (Defined) to level 4 (Quantitatively "
                "Managed): score 50.0 -> 83.3 (level 4 needs 70).",
    }
    assert json.loads(json.dumps(data)) == data


def test_no_hint_without_a_methodology():
    assessment, prop = _assessment("Controlled", A, "cmmi")
    assessment.methodology = None
    assert next_level_hint(assessment, prop, prop.checks[0]) is None


# ------------------------------------------------------------------ exhaustive sweep
KINDS = ("PASS", "PARTIAL", "FAIL", "ERROR", MISSING, GENUINE)


def _sweep_cases(max_checks: int):
    for n in range(1, max_checks + 1):
        for combo in itertools.product(KINDS, repeat=n):
            yield [(f"X-{i:02d}", kind) for i, kind in enumerate(combo)]


@pytest.mark.parametrize("methodology", sorted(REGISTRY))
def test_every_hint_matches_a_brute_force_search(methodology):
    """Every status mix of 1-5 checks: the effect, the fewest fixes with and
    without the check and the ids named agree with an exhaustive search over
    the property's open entries (the design's invariants)."""
    m = REGISTRY[methodology]
    seen = set()
    for statuses in _sweep_cases(5):
        assessment, prop = _assessment("Monitored", statuses, methodology)
        reported = assessment.methodology.properties[prop.key]
        status_of = {c.check_id: c.status for c in prop.checks}
        open_ids = [c.check_id for c in prop.checks if c.status in OPEN]

        def level(fixed):
            score = score_statuses(Status.PASS if cid in fixed else st for cid, st in status_of.items())
            return m.level_for_score(score).level

        for check in prop.checks:
            if not (check.status in OPEN or check.missing_data is not None):
                continue
            h = next_level_hint(assessment, prop, check)
            seen.add(h.effect)
            assert h.effect in NEXT_LEVEL_EFFECTS
            assert (h.current_level, h.max_level) == (reported.level, len(m.levels))
            if check.status is Status.NOT_APPLICABLE:
                assert h.effect == "not-scored" and h.target_level is None
                if reported.level is not None:
                    # Every result the check can get once its data is supplied.
                    rest = [st for cid, st in status_of.items() if cid != check.check_id]
                    outcomes = {m.level_for_score(score_statuses(rest + [result])).level
                                for result in (Status.PASS, Status.PARTIAL, Status.FAIL, Status.ERROR)}
                    assert ("its result can then change" in h.text) == (len(outcomes) > 1)
                    assert ("whatever its result" in h.text) == (len(outcomes) == 1)
                continue
            if reported.level == len(m.levels):
                assert h.effect == "top-level" and h.target_level is None
                continue
            target = reported.level + 1
            assert h.target_level == target <= h.max_level
            routes = [set(s) for r in range(1, len(open_ids) + 1) for s in itertools.combinations(open_ids, r)
                      if level(set(s)) >= target]
            with_this = [s for s in routes if check.check_id in s]
            without_this = [s for s in routes if check.check_id not in s]
            fewest = min(len(s) for s in routes)
            assert h.fewest_fixes == fewest
            assert h.fixes_needed == min(len(s) for s in with_this)
            assert level({check.check_id, *h.with_check_ids}) >= target
            assert h.target_reachable_without_this == bool(without_this)
            if without_this:
                assert len(h.without_check_ids) == min(len(s) for s in without_this)
                assert check.check_id not in h.without_check_ids and level(set(h.without_check_ids)) >= target
            alone = level({check.check_id}) >= target
            assert (h.effect == "alone") == alone == (h.level_if_fixed >= target)
            if not alone:
                # Verifier finding (deliberately changed): a check in some fewest sets but not all is
                # "one-of"; "not-needed" is kept for a check in no fewest set.
                fewest_sets = [s for s in routes if len(s) == fewest]
                if all(check.check_id in s for s in fewest_sets):
                    expected = "with-others"
                elif any(check.check_id in s for s in fewest_sets):
                    expected = "one-of"
                else:
                    expected = "not-needed"
                assert h.effect == expected
                assert 2 <= h.fixes_needed <= len(open_ids)
                assert ("does not need this check" in h.text) == (h.effect == "not-needed")
                assert ("can be one of them" in h.text) == (h.effect == "one-of")
                if h.effect == "one-of":
                    assert h.fixes_needed == h.fewest_fixes == len(h.without_check_ids)
                if h.effect == "not-needed":
                    assert h.fixes_needed > h.fewest_fixes
    assert seen == set(NEXT_LEVEL_EFFECTS)


# ------------------------------------------------------------------ the synthetic kit
@pytest.mark.parametrize("methodology", sorted(REGISTRY))
@pytest.mark.parametrize("full_inputs", [True, False], ids=["full-inputs", "facts-only"])
def test_hints_agree_with_the_reported_levels_on_the_synthetic_plans(methodology, full_inputs):
    from miccmac_study import synthetic

    session = dt.date(2026, 11, 23)
    effects = set()
    for index, host in enumerate(["H1", "H2", "H3", "H4", "H5"]):
        plan = synthetic.plan_host(host, index, 7, session)
        context = {"facts": json.loads(json.dumps(plan.facts)), clock.AS_OF_KEY: session}
        if full_inputs:
            context.update(attestation=plan.attestation, inventory_record=plan.inventory_record)
        assessment = run_assessment(host, context=context, methodology_name=methodology)
        levels = {key: result.level for key, result in assessment.methodology.properties.items()}
        for entry in build_risk_register(assessment):
            assert entry.next_level.methodology == methodology
            assert entry.next_level.current_level == levels[entry.property_key]
            effects.add(entry.next_level.effect)
    assert "alone" in effects
