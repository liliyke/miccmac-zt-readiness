"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac_study.stats. Expected values are computed by hand
(shown in the comments) so each can be re-derived without software."""
from __future__ import annotations

from fractions import Fraction

import pytest

from miccmac_study import stats


# ------------------------------------------------------------------ Wilson interval
def test_wilson_four_of_five():
    # p = 0.8, z^2 = 3.841459, denominator = 1 + 3.841459/5 = 1.768292
    # centre = (0.8 + 0.384146) / 1.768292 = 0.669655
    # half = 1.959964/1.768292 * sqrt(0.16/5 + 3.841459/100) = 0.294121
    # interval = 0.669655 -/+ 0.294121 = 0.3755 to 0.9638
    low, high = stats.wilson_interval(4, 5)
    assert (round(low, 4), round(high, 4)) == (0.3755, 0.9638)


def test_wilson_five_of_five_and_zero_of_five():
    # k = n: low = n / (n + z^2) = 5 / 8.841459 = 0.5655, high exactly 1.
    low, high = stats.wilson_interval(5, 5)
    assert round(low, 4) == 0.5655 and high == 1.0
    # k = 0: low exactly 0, high = z^2 / (n + z^2) = 3.841459 / 8.841459 = 0.4345.
    low, high = stats.wilson_interval(0, 5)
    assert low == 0.0 and round(high, 4) == 0.4345


def test_wilson_zero_of_zero_is_none():
    assert stats.wilson_interval(0, 0) is None
    assert stats.wilson_steps(0, 0) is None
    assert stats.proportion(0, 0) is None


def test_wilson_steps_match_interval():
    steps = stats.wilson_steps(4, 5)
    assert steps["denominator"] == pytest.approx(1.768292, abs=1e-6)
    assert steps["centre"] == pytest.approx(0.669655, abs=1e-6)
    assert steps["half_width"] == pytest.approx(0.294121, abs=1e-6)
    assert (steps["low"], steps["high"]) == stats.wilson_interval(4, 5)


def test_wilson_rejects_bad_counts():
    with pytest.raises(ValueError):
        stats.wilson_interval(6, 5)
    with pytest.raises(TypeError):
        stats.wilson_interval(1.0, 5)


# ------------------------------------------------------------------ threshold
def test_meets_threshold_uses_exact_fractions():
    assert stats.meets_threshold(4, 5, Fraction(4, 5)) is True
    assert stats.meets_threshold(3, 5, Fraction(4, 5)) is False
    assert stats.meets_threshold(0, 0, Fraction(4, 5)) is None
    # 0.8 as a float would be 0.8000000000000000444...; it must still mean 4/5.
    assert stats.meets_threshold(4, 5, 0.8) is True
    assert stats.meets_threshold(28, 35, "0.80") is True
    assert stats.meets_threshold(27, 35, "0.80") is False


def test_minimum_successes():
    assert stats.minimum_successes(5, Fraction(4, 5)) == 4
    assert stats.minimum_successes(35, Fraction(4, 5)) == 28
    assert stats.minimum_successes(4, Fraction(4, 5)) == 4      # 3/4 = 0.75 is short
    assert stats.minimum_successes(5, Fraction(9, 10)) == 5
    assert stats.minimum_successes(0, Fraction(4, 5)) is None


# ------------------------------------------------------------------ chance baseline
def test_uniform_chance_baselines():
    # 5x5 within one: 5 diagonal + 2 x 4 neighbours = 13 of 25 = 52%.
    assert stats.uniform_chance(5, 5) == Fraction(13, 25)
    # 4x4: 4 + 2 x 3 = 10 of 16 = 62.5%.
    assert stats.uniform_chance(4, 4) == Fraction(10, 16)
    # 5 tool levels x 4 manual: t=1:2, t=2:3, t=3:3, t=4:2, t=5:1 -> 11 of 20.
    assert stats.uniform_chance(5, 4) == Fraction(11, 20)


def test_uniform_chance_exact():
    assert stats.uniform_chance(5, 5, within=0) == Fraction(1, 5)
    assert stats.uniform_chance(4, 4, within=0) == Fraction(1, 4)
    assert stats.uniform_chance(5, 4, within=0) == Fraction(4, 20)


# ------------------------------------------------------------------ percentiles
def test_percentile_linear_interpolation():
    # N = 4, q = 0.025: h = 3 x 0.025 = 0.075 -> 0.5 + 0.075 x (0.75 - 0.5) = 0.51875
    values = [1.0, 0.5, 0.75, 0.75]
    assert stats.percentile(values, 0.025) == pytest.approx(0.51875)
    assert stats.percentile(values, 0.975) == pytest.approx(0.98125)
    assert stats.percentile(values, 0) == 0.5 and stats.percentile(values, 1) == 1.0
    assert stats.percentile([3, 1, 2], 0.5) == 2.0


# ------------------------------------------------------------------ bootstrap
def test_bootstrap_exact_two_hosts():
    # Hosts A = (1, 2), B = (2, 2). The four ordered resamples:
    #   AA = 2/4 = 0.50, AB = 3/4, BA = 3/4, BB = 4/4 = 1.00
    # sorted [0.5, 0.75, 0.75, 1.0]; 2.5%: h = 0.075 -> 0.51875; 97.5%: h = 2.925 -> 0.98125.
    result = stats.bootstrap_pooled([(1, 2), (2, 2)], iterations=100, seed=1, exact_limit=1000)
    assert result["method"] == "exact"
    assert result["estimate"] == 0.75
    assert (result["resamples"], result["dropped"], result["seed"], result["hosts"]) == (4, 0, None, 2)
    assert result["low"] == pytest.approx(0.51875)
    assert result["high"] == pytest.approx(0.98125)


def test_bootstrap_exact_three_hosts():
    # Hosts A = (1, 1), B = (0, 1), C = (2, 2): 27 ordered resamples. Counting
    # how often each host is drawn (a, b, c) and the multinomial weight:
    #   (0,3,0) 1 x 0      (1,2,0) 3 x 1/3    (0,2,1) 3 x 1/2    (2,1,0) 3 x 2/3
    #   (1,1,1) 6 x 3/4    (0,1,2) 3 x 4/5    (3,0,0), (0,0,3) 1 each and
    #   (2,0,1), (1,0,2) 3 each, all = 1  ->  8 x 1
    # 2.5%: h = 26 x 0.025 = 0.65 -> 0 + 0.65 x (1/3 - 0) = 13/60
    # 97.5%: h = 26 x 0.975 = 25.35 -> between the 26th and 27th values, both 1.
    result = stats.bootstrap_pooled([(1, 1), (0, 1), (2, 2)], exact_limit=27)
    assert result["method"] == "exact" and result["resamples"] == 27
    assert result["estimate"] == 0.75
    assert result["low"] == pytest.approx(13 / 60)
    assert result["high"] == 1.0


def test_bootstrap_drops_resamples_without_comparisons():
    # A = (1, 2), B = (0, 0): AA = 2/4, AB = BA = 1/2, BB has n = 0 -> dropped.
    result = stats.bootstrap_pooled([(1, 2), (0, 0)], exact_limit=10)
    assert (result["resamples"], result["dropped"]) == (3, 1)
    assert (result["estimate"], result["low"], result["high"]) == (0.5, 0.5, 0.5)


def test_bootstrap_monte_carlo_is_reproducible():
    clusters = [(1, 1), (0, 1), (2, 2)]
    first = stats.bootstrap_pooled(clusters, iterations=500, seed=20261122, exact_limit=0)
    second = stats.bootstrap_pooled(clusters, iterations=500, seed=20261122, exact_limit=0)
    assert first == second
    assert first["method"] == "monte-carlo" and first["seed"] == 20261122
    assert first["resamples"] + first["dropped"] == 500
    assert 0.0 <= first["low"] <= first["estimate"] <= first["high"] <= 1.0
    other = stats.bootstrap_pooled(clusters, iterations=500, seed=7, exact_limit=0)
    assert other["method"] == "monte-carlo" and other["seed"] == 7


def test_bootstrap_without_hosts():
    result = stats.bootstrap_pooled([], iterations=100, seed=1, exact_limit=10)
    assert (result["method"], result["estimate"], result["low"], result["resamples"]) == ("none", None, None, 0)


def test_bootstrap_five_hosts_is_exact_under_default_limit():
    result = stats.bootstrap_pooled([(7, 7)] * 4 + [(5, 7)], iterations=10, seed=1, exact_limit=1_000_000)
    assert result["method"] == "exact" and result["resamples"] == 5 ** 5
    assert result["estimate"] == pytest.approx(33 / 35)


# ------------------------------------------------------------------ kappa
def test_cohen_kappa_textbook_example():
    # Two readers, 50 grant proposals (the classic Wikipedia example):
    # both yes 20, A yes/B no 5, A no/B yes 10, both no 15.
    # po = 35/50 = 0.70; pe = 0.5 x 0.6 + 0.5 x 0.4 = 0.50; kappa = 0.2/0.5 = 0.40
    pairs = [("Y", "Y")] * 20 + [("Y", "N")] * 5 + [("N", "Y")] * 10 + [("N", "N")] * 15
    assert stats.cohen_kappa(pairs) == pytest.approx(0.4)


def test_cohen_kappa_undefined_cases():
    assert stats.cohen_kappa([]) is None
    assert stats.cohen_kappa([("PASS", "PASS")] * 4) is None      # pe = 1
    assert stats.cohen_kappa([("PASS", "PASS"), ("FAIL", "FAIL")]) == 1.0


def test_linear_weighted_kappa_hand_example():
    # Pairs (1,1) (1,1) (2,2) (2,3) (3,3) (1,3), categories 1..3:
    # unweighted: po = 4/6, pe = (3x2 + 2x1 + 1x3)/36 = 11/36 -> kappa = 13/25 = 0.52
    # weighted (disagreement |i - j|): observed 1 + 2 = 3, n = 6;
    # rows (3,2,1), columns (2,1,3): expected sum |i-j| r_i c_j = 21 + 10 + 5 = 36
    # kappa_w = 1 - 6 x 3 / 36 = 0.5
    pairs = [(1, 1), (1, 1), (2, 2), (2, 3), (3, 3), (1, 3)]
    assert stats.cohen_kappa(pairs) == pytest.approx(0.52)
    assert stats.linear_weighted_kappa(pairs, [1, 2, 3]) == pytest.approx(0.5)


def test_linear_weighted_kappa_equals_kappa_for_two_categories():
    pairs = [("Y", "Y")] * 20 + [("Y", "N")] * 5 + [("N", "Y")] * 10 + [("N", "N")] * 15
    assert stats.linear_weighted_kappa(pairs, ["N", "Y"]) == pytest.approx(0.4)


def test_linear_weighted_kappa_undefined_and_bad_labels():
    assert stats.linear_weighted_kappa([], [1, 2, 3]) is None
    assert stats.linear_weighted_kappa([(4, 4), (4, 4)], [1, 2, 3, 4, 5]) is None   # pe = 1
    assert stats.linear_weighted_kappa([(1, 1)], [1]) is None
    with pytest.raises(ValueError):
        stats.linear_weighted_kappa([(1, 6)], [1, 2, 3, 4, 5])
