"""Small statistics for the agreement analysis (protocol section 8).

Pure functions on plain Python numbers, with no third-party packages, so
every value can be re-derived by hand or in a spreadsheet:

- wilson_interval: 95% Wilson score interval for k successes in n.
- meets_threshold: exact rational comparison k/n >= threshold.
- uniform_chance: within-one (or exact) agreement expected if both sides
  picked levels uniformly at random.
- bootstrap_pooled: percentile interval for a pooled rate, resampling whole
  hosts (clusters) with replacement.
- cohen_kappa / linear_weighted_kappa: chance-corrected agreement.

Exact rational arithmetic (fractions.Fraction) is used wherever a
comparison or a percentile could otherwise be nudged by floating-point
rounding; results are returned as floats (or Fractions where stated).
"""
from __future__ import annotations

import itertools
import math
import random
from collections import Counter
from fractions import Fraction
from typing import Dict, Hashable, Iterable, List, Optional, Sequence, Tuple, Union

# Two-sided 95% standard normal quantile: the 97.5th percentile of N(0, 1).
Z_95 = 1.959963984540054

# The 2.5th and 97.5th percentiles, as exact fractions, for a 95% interval.
LOW_QUANTILE = Fraction(1, 40)
HIGH_QUANTILE = Fraction(39, 40)

Number = Union[int, float, Fraction]


def _check_counts(k: int, n: int) -> None:
    """k and n must be whole numbers with 0 <= k <= n."""
    for name, value in (("k", k), ("n", n)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be a whole number, got {value!r}")
    if not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")


def as_fraction(value: Union[Number, str]) -> Fraction:
    """A threshold or quantile as an exact fraction. Floats go through their
    shortest decimal text, so 0.8 becomes exactly 4/5."""
    if isinstance(value, Fraction):
        return value
    if isinstance(value, bool):
        raise TypeError(f"not a number: {value!r}")
    if isinstance(value, int):
        return Fraction(value)
    return Fraction(str(value).strip())


def proportion(k: int, n: int) -> Optional[float]:
    """k / n as a float, or None when n == 0."""
    _check_counts(k, n)
    return k / n if n else None


# ------------------------------------------------------------------ Wilson interval
def wilson_steps(k: int, n: int, z: float = Z_95) -> Optional[Dict[str, float]]:
    """The Wilson interval with its intermediate values, for showing the
    arithmetic in a hand-check:

        p = k / n
        denominator = 1 + z^2 / n
        centre = (p + z^2 / (2n)) / denominator
        half_width = z / denominator * sqrt(p (1 - p) / n + z^2 / (4 n^2))
        interval = centre - half_width .. centre + half_width

    The ends are clipped to 0..1 and set exactly to 0 when k == 0 and to 1
    when k == n (where they are 0 and 1 mathematically). None when n == 0."""
    _check_counts(k, n)
    if n == 0:
        return None
    p = k / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    centre = (p + z2 / (2.0 * n)) / denominator
    half_width = (z / denominator) * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))
    low = 0.0 if k == 0 else max(0.0, centre - half_width)
    high = 1.0 if k == n else min(1.0, centre + half_width)
    return {
        "k": k, "n": n, "z": z, "p": p, "z2": z2, "denominator": denominator,
        "centre": centre, "half_width": half_width, "low": low, "high": high,
    }


def wilson_interval(k: int, n: int, z: float = Z_95) -> Optional[Tuple[float, float]]:
    """95% (by default) Wilson score interval (low, high) for k of n, or
    None when n == 0. Example: 4 of 5 gives about (0.3755, 0.9638)."""
    steps = wilson_steps(k, n, z)
    if steps is None:
        return None
    return (steps["low"], steps["high"])


# ------------------------------------------------------------------ threshold
def meets_threshold(k: int, n: int, threshold: Union[Fraction, Number, str]) -> Optional[bool]:
    """True when k/n >= threshold, compared as exact fractions (so 4/5
    meets 0.80 exactly); None when n == 0."""
    _check_counts(k, n)
    if n == 0:
        return None
    return Fraction(k, n) >= as_fraction(threshold)


def minimum_successes(n: int, threshold: Union[Fraction, Number, str]) -> Optional[int]:
    """Smallest k with k/n >= threshold (for example 4 of 5 for 0.80), or
    None when n == 0."""
    _check_counts(0, n)
    if n == 0:
        return None
    return min(n, max(0, math.ceil(as_fraction(threshold) * n)))


# ------------------------------------------------------------------ chance baseline
def uniform_chance(tool_levels: int, manual_levels: int, within: int = 1) -> Fraction:
    """Share of the tool_levels x manual_levels level pairs (t, m), t in
    1..tool_levels and m in 1..manual_levels, with |t - m| <= within: the
    agreement expected if both sides chose levels uniformly at random.
    within=0 gives exact agreement. 5x5 within one: 13/25; 4x4: 10/16;
    5 tool levels against 4 manual levels: 11/20."""
    for name, value in (("tool_levels", tool_levels), ("manual_levels", manual_levels), ("within", within)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be a whole number, got {value!r}")
    if tool_levels < 1 or manual_levels < 1 or within < 0:
        raise ValueError("need at least one level on each side and within >= 0")
    hits = sum(
        1
        for t in range(1, tool_levels + 1)
        for m in range(1, manual_levels + 1)
        if abs(t - m) <= within
    )
    return Fraction(hits, tool_levels * manual_levels)


# ------------------------------------------------------------------ percentiles
def _order_statistic(ordered: Sequence[Tuple[Fraction, int]], index: int) -> Fraction:
    """The value at 0-based position `index` of the sorted sample that
    `ordered` describes as (value, count) pairs in ascending order."""
    seen = 0
    for value, count in ordered:
        seen += count
        if index < seen:
            return value
    raise IndexError(index)


def _percentile_from_counts(ordered: Sequence[Tuple[Fraction, int]], total: int, q: Fraction) -> Fraction:
    """Linear interpolation between order statistics (numpy's default
    method): position h = (total - 1) * q, value = x[floor(h)] +
    (h - floor(h)) * (x[floor(h) + 1] - x[floor(h)])."""
    position = (total - 1) * q
    below = math.floor(position)
    weight = position - below
    lower = _order_statistic(ordered, below)
    upper = _order_statistic(ordered, min(below + 1, total - 1))
    return lower + weight * (upper - lower)


def percentile(values: Iterable[Number], q: Union[Fraction, Number, str]) -> float:
    """The q-quantile (0 <= q <= 1) of `values` by linear interpolation
    between order statistics, position (N - 1) * q, as numpy's default."""
    sample = [as_fraction(v) if not isinstance(v, float) else Fraction(v) for v in values]
    if not sample:
        raise ValueError("percentile of an empty sample")
    q = as_fraction(q)
    if not 0 <= q <= 1:
        raise ValueError(f"quantile {q} is outside 0..1")
    ordered = sorted(Counter(sample).items())
    return float(_percentile_from_counts(ordered, len(sample), q))


# ------------------------------------------------------------------ cluster bootstrap
def bootstrap_pooled(
    clusters: Sequence[Tuple[int, int]],
    iterations: int = 10000,
    seed: int = 0,
    exact_limit: int = 1_000_000,
) -> Dict[str, object]:
    """Percentile bootstrap for a pooled rate, resampling hosts (clusters).

    `clusters` holds one (k, n) pair per host: k agreements out of n
    comparisons on that host. A resample draws as many hosts as there are,
    with replacement; its statistic is sum(k) / sum(n) over the drawn hosts.
    Resamples with sum(n) == 0 have no rate: they are dropped and counted.

    With H hosts there are H**H ordered resamples. When H**H <= exact_limit
    every one of them is enumerated (method "exact": deterministic, no seed
    used); otherwise `iterations` resamples are drawn with
    random.Random(seed) (method "monte-carlo": reproducible for a seed).

    The interval is the 2.5th and 97.5th percentile of the resampled rates,
    by linear interpolation between order statistics at position
    (N - 1) * q (numpy's default). With only 5 hosts there are 3125 ordered
    resamples and just 126 distinct host combinations, so the interval is
    coarse; it can even collapse to one value when the hosts look alike.

    Returns a dict: estimate (pooled rate of the original sample, or None),
    low, high (None when nothing was resampled), method ("exact",
    "monte-carlo", or "none" without hosts), resamples (kept), dropped,
    seed (None for exact), hosts."""
    pairs: List[Tuple[int, int]] = []
    for pair in clusters:
        k, n = pair
        _check_counts(k, n)
        pairs.append((k, n))
    hosts = len(pairs)
    total_k = sum(k for k, _ in pairs)
    total_n = sum(n for _, n in pairs)
    result: Dict[str, object] = {
        "estimate": (total_k / total_n) if total_n else None,
        "low": None,
        "high": None,
        "method": "none",
        "resamples": 0,
        "dropped": 0,
        "seed": None,
        "hosts": hosts,
    }
    if hosts == 0:
        return result

    # Tally resamples by (sum k, sum n); the rate depends on nothing else.
    tallies: Counter = Counter()
    if hosts ** hosts <= exact_limit:
        result["method"] = "exact"
        for combo in itertools.product(pairs, repeat=hosts):
            tallies[(sum(k for k, _ in combo), sum(n for _, n in combo))] += 1
    else:
        if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
            raise ValueError(f"iterations must be a whole number of at least 1, got {iterations!r}")
        result["method"] = "monte-carlo"
        result["seed"] = seed
        rng = random.Random(seed)
        for _ in range(iterations):
            sum_k = sum_n = 0
            for _ in range(hosts):
                k, n = pairs[rng.randrange(hosts)]
                sum_k += k
                sum_n += n
            tallies[(sum_k, sum_n)] += 1

    rates: Counter = Counter()
    dropped = 0
    for (sum_k, sum_n), count in tallies.items():
        if sum_n == 0:
            dropped += count
        else:
            rates[Fraction(sum_k, sum_n)] += count
    kept = sum(rates.values())
    result["resamples"] = kept
    result["dropped"] = dropped
    if kept:
        ordered = sorted(rates.items())
        result["low"] = float(_percentile_from_counts(ordered, kept, LOW_QUANTILE))
        result["high"] = float(_percentile_from_counts(ordered, kept, HIGH_QUANTILE))
    return result


# ------------------------------------------------------------------ kappa
def cohen_kappa(pairs: Iterable[Tuple[Hashable, Hashable]]) -> Optional[float]:
    """Cohen's kappa for nominal labels: (po - pe) / (1 - pe), where po is
    the share of pairs that agree and pe the agreement expected from each
    side's label frequencies. None when there are no pairs or pe == 1
    (both sides used one and the same label throughout)."""
    pairs = list(pairs)
    n = len(pairs)
    if n == 0:
        return None
    first = Counter(a for a, _ in pairs)
    second = Counter(b for _, b in pairs)
    observed = Fraction(sum(1 for a, b in pairs if a == b), n)
    expected = sum((Fraction(first[label] * second[label], n * n) for label in first), Fraction(0))
    if expected == 1:
        return None
    return float((observed - expected) / (1 - expected))


def linear_weighted_kappa(
    pairs: Iterable[Tuple[Hashable, Hashable]], categories: Sequence[Hashable]
) -> Optional[float]:
    """Linear-weighted kappa for ordinal labels such as levels.

    `categories` lists every possible label in order (for example
    [1, 2, 3, 4, 5]); two labels i and j positions apart disagree with
    weight |i - j| / (C - 1). Kappa = 1 - observed weighted disagreement /
    expected weighted disagreement (expected from each side's label
    frequencies), which equals (po_w - pe_w) / (1 - pe_w) with agreement
    weights 1 - |i - j| / (C - 1). None when there are no pairs, fewer than
    two categories, or the expected agreement is 1. A label outside
    `categories` raises ValueError."""
    order = list(categories)
    position = {label: index for index, label in enumerate(order)}
    if len(position) != len(order):
        raise ValueError("categories must not repeat")
    pairs = list(pairs)
    n = len(pairs)
    if n == 0 or len(order) < 2:
        return None
    for a, b in pairs:
        for label in (a, b):
            if label not in position:
                raise ValueError(f"label {label!r} is not one of the categories {order!r}")
    # The common factor 1 / (C - 1) cancels in the ratio, so plain position
    # distances are used.
    observed = sum(abs(position[a] - position[b]) for a, b in pairs)
    first = Counter(position[a] for a, _ in pairs)
    second = Counter(position[b] for _, b in pairs)
    expected = sum(first[i] * second[j] * abs(i - j) for i in first for j in second)
    if expected == 0:
        return None
    return float(1 - Fraction(observed * n, expected))
