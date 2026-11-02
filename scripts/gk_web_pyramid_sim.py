#!/usr/bin/env python3
"""gk_web_pyramid_sim.py — zero-API simulation for the W2A evidence-sharing pyramid.

Purpose
-------
Before spending API budget on the Web plan-challenge batch, check whether the
proposed measures can distinguish *independent evidence* from *shared-source
echo*.  The pyramid is implemented as an evidence-sharing topology:

  L0 independent   : each arm retrieves its own sources
  L1 broadcast     : one scout's sources are shared with all arms
  L2 downward      : a curated shared pool is pushed down; arms may add local
  L3 peer union    : all arms see the union of all retrieved sources

Measures
--------
  rho            pairwise Jaccard of source-id sets (mean)
  n_eff          Kish effective number of independent clusters
  agreement      largest verdict cluster / n_arms
  error_plain    majority verdict wrong
  error_disc     majority after deduplicating identical evidence sets
  false_conv     agreement >= 0.8 and error_plain >= error at L0
  abstain        n_eff < 2 (or no strict majority) under the discounted rule

This is a *design check*, not a claim about real models.  Pure stdlib; no API.
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import random
from typing import Iterable


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / float(len(sa | sb))


def kish(sizes: Iterable[int]) -> float:
    ss = [int(s) for s in sizes if int(s) > 0]
    total = sum(ss)
    if total <= 0:
        return 0.0
    return (total * total) / float(sum(s * s for s in ss))


LEVEL_SHARED = {"L0": 0.0, "L1": 0.4, "L2": 0.8, "L3": 1.0}


def _pool(prefix: str, n: int, quality: float, common_bias: float,
          rng: random.Random) -> dict[str, int]:
    """Return source-id -> truth (1 correct / 0 wrong).

    ``common_bias`` flips the *whole* pool with that probability (common cause);
    otherwise each source is independently wrong with ``1-quality``.
    """
    common_wrong = rng.random() < common_bias
    out: dict[str, int] = {}
    for i in range(n):
        if common_wrong:
            out[f"{prefix}-s{i}"] = 0
        else:
            out[f"{prefix}-s{i}"] = 1 if rng.random() < quality else 0
    return out


def _pick_sources(level: str, arm: int, n_sources: int,
                  shared_ids: list[str], local_ids: list[str]) -> list[str]:
    """Deterministic shared prefix + independent local suffix."""
    frac = LEVEL_SHARED[level]
    k_shared = int(round(n_sources * frac))
    k_shared = max(0, min(n_sources, k_shared))
    k_local = n_sources - k_shared
    local = [local_ids[(arm + i) % len(local_ids)] for i in range(k_local)]
    return shared_ids[:k_shared] + local


def _verdict(arm: int, sources: list[str], truth: dict[str, int],
             k: float, noise: float, phase_effect: float,
             cache_effect: float, rng: random.Random) -> int:
    """Bernoulli verdict; returns 1 if the arm says 'defect present'."""
    if not sources:
        return 0
    score = sum(truth.get(s, 0) for s in sources) / float(len(sources))
    # phase/cache act as measurement-channel biases on a subset of arms
    phase_bias = phase_effect * (1 if arm % 2 == 0 else -1)
    cache_bias = cache_effect * (1 if (arm // 2) % 2 == 0 else -1)
    logit = k * (score - 0.5) + phase_bias + cache_bias
    p = 1.0 / (1.0 + math.exp(-logit))
    p = min(1.0 - noise, max(noise, p))
    return 1 if rng.random() < p else 0


def _majority(verdicts: list[int]) -> int | None:
    ones = sum(verdicts)
    zeros = len(verdicts) - ones
    if ones == zeros:
        return None
    return 1 if ones > zeros else 0


def simulate_level(level: str, *, sims: int, n_arms: int, n_sources: int,
                   quality: float, shared_bias: float, k: float, noise: float,
                   phase_effect: float, cache_effect: float,
                   rng: random.Random) -> dict:
    rhos, neffs, neff_ev, agrs, errs, errs_disc, abstains = [], [], [], [], [], [], []
    false_conv = 0
    for _ in range(sims):
        # One shared pool + one local pool per arm.
        shared_pool = _pool("shared", 32, quality, shared_bias, rng)
        local_pools = {a: _pool(f"a{a}", 32, quality, 0.0, rng)
                       for a in range(n_arms)}
        truth: dict[str, int] = dict(shared_pool)
        for p in local_pools.values():
            truth.update(p)

        shared_ids = sorted(shared_pool)
        arm_sources = []
        for a in range(n_arms):
            local_ids = sorted(local_pools[a])
            arm_sources.append(_pick_sources(level, a, n_sources,
                                             shared_ids, local_ids))
        rho_sim = (sum(jaccard(arm_sources[i], arm_sources[j])
                       for i, j in itertools.combinations(range(n_arms), 2))
                   / max(1, len(list(itertools.combinations(range(n_arms), 2)))))
        rhos.append(rho_sim)
        # Design-effect effective number of independent arms: n / (1 + (n-1) rho).
        neff_ev.append(n_arms / (1.0 + (n_arms - 1) * rho_sim))

        verdicts = [_verdict(a, arm_sources[a], truth, k, noise,
                             phase_effect, cache_effect, rng)
                    for a in range(n_arms)]
        cluster_sizes = [sum(1 for v in verdicts if v == c) for c in (0, 1)]
        neffs.append(kish([s for s in cluster_sizes if s > 0]))
        agrs.append(max(cluster_sizes) / float(n_arms))

        maj = _majority(verdicts)
        errs.append(0 if maj == 1 else 1)  # gold = defect present (1)

        # Discounted: deduplicate identical evidence sets; each unique set counts once.
        seen: dict[tuple[str, ...], list[int]] = {}
        for a in range(n_arms):
            key = tuple(sorted(arm_sources[a]))
            seen.setdefault(key, []).append(verdicts[a])
        unique_verdicts = []
        for vs in seen.values():
            v = _majority(vs)
            if v is not None:
                unique_verdicts.append(v)
        maj_d = _majority(unique_verdicts) if unique_verdicts else None
        errs_disc.append(0 if maj_d == 1 else 1)
        abstains.append(1 if (maj_d is None or neff_ev[-1] < 2.0) else 0)

    mean = lambda xs: sum(xs) / float(len(xs)) if xs else 0.0
    return {
        "level": level,
        "rho": round(mean(rhos), 4),
        "n_eff_evidence": round(mean(neff_ev), 4),
        "n_eff_verdict": round(mean(neffs), 4),
        "agreement": round(mean(agrs), 4),
        "error_plain": round(mean(errs), 4),
        "error_discounted": round(mean(errs_disc), 4),
        "false_convergence": round(sum(1 for a, e in zip(agrs, errs)
                                       if a >= 0.8 and e == 1) / float(sims), 4),
        "abstain": round(mean(abstains), 4),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sims", type=int, default=300)
    ap.add_argument("--n-arms", type=int, default=6)
    ap.add_argument("--n-sources", type=int, default=5)
    ap.add_argument("--quality", type=float, default=0.85)
    ap.add_argument("--shared-bias", type=float, default=0.30)
    ap.add_argument("--k", type=float, default=6.0)
    ap.add_argument("--noise", type=float, default=0.02)
    ap.add_argument("--phase-effect", type=float, default=0.0)
    ap.add_argument("--cache-effect", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=20261018)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    rows = []
    for level in ("L0", "L1", "L2", "L3"):
        rows.append(simulate_level(
            level, sims=args.sims, n_arms=args.n_arms,
            n_sources=args.n_sources, quality=args.quality,
            shared_bias=args.shared_bias, k=args.k, noise=args.noise,
            phase_effect=args.phase_effect, cache_effect=args.cache_effect,
            rng=rng))
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print("level    rho   n_eff_ev  n_eff_verd  agree  err_plain  err_dedup  false_conv  abstain")
        for r in rows:
            print("%-5s %6.4f %9.4f %11.4f %6.4f %9.4f %9.4f %11.4f %8.4f" % (
                r["level"], r["rho"], r["n_eff_evidence"], r["n_eff_verdict"],
                r["agreement"], r["error_plain"], r["error_discounted"],
                r["false_convergence"], r["abstain"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
