#!/usr/bin/env python3
"""缺陷计划生成器（W2A §6.3(1) ①；`ECC-0FC756057411`）。

从种子产出 `(plan_text, gold_defects)`：基线计划 + k∈[2,5] 个注入缺陷，附判分对照的金标集。

  D1 contradiction        一步要求 X，另一步要求非 X
  D2 dangling dependency  一步消费无任何步骤产出的 artifact
  D3 unsupported claim    强结论无验证即断言
  D4 dependency inversion 一步消费「后置步骤」的 artifact
  D5 over-reach           一步超越约束矩阵的授权范围

注入**确定性**（同种子 ⟹ 逐字节相同）。每个注入缺陷在计划里留**一条特征 clause**，金标记录
携该 clause 原文，判分器（`gk_moa_judge`）靠**臂回引的 clause** 复原缺陷 id（臂是对**它引的
证据**判分，非自由转述 —— 该代理性见判分器 docstring）。

难度旋钮 = k（2–5）+ `stealth`（环绕干扰句）。防天花板 = `--escalate` 语义（k+1），由调用方
在臂饱和（`det_F1 == 1`）时施加。

**纯库**（禁直接执行；技能内置 cmd 路由）。
"""
import random

CODES = ("D1", "D2", "D3", "D4", "D5")

PLAN_TITLE = "add a guarded stopping criterion to the review loop"
PLAN_GOAL = ("stop the refinement loop on a measured decay ratio rather than a "
             "wall-clock budget; refuse to emit a horizon when the stock does not decay.")

# distractor clauses (stealth): real planning language that carries no defect.
DISTRACTORS = (
    "keep the change behind the existing feature flag;",
    "record the estimator version in the appendix;",
    "preserve the current journal format;",
    "no new dependency is introduced;",
)


def _base_steps():
    return [
        "read the sealed ledger and recompute the per-round defect counts mu_n;",
        "fit the decay ratio r_hat as the geometric mean of adjacent ratios;",
        "emit the horizon N* when r_hat < 1, circuit-break when r_hat >= 1;",
    ]


def _inject(code, steps, rng, stealth):
    """Append/insert one defect step; return `(steps, gold_record)`.

    The distinctive clause is fixed per code (so the judge can match it) but its
    step number / artifact name vary with `rng`, and `stealth` pads it with
    distractor clauses so the defect is not the last thing in the plan.
    """
    idx = len(steps) + 1
    if code == "D1":
        ref = rng.choice(range(1, idx))
        clause = "this contradicts step %d" % ref
        step = "require the horizon to be emitted only when r_hat >= 1; %s;" % clause
    elif code == "D2":
        missing = "calibration-table-%d" % rng.randint(100, 999)
        clause = "produced by undefined artifact %s" % missing
        step = "consume the %s %s;" % (missing, clause)
    elif code == "D3":
        clause = "asserted without verification"
        step = "conclude that the decay is guaranteed to converge, %s;" % clause
    elif code == "D4":
        clause = "before it is produced"
        producer = idx + rng.randint(1, 3)
        step = "emit the horizon from the estimate of step %d %s;" % (producer, clause)
    elif code == "D5":
        clause = "beyond the authorized scope"
        step = "modify the sealed ledger directly, bypassing the review gate, %s;" % clause
    else:
        raise ValueError("unknown defect code: %r" % code)

    if stealth > 0:
        pads = rng.sample(DISTRACTORS, min(stealth, len(DISTRACTORS)))
        step = step + " " + " ".join(pads)

    if code == "D4":
        steps = [step] + steps        # inversion: consumer placed BEFORE its producer
    else:
        steps = steps + [step]
    return steps, {"id": code, "code": code, "clause": clause}


def render(steps):
    body = "\n".join("%d. %s" % (i + 1, s) for i, s in enumerate(steps))
    return ("# Plan: %s\n## Goal\n%s\n## Steps\n%s\n"
            "## Constraints\n- the sealed ledger is read-only after the review gate.\n"
            % (PLAN_TITLE, PLAN_GOAL, body))


def generate(seed, k=3, stealth=1):
    """One plan with `k` distinct injected defects.  Deterministic in (seed, k, stealth)."""
    if not 2 <= k <= len(CODES):
        raise ValueError("k must be in [2, %d]" % len(CODES))
    rng = random.Random(seed)
    codes = list(CODES)
    rng.shuffle(codes)
    chosen = codes[:k]
    steps, gold = _base_steps(), []
    for c in chosen:
        steps, g = _inject(c, steps, rng, stealth)
        gold.append(g)
    for g in gold:                    # step index filled AFTER every injection
        g["step"] = next((i + 1 for i, s in enumerate(steps) if g["clause"] in s), None)
    return {"seed": seed, "k": k, "stealth": stealth,
            "codes": chosen, "plan_text": render(steps), "gold": gold}
