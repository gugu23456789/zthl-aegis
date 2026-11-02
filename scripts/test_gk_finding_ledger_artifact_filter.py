#!/usr/bin/env python3
"""影子域枚举的**旁挂产物过滤**回归（`ECC-8F359340A5B9`，2026-10-01，**红先**）。

病象（只读取证，`finding ledger` 现场）：
  `sources` 里混进两条**伪域** —— `credit-ledger.jsonl.seal` / `budget-log.jsonl.seal`
  （`domain=…`、`kind=domain`、`total=0`）⟹ 域枚举虚增、`ids_total` 被污染；
  更糟：`--domain credit-ledger.jsonl.seal` 会被 `resolve_domain_state` 判为**存在**，
  写下去即**砸掉封印文件**。

根因 = **产物命名体系漂移**：模块名用下划线（`gk_credit_ledger` / `gk_budget_ledger`），
产物名用连字符（`.credit-ledger.jsonl` / `.budget-log.jsonl`），而**旁挂后缀清单在消费者侧
手抄第二份**（`gk_finding._LEDGER_ARTIFACT_SUFFIXES`）⟹ 后加的 `.seal`（`SEAL_SUFFIX`）
漏登记（`.jsonl` 收录了、`.jsonl.seal` 没有）。

各臂（落刀前 A1/A2/A4 红，A3 恒绿）：
  A1 `_is_live_ledger_name` 对封印文件必须 False；
  A2 **抗漂移**：账本模块声明的 `SUFFIX` / `SEAL_SUFFIX` 必须被过滤清单覆盖（单源派生判据）；
  A3（反臂）真活体域 state 仍须 True（防「一刀切成全过滤」把域枚举打死）；
  A4（行为）`_ledger_sources` 只回 base + 真域，**不含**任何 `.seal`。
"""
import json
from pathlib import Path

import gk_budget_ledger
import gk_credit_ledger
import gk_finding

SEAL_NAMES = (
    ".gatekeeper.state.credit-ledger.jsonl.seal",
    ".gatekeeper.state.budget-log.jsonl.seal",
)


def _covered(name: str) -> bool:
    """名字是否被旁挂产物过滤清单覆盖（`endswith` 语义，与 `_is_live_ledger_name` 同源）。"""
    return name.endswith(gk_finding._LEDGER_ARTIFACT_SUFFIXES)


def test_arm1_seal_is_not_live_ledger():
    """A1：`<state>.<ledger>.jsonl.seal` 是**封印**、不是活体域 ledger。"""
    for n in SEAL_NAMES:
        assert gk_finding._is_live_ledger_name(n) is False, (
            "%s 被判为活体域 ledger（封印文件可被当域写入 ⟹ 毁封印）：%r"
            % (n, gk_finding._LEDGER_ARTIFACT_SUFFIXES))


def test_arm2_ledger_suffixes_covered_by_filter():
    """A2（抗漂移）：账本模块声明的产物后缀必须全部被过滤清单覆盖 —— 治「手抄第二份」漂移。"""
    declared = {
        "gk_credit_ledger.SUFFIX": gk_credit_ledger.SUFFIX,
        "gk_credit_ledger.SEAL_SUFFIX": gk_credit_ledger.SEAL_SUFFIX,
        "gk_credit_ledger.BASELINE_SUFFIX": gk_credit_ledger.BASELINE_SUFFIX,
        "gk_budget_ledger.SUFFIX": gk_budget_ledger.SUFFIX,
        "gk_budget_ledger.SEAL_SUFFIX": gk_budget_ledger.SEAL_SUFFIX,
    }
    miss = [k for k, v in declared.items() if not _covered(".gatekeeper.state" + v)]
    assert not miss, (
        "旁挂产物后缀未被 `_LEDGER_ARTIFACT_SUFFIXES` 覆盖（会被当活体域 ledger）：%s；"
        "现清单=%r" % (miss, gk_finding._LEDGER_ARTIFACT_SUFFIXES))


def test_arm5_baseline_suffix_cannot_be_domain(tmp_path):
    """A5（2026-10-19）：签名基线 sidecar 不得被 `--domain` 当域 state 写入。"""
    import pytest as _pytest
    base = tmp_path / ".gatekeeper.state"
    base.write_text(json.dumps({"gate_data": {}}, ensure_ascii=False), encoding="utf-8")
    bp = tmp_path / (".gatekeeper.state" + gk_credit_ledger.BASELINE_SUFFIX)
    bp.write_text("{}\n", encoding="utf-8")
    with _pytest.raises(ValueError):
        gk_finding.resolve_domain_state_ex(
            str(base), gk_credit_ledger.BASELINE_SUFFIX.lstrip("."))


def test_arm3_real_domain_state_still_live():
    """A3（反臂）：真活体域 state 仍须判为活体（防过度过滤把域枚举打死）。"""
    for n in (".gatekeeper.state.my-plan-2026", ".gatekeeper.state.spz2glb.r7"):
        assert gk_finding._is_live_ledger_name(n) is True, "真域被误过滤：%s" % n


def test_arm4_ledger_sources_excludes_seals(tmp_path, monkeypatch):
    """A4（行为）：`_ledger_sources` 只枚举 base + 真域，旁挂账本与其封印一律不收。"""
    # 隔离：`_ledger_sources` 默认跨仓扫描（`_candidate_repos`）会把本仓真实域 ledger 带入
    #   ⟹ 本臂只测「同目录产物过滤」，必须钉死候选仓为空（否则断言随环境漂移）。
    monkeypatch.setattr(gk_finding, "_candidate_repos", lambda state_file: [])
    base = tmp_path / ".gatekeeper.state"
    base.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    (tmp_path / ".gatekeeper.state.plan-a").write_text(json.dumps({"gate_data": {}}),
                                                       encoding="utf-8")
    (tmp_path / ".gatekeeper.state.credit-ledger.jsonl").write_text('{"x":1}\n', encoding="utf-8")
    (tmp_path / ".gatekeeper.state.credit-ledger.jsonl.seal").write_text(
        json.dumps({"alg": "sha256"}), encoding="utf-8")
    (tmp_path / ".gatekeeper.state.budget-log.jsonl.seal").write_text(
        json.dumps({"alg": "sha256"}), encoding="utf-8")

    doms = sorted(d for _p, d, _k in gk_finding._ledger_sources(str(base)))
    assert doms == ["", "plan-a"], (
        "域枚举被旁挂产物污染（封印被当域）：%r" % (doms,))
