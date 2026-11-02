"""
test_gk_moa_chain_t2.py -- MoA 链 T2 红先臂：P/L/M 分组**独立 CLI 出口**（`--group`）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T2「把 `assess_findings` 的
`carrier:L/P/M` 分面独立导出（`--group`），供链消费」。

现状：`plm_groups()` 已存在（骨架，复用 `assess_findings` 禁第二实现），但**无 CLI 出口**
（`moa-aggregate` 未注册/转发 `--group`）—— 调用方拿不到分组，链只能吃封套里的 `steps.plm`。

本切片：① 单元钉 `plm_groups` 形态（P/L/M 恒在 + 分类正确）；② 行为臂钉 `--group` 出口；
③ 形态臂钉 CLI 转发（零新增 `_CMD_REG`，挂既有 `moa-aggregate`）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
CLI = SCRIPTS.parent / "gatekeeper-cli.sh"


def _agg(cons, refs=None, clusters=None):
    return {"references": refs or [], "clusters": clusters or [], "trace": {},
            "consensus": cons}


# ── ① 单元：形态（P/L/M 恒在）+ 分类正确 ────────────────────────────────────
def test_plm_groups_shape_always_has_three_keys():
    from gk_moa_aggregate import plm_groups
    g = plm_groups(_agg({}))
    assert set(g) == {"P", "L", "M"}, g


def test_plm_groups_classifies_mechanism_to_M():
    """批级机制信号（弃权 / 污染率>0）⟹ 归 M。"""
    from gk_moa_aggregate import plm_groups
    g = plm_groups(_agg({"abstain": True, "top_weight": 0.1, "min_agreement": 0.5,
                         "pollution_tilt": 0.2}))
    assert len(g["M"]) >= 2, g


def test_plm_groups_classifies_dissent_to_P():
    """臂间实质分歧（≥2 簇且未弃权）⟹ 归 P。"""
    from gk_moa_aggregate import plm_groups
    g = plm_groups(_agg({"n_clusters": 2, "abstain": False}))
    assert len(g["P"]) >= 1, g


# ── ② 行为臂：`--group` 直接导出 `{"plm": …}` ───────────────────────────────
def test_group_flag_emits_plm(tmp_path, monkeypatch, capsys):
    import gk_moa_aggregate as M
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: _agg(
        {"abstain": True, "top_weight": 0.1, "min_agreement": 0.5, "pollution_tilt": 0.2}))
    monkeypatch.setattr(sys, "argv", ["gk_moa_aggregate.py", "--state", str(st), "--group"])
    rc = M.main()
    out = capsys.readouterr().out
    assert rc == 0, (rc, out)
    assert '"plm"' in out and '"mode": "plm_groups"' in out, out


# ── ③ 形态臂：CLI 转发（挂既有 moa-aggregate，零新增 _CMD_REG）──────────────
def test_cli_forwards_group_flag():
    s = CLI.read_text(encoding="utf-8")
    assert "--group) group_flag=true" in s, "--group 未解析"
    assert "$group_flag && args+=(--group)" in s, "--group 未转发到 python"
    assert "_CMD_REG[moa-aggregate]" in s and "_CMD_REG[plm-groups]" not in s, "不得新增 _CMD_REG"


def test_python_has_group_arg_and_branch():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert 'add_argument("--group"' in src, "python 未注册 --group"
    assert "if args.group:" in src, "python 未处理 --group"
    assert "plm_groups(agg)" in src, "--group 未经 plm_groups（禁第二实现）"
