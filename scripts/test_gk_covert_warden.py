#!/usr/bin/env python3
"""红先臂：T4 隐蔽事件通道 warden（§9.6 Q4 / §9.5 ⚠修）—— Storage / Timing / Behavioral 三轴。

缺陷（`ECC-F3A27EB08725`）：本仓**无 warden / 无隐写分析**；相关性降权只对**显式相关**有效，
对**隐蔽通道**（Storage/Timing/Behavioral）**不可见** ⟹ 一致度虚高 = **假收敛**（Whispering
Agents, AAAI-26, `arXiv:2508.02188`：三轴 + IND-STAT/IND-INT）。

判据（HEAD 必红 —— `gk_covert_warden` 尚不存在 ⟹ 各臂 import 即红）：
  1) 模块 + 三轴函数实存；
  2) **Storage**：Unicode 隐写（零宽/BOM/RLI）在共享面残留 → flag；
  3) **Timing**：臂间完成时刻的**时序独立性 IND-STAT**；`n` 小 → `UNDER_POWERED`
     （**不得**读作"无隐蔽通道"）；间隔过于规则 → `DEPENDENT`；
  4) **Behavioral**：臂间**结构去重 IND-INT**（证据锚集合 Jaccard 超阈 → flag）。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))


def test_three_axis_scan_exists():
    import gk_covert_warden as W
    for fn in ("scan_storage", "ind_stat", "ind_int", "scan"):
        assert hasattr(W, fn), "缺 %s" % fn


def test_storage_flags_unicode_stego(tmp_path):
    import gk_covert_warden as W
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {"subagent_history": [
        {"subagent_id": "sub-1", "conclusion": "x\u200by"}]}}, ensure_ascii=False), encoding="utf-8")
    r = W.scan_storage(str(st))
    assert r.get("hits"), r


def test_ind_stat_underpowered_small_n():
    import gk_covert_warden as W
    r = W.ind_stat([100, 101, 130, 131])
    assert r["verdict"] == "UNDER_POWERED", r
    assert r["verdict"] != "INDEPENDENT", "n 小 ⟹ 不得读作无通道"


def test_ind_stat_flags_too_regular():
    import gk_covert_warden as W
    r = W.ind_stat([0, 10, 20, 30, 40, 50, 60, 70])
    assert r["verdict"] == "DEPENDENT", r


def test_ind_int_flags_structural_dup():
    import gk_covert_warden as W
    arms = [{"subagent_id": "a", "anchors": ["f.py:1", "f.py:2"]},
            {"subagent_id": "b", "anchors": ["f.py:1", "f.py:2"]},
            {"subagent_id": "c", "anchors": ["g.py:9"]}]
    r = W.ind_int(arms)
    assert r.get("pairs"), r
    assert any(p["jaccard"] >= 0.9 for p in r["pairs"]), r


def test_scan_returns_three_axes(tmp_path):
    import gk_covert_warden as W
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {"subagent_history": [
        {"subagent_id": "sub-%d" % i, "batch_id": "b" * 12, "arm_group": "G1",
         "anchors": ["f.py:%d" % i], "ts": 1000 + i * 7} for i in range(6)]}},
        ensure_ascii=False), encoding="utf-8")
    r = W.scan(str(st))
    for axis in ("storage", "timing", "behavioral"):
        assert axis in r, r


# ══════════ 接线臂：warden 挂进聚合入口（§5，`ECC-143409BC4A8C`）══════════
# 病象：warden 已落 `scripts/gk_covert_warden.py`，但**无消费方** —— `moa-aggregate`
#   既不认 `--covert-scan` 也不把三轴封套并入聚合输出 ⟹ 纸老虎（判据在源码却不可达）。
# 修法：`gk_moa_aggregate._covert_scan`（延迟导入单源） + argparse `--covert-scan` +
#   调用并入 `agg["covert"]`；`gatekeeper-cli.sh cmd_moa_aggregate` 白名单转发。
# 判据（HEAD 必红）：修前无 `_covert_scan` / argparse 拒收该 flag / CLI 未转发。

def test_covert_scan_helper_exists():
    """接线臂：`gk_moa_aggregate` 须提供 `_covert_scan`（warden 挂点，禁第二实现）。"""
    import gk_moa_aggregate as M
    assert hasattr(M, "_covert_scan"), "gk_moa_aggregate 缺 _covert_scan（warden 未接线）"


def test_covert_scan_flag_attaches_axis(tmp_path):
    """功能臂（真跑入口）：`--covert-scan` 须把三轴封套并入聚合输出（键 `covert`）。"""
    import subprocess
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {"subagent_history": [
        {"subagent_id": "sub-%d" % i, "anchors": ["f.py:%d" % i], "ts": 1000 + i * 7}
        for i in range(6)]}}, ensure_ascii=False), encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "gk_moa_aggregate.py"),
         "--state", str(st), "--covert-scan"],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout + r.stderr)[:400]
    agg = json.loads(r.stdout)
    assert "covert" in agg, "聚合封套缺 covert（--covert-scan 未并入）"
    assert {"storage", "timing", "behavioral"} <= set(agg["covert"]), agg["covert"]


def test_covert_scan_cli_forwards_flag():
    """接线臂（源码形态）：`cmd_moa_aggregate` 须白名单转发 `--covert-scan`。"""
    cli = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8", errors="replace")
    seg = cli.split("cmd_moa_aggregate()", 1)[1].split("\n}", 1)[0]
    assert "local covert_scan=false" in seg, "缺旗标声明"
    assert "--covert-scan) covert_scan=true" in seg, "缺 case 分支（flag 未被认领）"
    assert "args+=(--covert-scan)" in seg, "缺转发（认领后未喂 python）"
