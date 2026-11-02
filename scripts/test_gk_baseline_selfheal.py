#!/usr/bin/env python3
"""质询前置基线刷新「纯 analyze 刷不动卡死索引」—— 红先臂（2026-10-07，ECC-9FD1BEB74F82）。

病象：`_review_channel_preflight` 的 B 块（plan-refinement 通道）与 `_gitnexus_ensure_baseline`
  在 status=stale 时都调**纯** `_run_gitnexus analyze`；对**卡死态**索引
  （`incremental-in-progress` + `embedding-checkpoint-pending`）无法清除 ⟹ 刷完仍 stale
  ⟹ fail-closed `BASELINE_STALE` ⟹ 3×K 臂全 rc≠0 ⟹ `dispatch_blocked`（且真因被 rm -rf 吞）。
  能清残态的**唯一**自愈是 `_gx_analyze_embeddings`（--embeddings → 失败再 --drop-embeddings）。

判据（红先，落刀前 HEAD **必红**）：
  arm1  B 块的 stale 刷新须改走 `_gx_analyze_embeddings "$_bl_dir"`（HEAD 为纯 analyze → 红）
  arm2  `_gx_analyze_embeddings` 的 analyze 须显式 `GK_GX_DIR="$dir"`（HEAD 未传 → 红）
  arm3  `_gitnexus_ensure_baseline` 须改走 `_gx_analyze_embeddings "$dir"`（HEAD 纯 analyze → 红）
  arm4  自愈须**跨进程单飞**（flock），并发臂不并发 analyze（HEAD 无锁 → 红）
  arm5  `dispatch_blocked` 报文须回传逐臂真因 `reason`（HEAD 无 → 红）
  arm6  守门臂（改前已绿）：`_gx_analyze_embeddings` 仍是 `analyze --embeddings` 的**单源**
  arm7  守门臂（改前已绿）：`BASELINE_STALE` + `GK_ALLOW_STALE_BASELINE` 逃生口不得被本刀破坏
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def _body(name: str) -> str:
    s = _src()
    i = s.find("\n" + name + "() {")
    assert i != -1, "函数 %s 不存在" % name
    j = s.find("\n}", i)
    assert j != -1, "函数 %s 无闭合" % name
    return s[i:j]


def test_arm1_preflight_b_routes_selfheal():
    """arm1：B 块 stale 刷新必须走自愈单源，而非纯 analyze。

    2026-10-27（U3 归因）：刷新已上抽为单一源 `_gitnexus_refresh_if_stale`（`106516c`，
    2026-10-16）⟹ 判据改**两段式**，比原单字面更强：B 块调 helper，且 helper 内走
    `_gx_analyze_embeddings`（残态自愈 + 跨进程单飞都在后者里）。
    """
    b = _body("_review_channel_preflight")
    assert '_gitnexus_refresh_if_stale "$_bl_dir"' in b, (
        "B 块未走 gitnexus 刷新 helper ⟹ 卡死索引刷不绿 ⟹ BASELINE_STALE 全臂拦停")
    h = _body("_gitnexus_refresh_if_stale")
    assert '_gx_analyze_embeddings "$_d"' in h, (
        "刷新 helper 未走自愈单源 `_gx_analyze_embeddings` ⟹ 残态（incremental-in-progress / "
        "embedding-checkpoint-pending）仍刷不绿")


def test_arm2_selfheal_pins_gx_dir():
    """arm2：自愈须把目标目录显式传入（否则隐式靠 _gx_repo_dir_for_current，可能刷错仓）。"""
    b = _body("_gx_analyze_embeddings")
    assert 'GK_GX_DIR="$dir"' in b, "自愈未显式钉 GK_GX_DIR ⟹ analyze 目标非入参 dir"


def test_arm3_ensure_baseline_routes_selfheal():
    """arm3：登记侧基线确保同样须走自愈单源。"""
    b = _body("_gitnexus_ensure_baseline")
    assert '_gx_analyze_embeddings "$dir"' in b, (
        "_gitnexus_ensure_baseline 仍用纯 analyze ⟹ 卡死索引同样刷不绿")


def test_arm4_selfheal_singleflight():
    """arm4：自愈须跨进程单飞，防 3×K 臂并发 analyze 踩踏（lbug.wal.dirty-recovery）。"""
    b = _body("_gx_analyze_embeddings")
    assert "flock" in b, "自愈无跨进程互斥 ⟹ 并发臂各起 analyze 互相踩踏"


def test_arm5_dispatch_blocked_carries_reason():
    """arm5：dispatch_blocked 须回传逐臂真因（否则真因被 rm -rf 吞，只剩笼统报错）。

    2026-10-27（U3 归因）：原取**首个**含 `dispatch_blocked` 的行 —— 2026-10-19 起首个命中是
    注释（`gatekeeper-cli.sh:4855` 的 W2A-L0 说明），并非发射行 ⟹ 判据改为只看**echo 发射行**
    （允许多条：每条都须带 `reason`）。
    """
    lines = [l for l in _src().splitlines()
             if "dispatch_blocked" in l and l.lstrip().startswith("echo")]
    assert lines, "未找到 dispatch_blocked 发射行（判据失焦 ⟹ fail-loud）"
    bad = [l for l in lines if "reason" not in l]
    assert not bad, f"dispatch_blocked 未回传 reason ⟹ 失败真因不可达：{bad[0][:300]}"


def test_arm8_dispatch_success_carries_receipt():
    """arm8（2026-10-08，ECC-64F4D0BF14F1）：批级下发**成功**路径须回执 JSON。

    病象：成功路径原只 `return 0`、**零 stdout**（`bat` 块末）⟹ 0 字节回执被误判为
    「静默失败 / fail-open」（本会话实测误判）。失败路径已有 `dispatch_blocked` ⟹ 成功侧须对称补。
    """
    s = _src()
    assert "\\\"dispatched\\\"" in s and "\\\"mode\\\":\\\"batch\\\"" in s, \
        "批级下发成功路径无回执 ⟹ 结果不可观测（易被误判为静默失败）"


def test_arm6_embeddings_single_source():
    """arm6（守门）：analyze --embeddings 仍单源 —— 代码行次数 == _gx_analyze_embeddings 内次数。"""
    def _code(s):
        return "\n".join(l for l in s.splitlines() if not l.lstrip().startswith("#"))
    total = _code(_src()).count("analyze --embeddings")
    inside = _code(_body("_gx_analyze_embeddings")).count("analyze --embeddings")
    assert total == inside and total > 0, (
        "analyze --embeddings 出现第二实现（_gx_analyze_embeddings 之外）")


def test_arm7_escape_hatch_preserved():
    """arm7（守门）：基线门与逃生口不得被本刀破坏。

    2026-11-02：门仍在，但阻断面收窄到 `unavailable`（`stale` → advisory）。
    """
    s = _src()
    assert "BASELINE_UNAVAILABLE" in s, "基线门判定被破坏（unavailable 分支被删）"
    assert "GK_ALLOW_STALE_BASELINE" in s, "逃生口被破坏（依赖不可用不得锁死序列）"
