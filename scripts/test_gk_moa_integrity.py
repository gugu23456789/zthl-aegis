#!/usr/bin/env python3
"""s5 红先：MoA 完整性 + 臂间离散检测器（消融 vs 正规可显著区分）（2026-10-14）。

动机（六个窄任务质询裁定）：`gk_task_gate.submit --expand-groups` 在 `narrow_tasks[]`
不足时**曾静默回退同名复制**（`group_tasks:false`）⟹「3 组 MoA」被静默降级成 3×K 个
**同题**样本（组别只剩 index 标签）= 假 MoA。入口侧已 fail-closed，但**产物侧无任何判据**
能自证「这批臂真的按组分化」——本模块补**事后可观测量**（纯函数，0 网络/0 写盘）。

红先（HEAD 必红 = `gk_moa_integrity` 模块不存在）：
  1 退化   6 条同题、无臂标记 ⟹ degenerate + verdict=FAIL + circuit_break（假 MoA 签名）
  2 正规   3 组×2 臂、逐臂窄任务不同 ⟹ OK + narrow_hit_rate=1.0 + 零熔断
  3 缺组   仅 2 组 ⟹ FAIL（distinct_groups < expected_groups）
  4 离散   控制（组内≈组间）F≈0/p→1；处理（组间≫组内）F 大/p 小 ⟹ **消融 vs 正规可区分**
  5 并发   adaptive_workers 核数/clamp/内存下限语义（硬件自适应）
  6 CLI    integrity 子命令读 state 出 JSON；FAIL ⟹ 退出码 2（熔断候选）
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_hub_scheduler as hs  # noqa: E402  (s5.5：自适应并发度唯一源)
from gk_moa_integrity import (adaptive_workers, arm_dispersion,  # noqa: E402
                              parse_arm_marker, pipeline_integrity)


def _mk(g, nid, body):
    """按 gk_task_gate._group_expand_records 的**逐字**格式造臂记录。"""
    return {"id": "arm-%s-%s" % (g, nid),
            "full_task": "plan-refinement: p — t\n\n【本臂窄任务（G%s｜id=%s）】\n%s"
                         % (g, nid, body)}


class TestPipelineIntegrity:
    def test_arm1_degenerate_circuit_break(self):
        """6 条逐字同题、零臂标记 = fail-open 回退的现场 ⟹ 必须判 FAIL + 熔断候选。"""
        recs = [{"id": "r%d" % i, "full_task": "plan-refinement: p — 同题"} for i in range(6)]
        r = pipeline_integrity(recs, expected_arms=6)
        assert r["arms"] == 6
        assert r["valid_markers"] == 0
        assert r["distinct_full_tasks"] == 1
        assert r["distinct_groups"] == 0
        assert r["degenerate"] is True
        assert r["verdict"] == "FAIL"
        assert r["circuit_break"] is True

    def test_arm2_proper_grouped_ok(self):
        recs = [_mk(g, "nt-g%d-%d" % (g, j), "正文%d%d" % (g, j))
                for g in (1, 2, 3) for j in (1, 2)]
        r = pipeline_integrity(recs, expected_arms=6)
        assert r["arms"] == 6
        assert r["distinct_groups"] == 3
        assert r["distinct_narrow_ids"] == 6
        assert r["distinct_full_tasks"] == 6
        assert r["narrow_hit_rate"] == 1.0
        assert r["degenerate"] is False
        assert r["circuit_break"] is False
        assert r["verdict"] == "OK"

    def test_arm3_missing_group_fails(self):
        recs = [_mk(g, "nt-g%d-%d" % (g, j), "X") for g in (1, 2) for j in (1, 2)]
        r = pipeline_integrity(recs, expected_groups=3, expected_arms=6)
        assert r["distinct_groups"] == 2
        assert r["distinct_narrow_ids"] == 4
        assert r["narrow_hit_rate"] < 1.0
        assert r["degenerate"] is True
        assert r["verdict"] == "FAIL"
        assert "insufficient_groups" in r["reasons"]

    def test_parse_arm_marker(self):
        g, nid = parse_arm_marker("x\n\n【本臂窄任务（G2｜id=nt-7）】\n正文")
        assert (g, nid) == ("G2", "nt-7")
        assert parse_arm_marker("无标记") == ("", "")

    def test_arm7_batch_scoping_separates_ablation_and_formal(self):
        """同一条 state 里并存两批：消融批（同题无标记）+ 正规批（3 组有标记）。

        全量聚合会**混批**（历史的同题批把正规批拖成 FAIL）⟹ 必须能按 `batch` 键**分批复核**
        —— 分批复核正是「消融 vs 正规」可在同一 state 上并排取数的落地形态。
        """
        control = [{"id": "c%d" % i, "batch": "cbatch", "full_task": "同题"}
                   for i in range(6)]
        formal = [dict(_mk(g, "nt-g%d-%d" % (g, j), "B"), batch="fbatch")
                  for g in (1, 2, 3) for j in (1, 2)]
        allrecs = control + formal
        c = pipeline_integrity(allrecs, expected_arms=6, batch="cbatch")
        f = pipeline_integrity(allrecs, expected_arms=6, batch="fbatch")
        assert c["arms"] == 6 and c["verdict"] == "FAIL" and c["circuit_break"] is True
        assert c["distinct_groups"] == 0
        assert f["arms"] == 6 and f["verdict"] == "OK" and f["circuit_break"] is False
        assert f["distinct_groups"] == 3 and f["narrow_hit_rate"] == 1.0


class TestArmDispersion:
    def test_arm4_dispersion_discriminates(self):
        """控制（组内≈组间）vs 处理（组间≫组内）—— 消融模式与正规模式在此判据必然分离。"""
        control = {"G1": [80, 81, 79], "G2": [80, 81, 79], "G3": [80, 81, 79]}
        treat = {"G1": [90, 91, 89], "G2": [70, 71, 69], "G3": [50, 51, 49]}
        c = arm_dispersion(control, perms=2000)
        t = arm_dispersion(treat, perms=2000)
        assert c["k"] == 3 and c["n"] == 9
        assert t["delta_phase"] > c["delta_phase"]
        assert t["between_sd"] > c["between_sd"]
        assert c["p"] > 0.5              # 组标签无解释力
        assert t["p"] < 0.05             # 组标签强解释力
        assert t["f"] > c["f"]


class TestAdaptiveWorkers:
    def test_arm5_adaptive_workers(self, monkeypatch):
        monkeypatch.setattr(hs, "visible_cpus", lambda: 8)
        monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
        assert adaptive_workers(100) == 7        # 8 - reserve(1)
        assert adaptive_workers(3) == 3          # 不超过待办数
        assert adaptive_workers(100, cap=4) == 4  # 显式上限
        monkeypatch.setattr(hs, "visible_cpus", lambda: 1)
        assert adaptive_workers(100) == 1        # 保底 1
        assert adaptive_workers(0) == 1

    def test_arm5b_memory_floor_clamps(self, monkeypatch):
        monkeypatch.setattr(hs, "free_avail_mb", lambda: 100)   # 空闲内存低于下限
        assert adaptive_workers(100, cpus=8, min_free_mb=512) == 1


class TestRedTeamHardening:
    """红队：模拟探测器自身隐患（设备可移植性 / 硬编码 / 标记伪造 / 误报 / 输入健壮）。"""

    def test_f1_affinity_aware_device_portability(self, monkeypatch):
        """换设备：容器/绑核下 affinity 可见 2 核而 `os.cpu_count()` 报 16 ⟹ 必须取 2，
        否则在受限设备上过度订阅（OOM / 排队）。"""
        monkeypatch.setattr(hs.os, "sched_getaffinity", lambda pid: {0, 1}, raising=False)
        monkeypatch.setattr(hs.os, "cpu_count", lambda: 16)
        monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
        assert hs.visible_cpus() == 2
        assert adaptive_workers(100) == 1          # 2 核 - reserve(1)

    def test_f2_env_single_source_no_hardcode(self, monkeypatch):
        """无硬编码：核数/上限/内存下限均 env 单源（换设备不靠改代码）。"""
        monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
        monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
        monkeypatch.setenv("GK_HUB_WORKERS_RESERVE", "4")
        assert adaptive_workers(100) == 12
        monkeypatch.setenv("GK_HUB_WORKERS_CAP", "5")
        assert adaptive_workers(100) == 5
        monkeypatch.setattr(hs, "free_avail_mb", lambda: 100)
        monkeypatch.setenv("GK_HUB_MIN_FREE_MB", "512")
        assert adaptive_workers(100) == 1

    def test_f3_ungrounded_marker_fails(self):
        """标记伪造：臂贴上**不在已登记清单**里的 id 冒充分组 ⟹ 必须 FAIL
        （只看组名字符串会被 `【…（G1｜id=FAKE）】` 骗过）。"""
        recs = [_mk(g, "FAKE-%d-%d" % (g, j), "X") for g in (1, 2, 3) for j in (1, 2)]
        nts = [{"id": "W2AP2-G%d-%s" % (g, s)} for g in (1, 2, 3) for s in ("A", "B")]
        r = pipeline_integrity(recs, expected_arms=6, narrow_tasks=nts)
        assert "ungrounded_narrow_id" in r["reasons"]
        assert r["verdict"] == "FAIL" and r["circuit_break"] is True

    def test_f3b_grounded_ok(self):
        nts = [{"id": "W2AP2-G%d-%s" % (g, s)} for g in (1, 2, 3) for s in ("A", "B")]
        recs = [_mk(g, "W2AP2-G%d-%s" % (g, s), "X") for g in (1, 2, 3) for s in ("A", "B")]
        r = pipeline_integrity(recs, expected_arms=6, narrow_tasks=nts)
        assert r["verdict"] == "OK" and "ungrounded_narrow_id" not in r["reasons"]

    def test_f4_batch_not_found_not_circuit(self):
        """批次号打错 ⟹ NO_DATA（不误触熔断），与真退化区分（防误报）。"""
        recs = [{"id": "a", "batch": "B1", "full_task": "x"}]
        r = pipeline_integrity(recs, batch="TYPO", expected_arms=1)
        assert r["batch_found"] is False
        assert r["verdict"] == "NO_DATA"
        assert r["circuit_break"] is False
        assert "batch_not_found" in r["reasons"]

    def test_f5_non_numeric_score_clean(self):
        """非数值分数 ⟹ 干净报错（不抛栈崩）。"""
        r = arm_dispersion({"G1": [1, "x"], "G2": [3, 4]})
        assert r["check"] == "arm_dispersion"
        assert r.get("error") == "non_numeric_score"
        assert r["verdict"] == "INVALID"


class TestCli:
    def test_arm6_cli_integrity_exit2_on_fail(self, tmp_path):
        st = tmp_path / "s.json"
        st.write_text(json.dumps({"gate_data": {"task_pipeline": [
            {"id": "a", "full_task": "同题"},
            {"id": "b", "full_task": "同题"}]}}, ensure_ascii=False), encoding="utf-8")
        r = subprocess.run([sys.executable, str(HERE / "gk_moa_integrity.py"),
                            "integrity", "--state", str(st)],
                           capture_output=True, text=True)
        assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
        out = json.loads(r.stdout)
        assert out["arms"] == 2 and out["circuit_break"] is True
