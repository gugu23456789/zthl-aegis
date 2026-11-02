"""`discover` 跨会话基础设施键保全（finding `ECC-A135BE8837AF`）单测。

三层判据：
  ① **纯函数语义**（`gk_discover_carry.carry_over`）—— 保全 `gate_data.edit_budget` /
     `gate_data.ecc_findings`（list）/ 顶层 `worktrees_extra`；**不**保全本轮燃烧项；
     缺键/空值不造空壳；畸形输入 fail-soft。
  ② **事故回归臂** —— 用 2026-10-01 真实被砸的那份 state 形态做夹具，钉死「会话盒原值存活」。
  ③ **接线不变量**（源码级）—— `cmd_discover` 里「重建前快照 → 重建 → 回填」的**次序**不可倒，
     且回填必经**单一出纳** `_state_write`（禁第二写者）；重建本身仍须清空 `gate_data`（既有语义不破）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gk_discover_carry import (CARRY_GATE_KEYS, CARRY_GATE_LIST_KEYS,  # noqa: E402
                               CARRY_GATE_SCALAR_KEYS, CARRY_TOP_KEYS, carry_over)

_OTHER_SID = "6a3e34696caeb2204fa8bc88"
_WT = "<home>/.trae/worktrees/spz-gatekeeper-r-sequence/agent/session/b3f2421a"


def _rebuilt_state() -> dict:
    """`cmd_discover` 重建产物形态（逐字对齐 heredoc 的键集）。"""
    return {"r_phase": "ECO-SCAN", "stage": "ECO-EDIT", "branch": "master",
            "worktree": "<home>/.trae/skills/spz-gatekeeper-r-sequence",
            "main_repo": "<home>/Downloads/<workspace>/spz_gatekeeper_project",
            "gate_data": {}, "monitor_scores": {}, "history": []}


class TestCarryOverSemantics:
    def test_preserves_edit_budget_and_write_surface(self):
        old = {"gate_data": {"edit_budget": {
                    "max": -1, "used": 0, "remaining": -1,
                    "sessions": {_OTHER_SID: {"max": 32, "used": 58, "remaining": 2}}}},
               "worktrees_extra": [_WT]}
        new = carry_over(old, _rebuilt_state())
        assert new["gate_data"]["edit_budget"]["sessions"][_OTHER_SID] == {
            "max": 32, "used": 58, "remaining": 2}
        assert new["gate_data"]["edit_budget"]["max"] == -1
        assert new["worktrees_extra"] == [_WT]

    def test_preserves_ecc_findings_ledger(self):
        """`ecc_findings`（list）跨轮存活（`ECC-01E84B0E87F5`）：discover 不得抹掉 finding 台账。"""
        finds = [{"id": "ECC-OLD", "status": "open"}]
        new = carry_over({"gate_data": {"ecc_findings": finds, "rejected_edits": [{"x": 1}]}},
                         _rebuilt_state())
        assert new["gate_data"]["ecc_findings"] == finds
        assert "rejected_edits" not in new["gate_data"]

    @pytest.mark.parametrize("key", ["rejected_edits", "entropy_history",
                                     "audit_state_result", "narrow_tasks"])
    def test_round_data_is_still_wiped(self, key):
        old = {"gate_data": {key: [{"x": 1}], "edit_budget": {"sessions": {_OTHER_SID: {"remaining": 2}}}},
               "worktrees_extra": [_WT]}
        new = carry_over(old, _rebuilt_state())
        assert key not in new["gate_data"], f"本轮燃烧项 {key} 必须仍被清空（既有语义不破）"
        assert new["gate_data"]["edit_budget"]["sessions"][_OTHER_SID]["remaining"] == 2

    @pytest.mark.parametrize("key,val", [
        ("subagent_history", [{"subagent_id": "sub-a"}]),
        ("task_pipeline", [{"id": "pr-1", "status": "pending"}]),
        ("t_star", {"frozen_at": "2026-10-07T00:26:32Z"}),
        ("satellite_index", {"skill.x": {"history": {"kind": "history", "records": 1}}}),
        ("jti_store", {"jti-1": 1791360000}),
        ("_sealed_agent_score", {"score": 57.1}),
        ("hook_block_log", [{"reason": "ember 回判消费的意图记忆切片"}]),
        # ECC-4815C3350DB5（2026-10-07 质询 6 臂跨臂共识）：`subagent_last` 被 docstring
        #   自列为本轮丢失项，却**不在**任何 CARRY 元组（判据零覆盖的第三态）。
        ("subagent_last", {"subagent_id": "sub-x", "task": "plan-refinement", "batch_id": "d0e1040721d3"}),
    ])
    def test_cross_round_ledgers_survive(self, key, val):
        """跨轮台账/基础设施须存活（`ECC-A4223D19AA16`，2026-10-07 实测）。

        原判据把 `subagent_history` / `task_pipeline` 等归「本轮燃烧项」⟹ 6 臂质询派发后任一
        `discover` 即抹掉**窗口内**臂记录且**未入卫星片** = 数据丢失（`moa-aggregate` references=0）。
        ⟹ 判据修订：**窗口内未入片不得丢**；出窗仍由归档负责（卫星片语义不变）。
        """
        new = carry_over({"gate_data": {key: val}}, _rebuilt_state())
        assert new["gate_data"].get(key) == val, f"跨轮键 {key} 未保全"

    def test_edit_count_scalar_survives(self):
        """标量键 `edit_count`：非零存活；0/缺键不造空壳（保 `未配置` 语义）。"""
        new = carry_over({"gate_data": {"edit_count": 7}}, _rebuilt_state())
        assert new["gate_data"].get("edit_count") == 7
        zero = carry_over({"gate_data": {"edit_count": 0}}, _rebuilt_state())
        assert zero["gate_data"].get("edit_count") is None

    @pytest.mark.parametrize("old", [
        {},
        {"gate_data": {}},
        {"gate_data": {"edit_budget": {}}},              # 空 dict ⟹ 不造空壳
        {"worktrees_extra": []},                          # 空 list ⟹ 不造空壳
        {"gate_data": {"ecc_findings": []}},              # 空 list ⟹ 不造空壳
        {"gate_data": {"edit_budget": "broken"}},         # 类型不符
        {"worktrees_extra": "/mnt/c/x"},                  # 类型不符
    ])
    def test_missing_or_empty_leaves_state_untouched(self, old):
        new = carry_over(old, _rebuilt_state())
        assert "edit_budget" not in new["gate_data"]
        assert "worktrees_extra" not in new
        assert "ecc_findings" not in new["gate_data"]

    @pytest.mark.parametrize("old", [None, "x", 7, [], {"gate_data": None}, {"gate_data": "x"}])
    def test_malformed_input_is_fail_soft(self, old):
        new = _rebuilt_state()
        assert carry_over(old, new) is new              # 不抛、原样返回
        assert new["gate_data"] == {}

    def test_history_is_not_carried_by_this_function(self):
        """history 由 heredoc 自身承接（既有实现），本函数**不**越权搬它（防双源）。"""
        new = carry_over({"history": [{"r_phase": "X"}]}, _rebuilt_state())
        assert new["history"] == []

    def test_whitelist_is_declared_single_source(self):
        # 单一登记点（三处同步）：`gk_discover_carry.py` 常量 + 其 docstring 判据 + 本断言。
        # 2026-10-07 扩充（ECC-A4223D19AA16）：原仅 3 键 ⟹ 质询臂记录 / 队列 / 收敛锚 /
        #   卫星索引 / jti / 封印分 / 计数在任一 discover 后被抹且**未入片** = 数据丢失。
        assert CARRY_GATE_KEYS == ("edit_budget", "t_star", "satellite_index",
                                   "jti_store", "_sealed_agent_score", "subagent_last")
        assert CARRY_GATE_LIST_KEYS == ("ecc_findings", "task_pipeline", "subagent_history",
                                        "hook_block_log")
        assert CARRY_GATE_SCALAR_KEYS == ("edit_count",)
        assert CARRY_TOP_KEYS == ("worktrees_extra",)


class TestIncidentRegression:
    """2026-10-01 真实事故夹具：我的 plain discover 把并发会话额度盒抹成 0/0/0。"""

    OLD = {
        "r_phase": "ECO-SCAN", "stage": "ECO-EDIT", "branch": "master",
        "gate_data": {
            "edit_budget": {"max": -1, "used": 0, "remaining": -1,
                            "sessions": {_OTHER_SID: {"max": 32, "used": 58, "remaining": 2},
                                         "6ab53c5749c94a80f5f79109": {"max": 12, "used": 3, "remaining": 9}}},
            "scheduler": {"mode": "cosine"},
            "project_type": "standing",
            "rejected_edits": [{"violations": ["x"]}],
            "ecc_findings": [{"id": "ECC-OLD"}],
        },
        "worktrees_extra": [_WT],
        "history": [{"r_phase": "ECO-SCAN"}],
        "target_repo": "skill",
    }

    def test_both_session_boxes_survive_rebuild(self):
        new = carry_over(self.OLD, _rebuilt_state())
        sessions = new["gate_data"]["edit_budget"]["sessions"]
        assert set(sessions) == {_OTHER_SID, "6ab53c5749c94a80f5f79109"}
        assert sessions[_OTHER_SID]["remaining"] == 2, "并发会话额度不得被重置"
        assert sessions["6ab53c5749c94a80f5f79109"]["remaining"] == 9
        assert new["worktrees_extra"] == [_WT], "技能仓写面允许集不得被清"
        # 本轮数据照旧清空；finding 台账（跨轮）须存活；其余顶层键照旧不承接（target_repo 由 GK_TR 块恢复）
        assert "rejected_edits" not in new["gate_data"]
        assert new["gate_data"]["ecc_findings"] == [{"id": "ECC-OLD"}], "finding 台账不得被 discover 抹"
        assert "target_repo" not in new


class TestDiscoverWiring:
    _CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

    @classmethod
    def _discover_body(cls) -> str:
        """按**函数后置 banner** 取 `cmd_discover` 全文（`\\n}` 边界不可靠：嵌套 bash/python 里
        存在行首 `}`，实测会截断到函数中段 ⟹ 三臂假红）。banner 紧随 cmd_discover 之后且唯一。"""
        txt = cls._CLI.read_text(encoding="utf-8")
        marker = "# ── v4.18 T73: gatekeeper 裸跑检测 ──"
        assert "cmd_discover() {" in txt and marker in txt, "锚缺失（实现被重排，请更新本锚）"
        head = txt.split("cmd_discover() {", 1)[1]
        return head.split(marker, 1)[0]

    def test_snapshot_precedes_rebuild_and_carry_follows(self):
        body = self._discover_body()
        snap = body.find('cp -f "$STATE_FILE" "$_carry_f"')
        # 锚须**重建 heredoc 独有**：`"gate_data":{},"monitor_scores":{}` 在 idle 分支**也**出现
        # （实测：用它会命中更早的 idle 行 ⟹ 次序断言假红），故并上 `main_repo` 字段定位真重建点。
        # 2026-11-02 重锚：discover 重建 heredoc 已改为 `g("GK_ST_MAIN_REPO")` 形态
        #   （原 `"main_repo":"$MAIN_REPO_WIN","gate_data":{}` 在 HEAD 已不存在）。
        rebuild = body.find('"main_repo": g("GK_ST_MAIN_REPO"), "gate_data": {},')
        carry = body.find("from gk_discover_carry import carry_over as _carry")
        assert snap != -1 and rebuild != -1 and carry != -1, "三要素缺一 ⟹ 保全链断裂"
        assert snap < rebuild < carry, "次序必须是「快照 → 重建 → 回填」（倒了即抹掉后又去读它）"

    def test_snapshot_precedes_phase_archive_wipe(self):
        """phase-changed 路径在重建前另有 `gate_data` 归档清空 ——
        快照必须**先于**它取，否则 carry 拿到的是抹空态（`ECC-01E84B0E87F5` 的 phase-changed 面）。

        2026-10-28 重锚（B8 抽取）：清空动作已从 CLI 内联下沉到
        `gk_discover_archive.py archive` ⟹ CLI 侧锚改为**该调用点**，并追加一条
        「模块里确实还在清 `gate_data`」的守卫（防下沉后只剩一个空调用）。
        """
        body = self._discover_body()
        snap = body.find('cp -f "$STATE_FILE" "$_carry_f"')
        wipe = body.find('gk_discover_archive.py" archive')
        assert snap != -1 and wipe != -1, "锚缺失（快照 / phase 归档被重排，请更新本锚）"
        assert snap < wipe, "快照必须先于 phase 归档清空 gate_data（否则 carry 无源可回填）"
        src = (Path(__file__).resolve().parent / "gk_discover_archive.py").read_text(
            encoding="utf-8")
        assert 's["gate_data"] = {}' in src, (
            "gk_discover_archive 已不再清空 gate_data ⟹ 本臂的「wipe」前提失效（判据须重写）")

    def test_carry_goes_through_single_writer(self):
        body = self._discover_body()
        carry = body.find("from gk_discover_carry import carry_over as _carry")
        assert body.rfind('_state_write "', 0, carry) > carry - 600, (
            "回填必须经单一出纳 _state_write（禁在 bash 内自建第二个 state 写者）")
        assert 'json.dump(d,open' not in body[carry:carry + 600]

    def test_rebuild_still_wipes_gate_data(self):
        body = self._discover_body()
        assert '"gate_data":{}' in body and '"monitor_scores":{}' in body, (
            "重建仍须清空 gate_data（本轮燃烧项语义不可被保全逻辑破坏）")

    def test_snapshot_file_is_cleaned_up(self):
        body = self._discover_body()
        assert 'rm -f "$_carry_f"' in body, "快照临时件必须回收（否则 /tmp/状态目录 只进不出）"

    def test_snapshot_cp_failure_is_loud(self):
        """ECC-A52B0EAB6C6D（2026-10-07 质询 6 臂）：carry 快照 `cp` 失败**禁静默**回退空对象
        —— 原式 `cp … 2>/dev/null || echo '{}' >` 可让保全在生产路径整体 no-op 且**零留痕**
        （现存三臂全在纯函数层，结构上测不到该路径）。修后须留痕（WARN + GK_DBG_LOG）。"""
        body = self._discover_body()
        assert 'cp -f "$STATE_FILE" "$_carry_f" 2>/dev/null || echo' not in body, \
            "快照 cp 失败仍静默回退（无留痕）⟹ 保全可整体 no-op 而不可观测"
        assert "discover-carry" in body, "cp 失败须留痕（WARN[discover-carry]）"

    def test_idle_branch_applies_carry(self):
        """ECC-7EC88E41702A（2026-10-07 质询 6 臂）：`!detected` 的 IDLE 早退原用裸 `cat >` 写
        state 并 `return 0`（零 carry / 零 checksum / 非原子）⟹ 绕过单一出纳、抹掉跨轮键。
        修后 IDLE 分支须同样经 carry 回填（快照 → 写 → `_state_write` + `carry_over`）。"""
        body = self._discover_body()
        idle = body.find('"stage":"IDLE"')
        assert idle != -1, "IDLE 锚缺失（实现被重排，请更新本锚）"
        tail = body[idle:]
        assert "carry_over" in tail, "IDLE 早退分支未接 carry_over（跨轮键仍会被抹）"
        assert "_idle_cf" in tail, "IDLE 分支缺快照变量（无源可回填）"
