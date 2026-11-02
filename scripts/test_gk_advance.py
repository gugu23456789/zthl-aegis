"""Test gk_advance.py — advance state machine (batch8 R-T6 Phase 7).

Covers the 20 scenarios contract (plan L2141): 6 stages × 2 states + ECO/ECC +
standing bypass + force + dry-run + monitor + entropy + tamper.
"""
import hashlib
import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

from gk_advance import _run  # noqa: E402


def _cs(gate_data):
    return hashlib.sha256(json.dumps(gate_data, sort_keys=True).encode()).hexdigest()[:16]


def _write_state(path, stage, gate_data=None, branch="feature/r1", worktree="/tmp/wt",
                 r_phase="R1", checksum=True, **extra):
    d = {"r_phase": r_phase, "stage": stage, "branch": branch, "worktree": worktree,
         "gate_data": gate_data or {}, "monitor_scores": {}, "history": []}
    d.update(extra)
    if checksum:
        d["_checksum"] = _cs(d["gate_data"])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    return str(path)


def _ok_env(**over):
    env = {"worktree_exists": True, "wt_registered": True, "uncommitted": "",
           "stash_count": 0, "ci_trigger": 1, "detect_changes": 0,
           "diff_files": "src/main.cc", "plan_backup_exists": True,
           "merge_check": True, "gn_up_to_date": True, "gn_stale": 0, "edit_used": 0}
    env.update(over)
    return env


# ─── STAGE_0 → STAGE_1 ───

def test_stage0_to_1_all_pass(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_0")
    r = _run(sf, "STAGE_1", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="unknown", skill_dir=str(tmp_path))
    assert r.get("allowed") is True
    assert r["transition"] == "STAGE_0→STAGE_1"
    assert r["stage"] == "STAGE_1"
    assert "edit_budget" in r


def test_stage0_to_1_worktree_missing(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_0")
    r = _run(sf, "STAGE_1", force=False, dry_run=False,
             env=_ok_env(worktree_exists=False, wt_registered=False),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("worktree not found" in v for v in r["violations"])


def test_stage0_to_1_branch_main(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_0", branch="main")
    r = _run(sf, "STAGE_1", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("branch is main" in v for v in r["violations"])


# ─── STAGE_1 → STAGE_2 ───

def test_stage1_to_2_all_pass(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_1")
    r = _run(sf, "STAGE_2", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True
    assert r["stage"] == "STAGE_2"


def test_stage1_to_2_uncommitted(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_1")
    r = _run(sf, "STAGE_2", force=False, dry_run=False,
             env=_ok_env(uncommitted="src/main.cc"), monitor_json=None, cc={},
             remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("uncommitted changes" in v for v in r["violations"])


def test_stage1_to_2_ci_trigger_missing(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_1")
    r = _run(sf, "STAGE_2", force=False, dry_run=False,
             env=_ok_env(ci_trigger=0), monitor_json=None, cc={}, remote="",
             skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("CI trigger not registered" in v for v in r["violations"])


# ─── STAGE_2 → STAGE_3 ───

def test_stage2_to_3_all_pass(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_2")
    r = _run(sf, "STAGE_3", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True


def test_stage2_to_3_allow_empty_blocked(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_2")
    r = _run(sf, "STAGE_3", force=False, dry_run=False,
             env=_ok_env(diff_files=""), monitor_json=None, cc={}, remote="",
             skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("--allow-empty bypass" in v for v in r["violations"])


# ─── STAGE_3 → STAGE_4 ───

def test_stage3_to_4_all_pass(tmp_path):
    gd = {"sprint_contract": {"scope": "x"}, "gitnexus": {"nodes": 100}}
    sf = _write_state(tmp_path / "s.json", "STAGE_3", gate_data=gd)
    r = _run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True


def test_stage3_to_4_sprint_contract_missing(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_3")
    r = _run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("sprint_contract missing" in v for v in r["violations"])


# ─── STAGE_4 → STAGE_5 ───

def test_stage4_to_5_all_pass(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_4")
    r = _run(sf, "STAGE_5", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True


def test_stage4_to_5_pr_not_merged(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_4")
    r = _run(sf, "STAGE_5", force=False, dry_run=False,
             env=_ok_env(merge_check=False), monitor_json=None, cc={}, remote="",
             skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("PR not merged" in v for v in r["violations"])


# ─── STAGE_5 → DONE ───

def test_stage5_to_done_all_pass(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_5")
    r = _run(sf, "DONE", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True
    assert r["stage"] == "DONE"


def test_stage5_to_done_plan_backup_missing(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_5")
    r = _run(sf, "DONE", force=False, dry_run=False,
             env=_ok_env(plan_backup_exists=False), monitor_json=None, cc={},
             remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert any("final plan backup missing" in v for v in r["violations"])


# ─── integrity / force / dry-run ───

def test_tampered_state_blocked(tmp_path):
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd,
                      checksum=False)
    with open(sf, "w", encoding="utf-8") as f:
        json.dump({"r_phase": "R1", "stage": "ECO-SCAN", "branch": "b",
                   "worktree": "/tmp/wt", "gate_data": gd,
                   "_checksum": "0000000000000000"}, f)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert r["reason"] == "STATE_FILE_TAMPERED"


def test_force_unknown_transition(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_4")
    r = _run(sf, "WEIRD_STAGE", force=True, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    # 2026-08-27 序列节点安全网：未知节点注册校验 = 结构完整性门禁，force 不可绕过
    # （原 bash 行为 L2853-2857 force WARN 放行 → 状态机可被任意字符串污染；
    #   现注册校验先于 _structural_gates 执行，与 ECO 顺序门禁同级别 fail-closed）
    assert r.get("ok") is False
    assert "UNKNOWN_NODE" in r.get("error", "")


def test_dry_run_no_write(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_0")
    before = open(sf, encoding="utf-8").read()
    r = _run(sf, "STAGE_1", force=False, dry_run=True, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True
    assert r.get("check_only") is True
    assert r["stage"] == "STAGE_0"  # not advanced
    after = open(sf, encoding="utf-8").read()
    assert before == after  # zero side effects (Paperclip pre-heartbeat contract)


# ─── monitor / entropy ───

def test_monitor_block_writes_bank_rejected(tmp_path):
    """M1（2026-10-31）：monitor 测量面不再阻断；`--local` 确定性失败由**额度银行**二次确认阻断。"""
    sf = _write_state(tmp_path / "s.json", "STAGE_3")
    r = _run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
             monitor_json={"score": 0.3, "verdict": "FAIL", "mode": "local"},
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert r.get("blocked_by_bank") is True
    assert r.get("reason") == "BANK_MONITOR_BLOCKED"
    d = json.load(open(sf, encoding="utf-8"))
    rej = d["gate_data"]["rejected_edits"]
    assert any(x["source"] == "bank" for x in rej)
    # 审计侧测量留痕（advisory）同时落账
    assert any(h.get("advisory") == "monitor_low_score"
               for h in d["gate_data"].get("monitor_history") or [])


def test_monitor_pass_proceeds(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_3",
                      gate_data={"sprint_contract": {"scope": "x"}})
    r = _run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
             monitor_json={"score": 0.9, "verdict": "PASS", "mode": "local"},
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True


def test_entropy_high_block(tmp_path):
    gd = {"rejected_edits": [{"score": 0.2, "source": "gate"}] * 10}
    sf = _write_state(tmp_path / "s.json", "STAGE_0", gate_data=gd)
    r = _run(sf, "STAGE_1", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    # standard branch: bash L2727 outputs {"ok":false,"error":"entropy_high",...}
    assert r.get("ok") is False
    assert r.get("error") == "entropy_high"
    d = json.load(open(sf, encoding="utf-8"))
    assert d["gate_data"].get("appeal_required") == "STAGE_1"


def test_entropy_null_fields_no_crash(tmp_path):
    """2026-08-23: 懒填充 state 的 gate_data 字段可能为 null（key 存在值 None）。
    `.get(k, [])` 不防 null → 熵计算/审计崩溃。`or []` 防御后必须返回 0.0 不崩。"""
    from gk_gate_entropy import compute_entropy_from_dict
    d = {"gate_data": {"rejected_edits": None, "human_calibration_log": None,
                       "subagent_history": None, "access_violations": None}}
    assert compute_entropy_from_dict(d, "STAGE_2") == 0.0
    assert compute_entropy_from_dict(d, "ECO-EDIT") == 0.0


# ─── ECO/ECC (non-standard) ───

def test_eco_scan_to_read_ok(tmp_path):
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="origin https://x", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    assert r["mode"] == "direct"
    # 2026-10-28（A4）：旧名 advance 归一后，hint.phase 输出规范名 ECO-RESEARCH
    assert r["hint"]["phase"] == "ECO-RESEARCH"
    assert r["current_remote"] == "origin https://x"
    assert "checklist" in r
    assert "gates" in r


def test_standing_scheduler_advances_cosine(tmp_path):
    """2026-08-31 优化器接线修复：standing 分支 advance 推进 cosine scheduler。

    standing 五节点常驻序列原不推进 scheduler.step（_edit_budget 仅 standard 调用）
    → cosine 退火失效。修复后：每次 ECO advance step+1，current_lr 按余弦退火递减，
    total_steps=6（五节点+回绕）时 step1→cos(pi/6)≈0.86 → lr=3。
    """
    gd = {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    d = json.load(open(sf, encoding="utf-8"))
    sched = d["gate_data"]["scheduler"]
    assert sched["current_step"] == 1
    # cosine(t=1/6): 1 + 0.5*(4-1)*(1+cos(pi/6)) = 1 + 1.5*1.866 = 3.799 → round 4? 
    # 实际 cos(pi/6)=0.866 → 1+0.5*3*(1.866)=1+2.799=3.799 → round=4
    assert sched["current_lr"] == 4  # step1 余弦起始段仍近 max


def test_standing_scheduler_dry_run_no_advance(tmp_path):
    """scheduler 推进在 dry_run 下零副作用（Paperclip 契约）。"""
    gd = {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=True, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    d = json.load(open(sf, encoding="utf-8"))
    assert d["gate_data"]["scheduler"]["current_step"] == 0  # 未推进


def test_standing_scheduler_wraps_around(tmp_path):
    """2026-09-01 落地"10 minor 剩余项：scheduler 无回绕"。

    standing 常驻序列循环推进：step 越过 total_steps 后回绕（% total），
    cosine 退火每周期重来。原 min(step,total) 饱和 → step≥total 恒 min_lr=1（永久失效）。
    回绕后 step=7 → t=(7%6)/6=1/6 → lr=4（与 step1 同相位）。
    """
    gd = {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 6, "current_lr": 1},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-DOC", gate_data=gd)
    r = _run(sf, "ECO-SCAN", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    d = json.load(open(sf, encoding="utf-8"))
    sched = d["gate_data"]["scheduler"]
    assert sched["current_step"] == 7
    # 回绕后 t=1/6 → cosine ≈ 4（非饱和 min_lr=1）
    assert sched["current_lr"] == 4


# ─── P2: standing 编辑预算 enforcement 注入 (2026-09-07 ECC-E75A3C2E8FE6, ㊴/㊵ 收敛缺省) ───
# standing 节点预算 = advance 进入节点时注入 edit_budget.remaining = 调度器 current_lr
#（SkillOpt cosine 退火，上限 max_lr=4；GATEKEEPER_EDIT_BUDGET 显式覆盖）。
# 消费：bash pre-tool-check edit 放行扣 1（flock），耗尽 BLOCK；advance 进新节点注入即重置。

def _standing_run(sf, current, to, dry_run=False, monitor=None):
    """standing 推进公共调用（monitor None → 无 PRM 阻断分支直接推进）。"""
    return _run(sf, to, force=False, dry_run=dry_run, env={}, monitor_json=monitor,
                cc={}, remote="", skill_dir=str(Path(sf).parent))


def test_standing_budget_injected_from_current_lr(tmp_path):
    """advance 进入 standing 节点注入 `edit_budget.remaining = min(current_lr × PER_LR, 硬顶)`。

    2026-09-23 预算解耦（用户裁定「梯度×2 + agent 池 additive」）：原状 = `current_lr`（一刀一单位），
    实测多文件批次必撞顶、只能人工 `state-patch` 抬 max（**绕过梯度**）。
    2026-09-23 再裁定「先提 PER_LR 额度」：PER_LR 2 → 4 ⟹ 本臂期望值 8 → 16（原 `8` 是旧口径
    硬编码；实测 `--affected --run` 自动选中本臂并报 `assert 16 == 8`，即为该裁定生效的佐证）。
    """
    gd = {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True
    d = json.load(open(sf, encoding="utf-8"))
    eb = d["gate_data"]["edit_budget"]
    # step0→1 cosine t=1/6 → current_lr=4 ⟹ 4 × 12 = 48 → 夹硬顶 24
    # （2026-10-23 owner 裁定：PER_LR 8→12、HARD_CAP 16→24）
    assert eb["remaining"] == 24
    assert eb["max"] == 24
    assert eb["used"] == 0


def test_advance_resets_exhausted_budget_on_node_change(tmp_path):
    """A（2026-10-23）：**standard 轨**耗尽后 advance 必须能进下一节点并重置额度。

    病象：`_edit_budget` 的归零键 = `r_phase`，而 `gk_advance` **只读** `r_phase`、从不推进它
    ⟹ 同一 `r_phase` 内进下一节点时 `remaining = max − edit_count` ≤ 0 ⟹ advance 直接返回
    「no more edits in this R-phase」⟹ 额度耗尽后 advance **救不回来**，只能手工 `state-patch`
    （绕过梯度、污染账本 —— 正是反棘轮要防的那条路）。
    ⚠ 范围（实测订正）：**standing 轨不受影响** —— `_run_nonstandard` 的注入面**无条件**重建
    `{used: 0, remaining: budget}`；本条只钉 standard 轨。
    修法：窗口键改为 `(r_phase, stage)` —— 进新节点 = 新窗口。
    """
    gd = {
        "edit_count": 40, "edit_count_phase": "R1",
        "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 0,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "STAGE_0", gate_data=gd)
    r = _run(sf, "STAGE_1", force=False, dry_run=False, env=_ok_env(),
             monitor_json=None, cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True or r.get("allowed") is True, (
        "耗尽节点上 advance 被拒 ⟹ 只能手工 state-patch 重置（绕过梯度）：%r"
        % (r.get("gates") or r,))
    d = json.load(open(sf, encoding="utf-8"))
    eb = d["gate_data"]["edit_budget"]
    assert eb["used"] == 0, "新节点未重置 used：%r" % (eb,)
    assert eb["remaining"] == eb["max"] and eb["remaining"] > 0, (
        "新节点未重置 remaining（旧窗口键未随节点推进）：%r" % (eb,))
    assert d["gate_data"].get("edit_count") == 0, (
        "窗口键命中后 edit_count 须归零：%r" % (d["gate_data"].get("edit_count"),))


def test_standing_budget_override_env(tmp_path, monkeypatch):
    """GATEKEEPER_EDIT_BUDGET 显式覆盖调度器 current_lr。"""
    monkeypatch.setenv("GATEKEEPER_EDIT_BUDGET", "2")
    gd = {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True
    d = json.load(open(sf, encoding="utf-8"))
    assert d["gate_data"]["edit_budget"]["remaining"] == 2


def test_standing_budget_dry_run_no_inject(tmp_path):
    """dry_run（--check）零副作用：不注入 edit_budget。"""
    gd = {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ", dry_run=True)
    assert r.get("ok") is True
    d = json.load(open(sf, encoding="utf-8"))
    assert "edit_budget" not in d["gate_data"]
    assert d["gate_data"]["scheduler"]["current_step"] == 0  # 未推进


def test_standard_edit_budget_semantics_unchanged(tmp_path):
    """standard 序列不触发 standing 注入路径——_edit_budget 语义不变（回归锚）。"""
    env = _ok_env()
    sf = _write_state(tmp_path / "s.json", "STAGE_0", gate_data={"project_type": "standard"})
    r = _run(sf, "STAGE_1", force=False, dry_run=False, env=env,
             monitor_json=None, cc={}, remote="unknown", skill_dir=str(tmp_path))
    assert r.get("allowed") is True
    # standard 成功路径返回 edit_budget（_edit_budget 快照），非 standing 注入块产物
    assert "edit_budget" in r
    assert r["stage"] == "STAGE_1"


def test_clear_appeal_block_uses_ar_not_to_stage(tmp_path):
    """L2 审查修正：_clear_appeal_block 按实际被驳回 gate（appeal_required=ar）清除，
    而非 to_stage——appeal 阻在 STAGE_3、force 推进到 STAGE_4 时，STAGE_3 标记必须清除。

    force 推进绕过 appeal DENIED → _clear_appeal_block 被调用：
    - gate_data.appeal_required 与 appeal_denied_gates 中的 STAGE_3 均清除
    - to_stage=STAGE_4 不受影响（本就该保留其他 gate 的 deny 标记）
    """
    from gk_advance import _clear_appeal_block
    d = {
        "gate_data": {
            "appeal_required": "STAGE_3",
            "appeal_entropy_at_block": 0.6,
        },
        "appeal_denied_gates": ["STAGE_3", "STAGE_1"],
    }
    _clear_appeal_block(d, "STAGE_4")
    assert "appeal_required" not in d["gate_data"]
    assert "appeal_entropy_at_block" not in d["gate_data"]
    assert d["appeal_denied_gates"] == ["STAGE_1"]  # STAGE_3 已清，STAGE_1 保留

    # 兼容旧路径：无 appeal_required 时按 to_stage 清除
    d2 = {"gate_data": {}, "appeal_denied_gates": ["STAGE_4", "STAGE_1"]}
    _clear_appeal_block(d2, "STAGE_4")
    assert d2["appeal_denied_gates"] == ["STAGE_1"]


def test_check_appeal_multi_source():
    """X1（2026-10-31）：`_check_appeal` 必须看见 `appeal_blocks` 的新阻断源。

    原实现只读单值 `gate_data.appeal_required` ⟹ 额度/审计第二源写入后本读点恒 clear（fail-open）。
    """
    from gk_advance import _check_appeal
    d = {"gate_data": {"appeal_blocks": {"credit": {"gate": "STAGE_3"}}}}
    assert _check_appeal(d) == "blocked:STAGE_3"
    # 旧 scalar 零回归
    assert _check_appeal({"gate_data": {"appeal_required": "STAGE_2"}}) == "blocked:STAGE_2"


def test_entropy_block_writes_multi_source():
    """熵门写点经单源 helper：`appeal_blocks.entropy` + 旧 scalar 镜像同时落盘。"""
    from gk_advance import _mark_appeal_block
    d = {}
    _mark_appeal_block(d, "STAGE_3", 0.75)
    gd = d["gate_data"]
    assert gd["appeal_blocks"]["entropy"]["gate"] == "STAGE_3"
    assert gd["appeal_blocks"]["entropy"]["entropy_rate"] == 0.75
    assert gd["appeal_required"] == "STAGE_3"
    assert gd["appeal_entropy_at_block"] == 0.75


def test_clear_appeal_block_clears_all_sources():
    """--force 人类终裁：多源并存时全部清除（不只 entropy 单值），deny 标记按各 gate 剔除。"""
    from gk_advance import _clear_appeal_block
    d = {
        "gate_data": {
            "appeal_required": "STAGE_3",
            "appeal_entropy_at_block": 0.6,
            "appeal_blocks": {
                "entropy": {"gate": "STAGE_3", "entropy_rate": 0.6},
                "credit": {"gate": "ECO-EDIT", "score": 3},
            },
        },
        "appeal_denied_gates": ["STAGE_3", "ECO-EDIT", "STAGE_1"],
    }
    _clear_appeal_block(d, "STAGE_4")
    assert "appeal_blocks" not in d["gate_data"]
    assert "appeal_required" not in d["gate_data"]
    assert "appeal_entropy_at_block" not in d["gate_data"]
    assert d["appeal_denied_gates"] == ["STAGE_1"]


# ─── Phase 7a: standing PRM Monitor 主动阻断 (2026-08-23) ───
# bash cmd_advance 已收集 monitor_json（熵驱动模式切换）；Python _run_nonstandard
# 以 critical_only=False 调用 _monitor_eval — standing 任意转换触发。

def test_standing_monitor_block(tmp_path):
    """standing 分支：M1 后 `--local` 确定性失败由**额度银行**二次确认阻断（measurement 只留痕）。"""
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={},
             monitor_json={"score": 0.3, "verdict": "FAIL", "mode": "local"},
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is False
    assert r.get("blocked_by_bank") is True
    assert r["reason"] == "BANK_MONITOR_BLOCKED"
    d = json.load(open(sf, encoding="utf-8"))
    rej = d["gate_data"]["rejected_edits"]
    assert any(x["source"] == "bank" for x in rej)
    assert any(h.get("advisory") == "monitor_low_score"
               for h in d["gate_data"].get("monitor_history") or [])


def test_standing_monitor_pass_proceeds(tmp_path):
    """standing monitor PASS 不阻断，正常推进。"""
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={},
             monitor_json={"score": 0.9, "verdict": "PASS", "mode": "local"},
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True


def test_standing_monitor_force_bypass(tmp_path):
    """standing monitor 阻断 --force 绕过（与 standard 分支行为一致）。"""
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=True, dry_run=False, env={},
             monitor_json={"score": 0.3, "verdict": "FAIL", "mode": "local"},
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True  # force bypasses monitor


def test_standing_monitor_dry_run_no_write(tmp_path):
    """standing monitor 阻断在 dry_run 下零副作用（Paperclip pre-heartbeat 契约）。"""
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    before = open(sf, encoding="utf-8").read()
    _run(sf, "ECO-READ", force=False, dry_run=True, env={},
         monitor_json={"score": 0.3, "verdict": "FAIL", "mode": "local"},
         cc={}, remote="", skill_dir=str(tmp_path))
    after = open(sf, encoding="utf-8").read()
    assert before == after  # zero side effects


def test_standing_eco_read_to_edit_no_plan_refinement_required(tmp_path):
    """standing 常驻序列豁免计划质询门禁（2026-08-24）：
    ECO-READ→ECO-EDIT 不要求 plan-refinement 点检（standing 非计划质询专用）。
    副作用声明: 无 adjudicate 记录时 ECO-EDIT→ECO-AUDIT 仍会被 adjudicate 门禁拦截。
    """
    gd = {"project_type": "standing", "subagent_history": [{"task": "read only"}]}
    sf = _write_state(tmp_path / "s.json", "ECO-READ", gate_data=gd)
    r = _run(sf, "ECO-EDIT", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    assert r["hint"]["phase"] == "ECO-EDIT"


def test_nonstandard_eco_read_to_edit_requires_plan_refinement(tmp_path):
    """非 standing（paper-maintenance 计划质询）仍强制 plan-refinement 点检。"""
    gd = {"project_type": "paper-maintenance", "subagent_history": [{"task": "read only"}]}
    sf = _write_state(tmp_path / "s.json", "ECO-READ", gate_data=gd)
    r = _run(sf, "ECO-EDIT", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is False
    assert "plan-refinement" in r.get("error", "")


def test_eco_edit_to_audit_requires_adjudicate(tmp_path):
    gd = {"project_type": "standing",
          "subagent_history": [{"task": "plan-refinement F1-F7 review"}]}
    sf = _write_state(tmp_path / "s.json", "ECO-EDIT", gate_data=gd)
    r = _run(sf, "ECO-AUDIT", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is False
    assert "adjudicate" in r.get("error", "")


def test_eco_sequential_violation(tmp_path):
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-AUDIT", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is False
    assert "ECO sequential violation" in r.get("error", "")


def test_eco_doc_to_ecc_boundary_ok(tmp_path):
    gd = {"project_type": "standing",
          "eco_completions": {"ECO-DOC": {"completed_at": "2026-08-01T00:00:00"}}}
    sf = _write_state(tmp_path / "s.json", "ECO-DOC", gate_data=gd)
    r = _run(sf, "ECC-PLAN", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    assert r["hint"]["phase"] == "ECC-PLAN"


def test_ecc_to_ecc_blocked_by_boundary(tmp_path):
    """ECC→ECC is blocked by I6 boundary gate (bash L2285-2291 semantic —
    ECC-* requires prior ECO cycle; ECC internal steps not advance-routable)."""
    gd = {"project_type": "standing",
          "eco_completions": {"ECO-EDIT": {"completed_at": "2026-08-01T00:00:00"}}}
    sf = _write_state(tmp_path / "s.json", "ECC-PLAN", gate_data=gd)
    r = _run(sf, "ECC-EXEC", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is False
    assert "requires prior ECO cycle" in r.get("error", "")


def test_standing_direct_advance(tmp_path):
    gd = {"project_type": "analysis"}
    sf = _write_state(tmp_path / "s.json", "AUDIT-STATE", gate_data=gd)
    r = _run(sf, "AUDIT-MEMORY", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True
    assert r["hint"]["phase"] == "AUDIT-MEMORY"


def test_audit_hint_carries_owner(tmp_path):
    """D7-B（2026-10-27）：AUDIT-* hint 透传归属域；派发行为不变。"""
    gd = {"project_type": "analysis"}
    sf = _write_state(tmp_path / "s.json", "AUDIT-STATE", gate_data=gd)
    r = _run(sf, "AUDIT-MEMORY", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True, r
    assert r["hint"]["owner"] == "skill.2026-10-04-audit-bureau-plan", r


# ─── P0 ledger: standing 审查节点出口完整性 (2026-09-07 b1g, ㊴/㊵ 收敛缺省, 合并 C5) ───
# ECO-AUDIT→ECO-DOC = standing 交叉审查出口——round-log（≥2 轮审查+轮间红队）+ audit --all 记录
# 谓词单源 = gk_node_guard.review_exit_gate；advance 出口单咽喉消费：
#   GK_GUARD_STRICT=1 → 硬阻断（出站被拒，state 不动）；默认 advisory（ok 放行 + ledger_advisory 附核对）。

def _ledger_ready_gd():
    """round-log 齐 + audit --all 记录落盘（standing；E2 起 = 有生产者两域 all-of）。"""
    return {
        "project_type": "standing",
        "subagent_history": [
            {"task": "crossrev: L1-L10 交叉审查 轮 1"},
            {"task": "redteam: 轮间红队挖洞"},
            {"task": "crossrev: L1-L10 交叉审查 轮 2"},
        ],
        "audit_state_result": {"state_checks": [], "audit_summary": {}},
        "audit_docs_result": {"docs_checks": [], "summary": {}},
    }


def test_standing_audit_to_doc_ledger_ready_passes(tmp_path):
    """ledger 齐（round-log ready + audit --all 记录）→ ECO-DOC 放行，无 ledger_advisory。"""
    sf = _write_state(tmp_path / "s.json", "ECO-AUDIT", gate_data=_ledger_ready_gd())
    r = _standing_run(sf, "ECO-AUDIT", "ECO-DOC")
    assert r.get("ok") is True
    assert "ledger_advisory" not in r
    d = json.load(open(sf, encoding="utf-8"))
    assert d["stage"] == "ECO-DOC"
    assert "ECO-VERIFY" in d["gate_data"]["eco_completions"]  # A4：写入归一后的规范名


def test_standing_audit_to_doc_ledger_pending_advisory(tmp_path):
    """ledger 缺（跳过审查/无 audit 记录）→ 默认 advisory：仍放行但附 ledger_advisory 供核对。"""
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-AUDIT", gate_data=gd)
    r = _standing_run(sf, "ECO-AUDIT", "ECO-DOC")
    assert r.get("ok") is True
    la = r.get("ledger_advisory")
    assert la is not None and la["status"] == "pending"
    assert any("audit --all 记录缺失" in m for m in la["missing"])


def test_standing_audit_to_doc_ledger_strict_blocks(tmp_path, monkeypatch):
    """GK_GUARD_STRICT=1 + ledger 缺 → 硬阻断（出站被拒，state 不推进）。"""
    monkeypatch.setenv("GK_GUARD_STRICT", "1")
    gd = {"project_type": "standing"}
    sf = _write_state(tmp_path / "s.json", "ECO-AUDIT", gate_data=gd)
    r = _standing_run(sf, "ECO-AUDIT", "ECO-DOC")
    assert r.get("ok") is False
    assert "P0" in r.get("error", "")
    assert r["ledger"]["status"] == "pending"
    d = json.load(open(sf, encoding="utf-8"))
    assert d["stage"] == "ECO-AUDIT"  # 出口被拒：未写入 ECO-DOC
    assert "ECO-AUDIT" not in d["gate_data"].get("eco_completions", {})


def test_standing_p0_gate_fires_on_canonical_stage_names(tmp_path, monkeypatch):
    """A4 站名压缩回归臂（红先）：规范名 ECO-VERIFY→ECO-DOC 仍须触发 P0 ledger 门。

    缺口：P0 判据原写死 `current == "ECO-AUDIT"`，站名压缩后规范路径（stage=ECO-VERIFY）
    恒不命中 ⟹ 门禁静默失效。本臂在修复前必红（ok=True，无 P0）。
    """
    monkeypatch.setenv("GK_GUARD_STRICT", "1")
    sf = _write_state(tmp_path / "s.json", "ECO-VERIFY",
                      gate_data={"project_type": "standing"})
    r = _standing_run(sf, "ECO-VERIFY", "ECO-DOC")
    assert r.get("ok") is False, r
    assert "P0" in r.get("error", ""), r


# ─── _eco_prereq_heuristic ECO-AUDIT 判据单源（批③ ② 接线统一）───
# 写入侧 = 有生产者两域 *_result（audit_state_result + audit_docs_result）；判据侧与
# node_guard audit_all_recorded 同一事实源（2026-10-28 E2 收紧为 all-of，legacy 别名已废）。
# l9_gatechain 与 ECO-AUDIT advisory 均经本函数单点委托。

def test_eco_audit_prereq_five_domain_recorded_ok():
    """有生产者的两域 *_result 同时落盘 → ECO-AUDIT 前置不报 missing（E2 all-of 收紧）。"""
    from gk_advance import _eco_prereq_heuristic
    h = _eco_prereq_heuristic({"gate_data": {"audit_state_result": {"state_checks": []},
                                             "audit_docs_result": {"docs_checks": []}}}, "ECO-AUDIT")
    assert h["missing"] == []


def test_eco_audit_prereq_single_domain_missing():
    """E2 负臂（红先）：只落一域 ⟹ 仍报 missing（原 `any` 语义的 fail-open 已关）。"""
    from gk_advance import _eco_prereq_heuristic
    h = _eco_prereq_heuristic({"gate_data": {"audit_state_result": {"state_checks": []}}}, "ECO-AUDIT")
    assert any(x["item"] == "audit_all" for x in h["missing"])


def test_eco_audit_prereq_legacy_audit_result_not_accepted():
    """E2（2026-10-28）：`audit_result` 零生产者且三写面已封 ⟹ 不再作采信面。"""
    from gk_advance import _eco_prereq_heuristic
    h = _eco_prereq_heuristic({"gate_data": {"audit_result": {"ok": True}}}, "ECO-AUDIT")
    assert any(x["item"] == "audit_all" for x in h["missing"])


def test_eco_audit_prereq_no_evidence_missing():
    """无任何 audit 证据 → missing 含 audit_all（判据空集一致性）。"""
    from gk_advance import _eco_prereq_heuristic
    h = _eco_prereq_heuristic({"gate_data": {}}, "ECO-AUDIT")
    assert any(x["item"] == "audit_all" for x in h["missing"])
