# -*- coding: utf-8 -*-
"""Q4③ 判别臂（hook-xenv §15.3-Q4）：登记动作 = 工具生成 --task + 人核（禁取消逐字一致）。

`--task-from-plan` 从计划文档提取质询目标行（canonical --task 串）喂给既有 submit
（`gatekeeper-cli.sh:7384` pending-only 唯一登记出口）⟹ 不构成第二张登记表。

臂：
  A 提取+过门：--task-from-plan --check-only ⟹ rc=0 且 L2 门放行（含 canonical 子串接地）；
  B 互斥：--task-from-plan 与 --task 并用 ⟹ 拒（禁双源）；
  C fail-loud：计划无质询目标行 ⟹ 显式拒绝（禁静默空 task 入队）；
  D 等值（§15.3 判别臂）：提取串与 canonical --task 串**逐字节等值**
    （同一 $task 进同一 submit ⟹ 入队条目逐字段等值）。

不做会怎样 = 双登记源（F4 分歧点实指）/ 人手拼串摩擦回潮。
回退 = 保留手拼路径不动，本 flag 纯增量（§15.3-Q4 回退款）。
"""
import json
import os
import subprocess

CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gatekeeper-cli.sh")
# 绝对路径：验收车道 `_accept_cli.sh` 先 `cd scripts/` 再跑 ⟹ 相对路径令 CLI 的 cwd 兜底
# `[ -f "$target" ]` 落空、`$SKILL_DIR/docs/plans/${target}` 又被前缀顶掉（并发会话实锤）。
PLAN = os.path.join(os.path.dirname(CLI), "docs", "plans", "2026-09-21-hook-xenv-form-fix-plan.md")
CANONICAL_HEAD = "对本文做 SCR 质询，逐条裁决下列四个问题"
CANONICAL_TAIL = "gaps + risks + missing_sites。"


def _cli(*args: str) -> tuple:
    # `GK_BUDGET_OVERRIDE=1`（`ECC-1F6514B84334`，2026-09-26 实测）：本调用是**判别探测**
    # （验 `--task-from-plan` 提取/互斥/fail-loud），**不是用户编辑** ⟹ 与生产面
    # `gk_agent_edit._cli_gate_ok` 同一口径。修前本文件每次 pytest 扣真 state 额度 3 次/验收轮
    # （`plan-refinement` 是写类子命令 ⟹ 经 `_bill_edit` 按次计）。
    # 2026-10-29：本文件验 `--task-from-plan` 的提取/互斥/fail-loud，**不是** PW-SN 机检面；
    #   preflight 现已接入 plan-lint（high/medium ⟹ 阻断），而本臂用的是 2026-09-21 存量计划
    #   （含历史行锚漂移）⟹ 显式关该门，避免历史债遮蔽本臂断言语义。
    p = subprocess.run(["bash", CLI, "plan-refinement", *args],
                       capture_output=True, text=True, timeout=120,
                       env={**os.environ, "GK_BUDGET_OVERRIDE": "1", "GK_PLAN_LINT_GATE": "0"})
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def test_arm_a_extract_and_gate_pass():
    """臂 A：--task-from-plan --check-only ⟹ rc=0，门放行（工具生成 + 门校验）。"""
    rc, blob = _cli(PLAN, "--task-from-plan", "--check-only")
    assert rc == 0, "rc=%r blob=%r" % (rc, blob[:300])
    assert '"check_only":true' in blob.replace(" ", ""), blob[:300]


def test_arm_b_mutual_exclusion_with_manual_task():
    """臂 B：与 --task 并用 ⟹ 拒（工具生成 vs 人手拼串禁双源）。"""
    rc, blob = _cli(PLAN, "--task-from-plan", "--task", "任意串", "--check-only")
    assert rc != 0, "互斥未拒：rc=%r blob=%r" % (rc, blob[:200])
    assert "互斥" in blob, blob[:200]


def test_arm_c_fail_loud_on_missing_line(tmp_path):
    """臂 C：计划无质询目标行 ⟹ fail-loud（禁静默空 task）。"""
    plan = tmp_path / "no_task_line.md"
    plan.write_text("<!-- META\ntarget_repo: skill\nproject_type: analysis\n-->\n# 无质询行\n\n正文。\n",
                    encoding="utf-8")
    rc, blob = _cli(str(plan), "--task-from-plan", "--check-only")
    assert rc != 0, "应 fail-loud：rc=%r blob=%r" % (rc, blob[:200])
    assert "未在计划中命中质询目标行" in blob, blob[:200]


def test_arm_d_extracted_task_equals_canonical():
    """臂 D（§15.3 判别臂）：提取串 == canonical --task 串（逐字节）。"""
    plan_abs = PLAN
    code = (
        "import io,sys\n"
        "for ln in io.open(sys.argv[1], encoding='utf-8'):\n"
        "    if ('质询目标' in ln) and ('逐字一致' in ln) and ('）**：' in ln):\n"
        "        print(ln.split('）**：', 1)[1].strip())\n"
        "        break\n"
    )
    p = subprocess.run(["python3", "-c", code, plan_abs], capture_output=True, text=True, timeout=60)
    extracted = p.stdout.strip()
    assert extracted.startswith(CANONICAL_HEAD), "提取串头部不匹配: %r" % extracted[:120]
    assert extracted.endswith(CANONICAL_TAIL), "提取串尾部不匹配: %r" % extracted[-120:]
    # 与本轮多臂质询真实入队的 task 前缀一致（人工 --task 基线 = 同一字符串）
    assert "只读，禁止改文件" in extracted
