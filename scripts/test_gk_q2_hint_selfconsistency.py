# -*- coding: utf-8 -*-
"""Q2 自洽臂（hook-xenv §15.3-Q2）：自动注入的 move-to-trash 命令必须本身过 hook。

判别臂（§15.3-Q2 原文）：对 hint 真生成的注入串（`mkdir -p "<trash>" && mv -- "<tgt>"
"<trash>/<base>.<ts>"`，构造式 = `pre_tool_hook.py` `_looks_path` 段 `_repl`）以 RunCommand
载荷喂回 `pre_tool_hook.main()`（subprocess + JSON stdin，宿主真实入口）：
  预期绿 = rc=0 且 proceed:true（注入串不是诱导犯规）；
  预期红 = rc=2 BLOCK（hint 变诱导犯规 ⟹ 降摩擦机制反向加摩擦）。

不做会怎样 = 使用者按 hint 粘贴即被自家安全网拦住，摩擦反升（§12.1 Q2 的病根）。
回退 = 本臂红 ⟹ 回退文案注入（保留泛 hint，§15.3-Q2 回退款）。

三臂：
  A 阴性对照：`rm -rf <夹具>` → 必 BLOCK（证 harness 有判别力，防假绿）；
  B hint 提取：从 A 的 BLOCK 文案里剥出注入串（`Fix（**自动替换 ...）:` 之后首段）；
  C 自洽：B 的注入串原样作为新载荷 → 断言 ALLOW。

纪律：hook 只**判**不执行载荷 ⟹ 夹具不会被真搬走、回收区零污染。
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "pre_tool_hook.py")
REPO = os.path.dirname(HERE)  # 技能仓根（governed scope 内，R0.x 生效面）


def _run_hook(command: str) -> tuple:
    """以 RunCommand 载荷喂真实 hook 入口，返回 (rc, blob)。

    blob = stdout + stderr 合并 —— BLOCK 文案走 **stderr**（§8⑦ 同款：stdout 仅部分
    路径吐 JSON；`{'rc':2,'raw':''}` 首跑实证）⟹ 两路都收，断言才看得见 reason。
    """
    payload = json.dumps({
        "tool_name": "RunCommand",
        "tool_input": {"command": command},
        "cwd": REPO,
    })
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([sys.executable, HOOK], input=payload, capture_output=True,
                       text=True, env=env, cwd=REPO, timeout=60)
    return p.returncode, (p.stdout or "") + "\n" + (p.stderr or "")


def _verdict(rc: int, out: str) -> dict:
    try:
        return json.loads(out)
    except Exception:
        return {"rc": rc, "raw": out[:200]}


def test_arm_a_negative_control_rm_rf_blocked():
    """臂 A（阴性对照）：rm -rf 字面路径夹具 ⟹ 必 BLOCK（rc=2），否则 harness 假绿。"""
    fixture = tempfile.mkdtemp(prefix="gk_q2_fixture_")
    os.makedirs(os.path.join(fixture, "sub"), exist_ok=True)  # 非空目录（真 rm -rf 目标形态）
    rc, blob = _run_hook("rm -rf %s" % fixture)
    assert rc == 2, "阴性对照未 BLOCK：rc=%r blob=%r" % (rc, blob[:200])
    assert "rm -rf" in blob, "BLOCK 文案缺失（判别力存疑）: %r" % blob[:200]


def test_arm_b_hint_contains_executable_replacement():
    """臂 B：BLOCK 文案里必须能剥出 `mkdir -p ... && mv -- ...` 注入串（可直接执行形态）。"""
    fixture = tempfile.mkdtemp(prefix="gk_q2_fixture_")
    rc, blob = _run_hook("rm -rf %s" % fixture)
    assert rc == 2
    assert "mkdir -p" in blob and "mv --" in blob, "hint 未含注入串: %r" % blob[:300]


def test_arm_c_injected_command_passes_hook():
    """臂 C（自洽主判据）：注入串原样作为新载荷 ⟹ 必须 ALLOW（rc=0）。"""
    fixture = tempfile.mkdtemp(prefix="gk_q2_fixture_")
    os.makedirs(os.path.join(fixture, "sub"), exist_ok=True)
    rc, blob = _run_hook("rm -rf %s" % fixture)
    assert rc == 2, "前置失败：rm -rf 未被拦（无法取得 hint）"
    start = blob.find("mkdir -p")
    assert start >= 0, "未找到注入串起点: %r" % blob[:300]
    seg = blob[start:]
    # 收口：注入串到 `_INERT` 尾注 / 换行 / `（命中文本` 之前为止（拒收 hint 尾注混入）
    for stop in ("惰性字面量", "GK_INERT_CMD", "（命中文本", "\n"):
        i = seg.find(stop, 10)
        if i > 0:
            seg = seg[:i]
            break
    injected = seg.strip()
    assert injected.startswith("mkdir -p") and "mv --" in injected, "注入串解析失败: %r" % injected[:200]
    rc2, blob2 = _run_hook(injected)
    assert rc2 == 0, (
        "自洽臂红：注入串被自家 hook 拦截（hint=诱导犯规）rc=%r blob=%r" % (rc2, blob2[:300]))


def test_arm_d_empty_state_file_env_not_override():
    """臂 D（回归锁）：`STATE_FILE=`（空串）不得判为显式覆盖 ⟹ hook 正常读默认 state。

    红先证据（2026-09-25）：原式 `"STATE_FILE" in os.environ` 对空串判 True ⟹
    `Path("")` = `Path(".")` ⟹ IsADirectoryError ⟹ 一切过 R0.x 的 RunCommand 被
    fail-closed「State file corrupt」确定性假拦（wslsh 环境实测）。
    """
    payload = json.dumps({
        "tool_name": "RunCommand",
        "tool_input": {"command": "echo gk-arm-d-probe"},
        "cwd": REPO,
    })
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", STATE_FILE="")
    p = subprocess.run([sys.executable, HOOK], input=payload, capture_output=True,
                       text=True, env=env, cwd=REPO, timeout=60)
    blob = (p.stdout or "") + "\n" + (p.stderr or "")
    assert "State file corrupt" not in blob, "空 STATE_FILE 仍触发 corrupt 假拦: %r" % blob[:200]
    assert p.returncode == 0, "echo 探针被拦：rc=%r blob=%r" % (p.returncode, blob[:200])
