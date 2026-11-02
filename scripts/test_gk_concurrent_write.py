#!/usr/bin/env python3
"""并发写 state 丢更新 红先臂（ECC-4E6D7F42CA05，2026-09-27）。

缺陷（实测，2026-09-27）：在一次性 state 副本上做 8 并发 `finding register`，
  CLI 全部返回 `ok:true`，但**只有 2 条落盘**（丢 6）；同样 8 条**串行**执行则 8/8。
根因 = 两条「读在锁外 + 写旧表」的读-改-写：
  ① `gk_finding.register`：`load_findings` 在锁外读，`save_findings` 虽持
     `state_lock` 却写**调用方传入的旧 list**（不在锁内重读合并）⟹ 后者覆盖前者；
     `save_findings` 自述的「读-改-写整体持锁（选项 A）」与实现不符。
  ② `gatekeeper-cli.sh` 的 `monitor --subagent` 落库块（写
     `subagent_history` / `subagent_last` / `_sealed_agent_score`）：
     `json.load` → `hist.append` → `json.dump`（裸 `open(...,'w')`）**全程无 `state_lock`**
     ⟹ 并发臂完成时互相覆盖（多臂并行派发的直接冲突面）。

臂清单（红先 = 落刀前必失败）：
  arm15a 行为：N 进程并发 `gk_finding.register` ⟹ 全部 N 条必须落盘（红先：HEAD 丢写）
  arm15b 静态：`gk_finding.register` 的读-改-写整体在 `state_lock` 内（红先：HEAD 读在锁外）
  arm15c 静态：CLI monitor 落库载荷持 `state_lock` 且不再裸 `json.dump(...STATE_FILE...)`（红先）
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
CLI = SD / "gatekeeper-cli.sh"
SCRIPTS = SD / "scripts"


def _py_fn(src: str, name: str) -> str:
    """抽 python 函数体（从 `def name(` 到下一个顶层 `def `/`class `）。"""
    m = re.search(rf"^def {re.escape(name)}\(", src, re.M)
    if not m:
        return ""
    nxt = re.search(r"^(?:def |class )", src[m.end():], re.M)
    return src[m.start():m.end() + (nxt.start() if nxt else len(src) - m.end())]


def _cli_history_payload(src: str) -> str:
    """切出 `monitor --subagent` 的落库 python 载荷（双引号区）。

    锚 = 派发行 `GK_TASK="$task" GK_HMAC_VALID="$hmac_valid" python3 -c "`
      … 首个「列 0 收尾行」`\n" 2>>`（C3① 前该行是 `" 2>/dev/null || true`；改 fail-loud 后为
      `" 2>>"${GK_DBG_LOG…}" || {…}` ⟹ 判据面不变，仅边界字面量随实装更新）。
    ⚠ 以 `str.index` 取**首次出现**（对齐本仓既有「注释不得写字面量以免更早命中」的教训）。
    """
    a = src.index('GK_TASK="$task" GK_HMAC_VALID="$hmac_valid" python3 -c "')
    b = src.index('\n" 2>>', a)
    return src[a:b]


def test_arm15a_concurrent_register_no_lost_update(tmp_path):
    """arm15a（行为，红先）：N 进程并发 `gk_finding.register` ⟹ 全部 N 条必须落盘。

    红先性：HEAD 上 `register` 的 `load_findings` 在锁外 ⟹ 并发各读同一旧表、
    `save_findings` 各写自己的旧表副本 ⟹ 后写者覆盖先写者（实测 8 并发仅 2 条落盘）。
    修后：整段读-改-写持 `state_lock` ⟹ 终值恒 == N。
    """
    state = tmp_path / ".gatekeeper.state"
    state.write_text(json.dumps({"stage": "ECO-EDIT", "gate_data": {"ecc_findings": []}},
                                ensure_ascii=False, indent=1),
                     encoding="utf-8", newline="\n")
    n = 8
    child = (
        "import os,sys\n"
        "sys.path.insert(0, os.environ['GK_SCRIPTS'])\n"
        "import gk_finding as F\n"
        "r = F.register(os.environ['GK_STATE'], os.environ['GK_TITLE'], 'manual')\n"
        "sys.exit(0 if r.get('id') else 1)\n"
    )
    ps = [subprocess.Popen([sys.executable, "-c", child],
                           env=dict(os.environ, GK_SCRIPTS=str(SCRIPTS),
                                    GK_STATE=str(state), GK_TITLE="c%d" % i),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          for i in range(n)]
    rcs = [p.wait(timeout=180) for p in ps]
    assert rcs == [0] * n, "并发 `register` 子进程非零退出: %r" % rcs
    got = json.loads(state.read_text(encoding="utf-8"))
    findings = got.get("gate_data", {}).get("ecc_findings") or []
    assert len(findings) == n, (
        "并发 `register` **丢更新**：落盘 %d 条（应 %d）⟹ 读-改-写未整体持锁" % (len(findings), n))


def test_arm15b_register_rmw_inside_state_lock():
    """arm15b（静态，红先）：`gk_finding.register` 的读-改-写整体在 `state_lock` 内。

    红先性：HEAD 上 `register` 直接 `findings = load_findings(...)`（锁外）⟹ 本臂红。
    """
    src = (SCRIPTS / "gk_finding.py").read_text(encoding="utf-8")
    body = _py_fn(src, "register")
    assert body, "未抽到 `gk_finding.register` —— 抽取式失效，臂失去意义"
    assert "with state_lock(state_file):" in body, (
        "`register` 未持 `state_lock`（读-改-写非原子 ⟹ 并发 register 丢更新）")
    lock_at = body.index("with state_lock(state_file):")
    read_at = body.index("load_findings(")
    assert read_at > lock_at, (
        "`register` 的 `load_findings` 仍在 `state_lock` **之前** ⟹ 读在锁外，丢更新窗口未闭")


def test_arm15c_cli_history_payload_holds_state_lock():
    """arm15c（静态，红先）：CLI monitor 落库载荷持 `state_lock` 且写走 `dump_state`。

    红先性：HEAD 的载荷 `json.load` → `hist.append` → 裸 `json.dump(open(STATE_FILE,'w'))`
    全程无锁 ⟹ 本臂红。修后：进入载荷即 `state_lock('$STATE_FILE')`，锁定跨读-写。
    """
    src = CLI.read_text(encoding="utf-8")
    payload = _cli_history_payload(src)
    assert "subagent_history" in payload, "切出的载荷不含 `subagent_history` —— 锚失效，臂失去意义"
    lock_tok = "state_lock(os.environ['GK_PY_STATE'])"
    read_tok = "json.load(open(os.environ['GK_PY_STATE']"
    assert lock_tok in payload, (
        "monitor 落库载荷未取 `state_lock` ⟹ 并发臂完成时读-改-写互相覆盖")
    lock_at = payload.index(lock_tok)
    read_at = payload.index(read_tok)
    assert read_at > lock_at, "载荷的状态读取在取锁**之前** ⟹ 锁未覆盖读，丢更新窗口仍在"
    assert "json.dump(d,open('$STATE_FILE'" not in payload, (
        "载荷仍用裸 `json.dump(...,STATE_FILE...)` 直写（非原子、绕开单一出纳）")
