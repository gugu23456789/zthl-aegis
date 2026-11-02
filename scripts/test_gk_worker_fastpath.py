#!/usr/bin/env python3
"""A7 接线红先臂：worker 快路（2026-10-29）

## 被堵的坑（全部实测，非推断）

| # | 坑 | 后果 |
|:--|:--|:--|
| ① | pidfile 只有 pid/port/token，**无代码版本** | 改完 `gk_*` 模块后，TTL 内的 daemon 仍按**旧逻辑**作答 ⟹ fail-closed 启动面静默错误 |
| ② | `call()` 默认 autostart + `wait_s=5` | 关键路径首调付 1.7s 冷启，比它要省的 ~0.26s 还贵 6 倍 |
| ③ | `call()` 默认 `timeout=10s` | daemon 卡住 ⟹ 一次门禁调用阻塞 10s（比失败更糟） |
| ④ | daemon env 在启动时**冻结** | 域化 state / 会话计划（`STATE_FILE`/`GK_PLAN_FILE`/`PLAN_POINTER`）被忽略 ⟹ 路由错 state |
| ⑤ | TTL = 自启动起**绝对**截止 | 连续调用到第 15 分钟即被判过期，随后白吃冷启 |
| ⑥ | 快路与原路径**语义漂移**风险 | 若 worker 侧重写 `resolve-state` 的 domain 推导 ⟹ 域路由两套实现 |

## 修的判据（本文件锁死）

- `code_epoch` 稳定 + 依赖文件变 ⟹ 变；pidfile 第 4 行 == 本地 epoch；
- epoch 不符 ⟹ `epoch_mismatch`（**不**发请求）；
- `--if-alive` 且无 pidfile ⟹ 非零退出且**不创建** pidfile（绝不 autostart）；
- `warm` ⟹ 建 pidfile 且 `resolve_state_cli` 可用；
- **逐字等价**：worker op 输出 == `gk_route_center resolve-state --derive-domain` 子进程输出
  （含域化场景）；
- 环境按请求生效且**不残留**（两次调用不同 `GK_PLAN_FILE` ⟹ 两次不同 domain）；
- CLI 集成：worker 开启/关闭 两种情形 CLI 均 rc=0，且开启时 dbg 日志出现快路命中标记。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"

sys.path.insert(0, str(SCRIPT_DIR))

import gk_worker_client as C  # noqa: E402
import gk_worker_epoch as E  # noqa: E402


def _wsl(p) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


# ── ① code_epoch 语义 ────────────────────────────────────────────────────────
def test_code_epoch_stable(tmp_path):
    """同目录两次 ⟹ 同值（指纹必须可复现，否则每次调用都判不符 = 快路永久失效）。"""
    for name in E._DEPS:
        (tmp_path / name).write_text("x", encoding="utf-8")
    assert E.code_epoch(str(tmp_path)) == E.code_epoch(str(tmp_path))


def test_code_epoch_changes_on_dependency_edit(tmp_path):
    for name in E._DEPS:
        (tmp_path / name).write_text("x", encoding="utf-8")
    a = E.code_epoch(str(tmp_path))
    p = tmp_path / "gk_state_route.py"
    p.write_text("y" * 64, encoding="utf-8")
    assert E.code_epoch(str(tmp_path)) != a


def test_code_epoch_missing_dep_is_part_of_state(tmp_path):
    """缺依赖与存在（空文件）不得同值 —— 「装上/删掉」也是状态变化。"""
    for name in E._DEPS:
        if name != "gk_state.py":
            (tmp_path / name).write_text("x", encoding="utf-8")
    a = E.code_epoch(str(tmp_path))
    (tmp_path / "gk_state.py").write_text("", encoding="utf-8")
    assert E.code_epoch(str(tmp_path)) != a


# ── ②-⑤ 客户端契约 ──────────────────────────────────────────────────────────
@pytest.fixture
def live(tmp_path):
    pf = str(tmp_path / "w.pid")
    env = {**os.environ, "GK_WORKER_PIDFILE": pf}
    r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_worker_client.py"), "warm"],
                       capture_output=True, text=True, timeout=180, env=env)
    assert r.returncode == 0, r.stderr[-400:]
    yield pf
    C.stop(pf)


def test_pidfile_has_epoch_line(live):
    info = C.read_pidfile(live)
    assert info["port"] > 0 and info["token"]
    assert info.get("epoch") == E.code_epoch(str(SCRIPT_DIR)), (
        "pidfile 第 4 行须 = 当前代码指纹 ⟹ 否则旧 daemon 无法被识别")
    lines = Path(live).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5


def test_epoch_mismatch_short_circuits(live):
    r = C.call("ping", pidfile=live, expected_epoch="deadbeefdeadbeef")
    assert r["ok"] is False and "epoch_mismatch" in r["error"]


def test_epoch_match_allows_call(live):
    r = C.call("ping", pidfile=live, expected_epoch=E.code_epoch(str(SCRIPT_DIR)))
    assert r["ok"] is True


def test_if_alive_never_autostarts(tmp_path):
    """无 pidfile + `--if-alive` ⟹ 非零退出，且**不得**创建 pidfile（关键路径禁冷启）。"""
    pf = tmp_path / "absent.pid"
    env = {**os.environ, "GK_WORKER_PIDFILE": str(pf)}
    r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_worker_client.py"),
                        "op", "ping", "--pidfile", str(pf), "--if-alive", "--timeout", "0.2"],
                       capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode != 0, f"离线竟成功：{r.stdout}"
    assert not pf.exists(), "`--if-alive` 不得 autostart（冷启 1.7s > 要省的 0.26s）"


# ── ⑥ 逐字等价（本文件的核心判据）────────────────────────────────────────────
def _cli_resolve(skill_dir: str) -> str:
    return subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_route_center.py"),
                           "resolve-state", "--derive-domain", "--skill-dir", skill_dir],
                          capture_output=True, text=True, timeout=180,
                          cwd=str(SCRIPT_DIR)).stdout.strip()


def _worker_resolve(pf: str, skill_dir: str) -> str:
    r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_worker_client.py"),
                        "op", "resolve_state_cli", "--pidfile", pf, "--if-alive",
                        "--epoch-auto", "--timeout", "5", "--unwrap", "--forward-env",
                        "--skill_dir", skill_dir, "--derive_domain", "1"],
                       capture_output=True, text=True, timeout=180, cwd=str(SCRIPT_DIR))
    assert r.returncode == 0, r.stderr[-400:]
    return r.stdout.strip()


def test_worker_op_byte_identical_to_cli(live, monkeypatch):
    monkeypatch.delenv("GK_PLAN_FILE", raising=False)
    assert _worker_resolve(live, str(SCRIPT_DIR)) == _cli_resolve(str(SCRIPT_DIR))


def test_worker_op_byte_identical_with_domain_plan(live, tmp_path, monkeypatch):
    plan = tmp_path / "dom.md"
    plan.write_text("<!-- META\ntarget_repo: skill\nworktree_needed: false\n"
                    "project_type: standing\nstate_domain: skill.epoch-parity\n-->\n",
                    encoding="utf-8", newline="\n")
    monkeypatch.setenv("GK_PLAN_FILE", str(plan))
    assert _worker_resolve(live, str(SCRIPT_DIR)) == _cli_resolve(str(SCRIPT_DIR))


def test_env_forwarding_does_not_leak_between_calls(live, tmp_path, monkeypatch):
    """第一次带会话计划（域路由），第二次不带 ⟹ 第二次不得沿用第一次的 domain。"""
    plan = tmp_path / "dom.md"
    plan.write_text("<!-- META\ntarget_repo: skill\nworktree_needed: false\n"
                    "project_type: standing\nstate_domain: skill.leak-probe\n-->\n",
                    encoding="utf-8", newline="\n")
    monkeypatch.setenv("GK_PLAN_FILE", str(plan))
    with_plan = json.loads(_worker_resolve(live, str(SCRIPT_DIR)))
    monkeypatch.delenv("GK_PLAN_FILE", raising=False)
    without = json.loads(_worker_resolve(live, str(SCRIPT_DIR)))
    assert with_plan.get("domain") == "skill.leak-probe", with_plan
    assert without.get("domain") in ("", None), (
        f"daemon 记住了上一次的 GK_PLAN_FILE ⟹ env 泄漏：{without.get('domain')!r}")


# ── CLI 集成：快路开/关都必须 rc=0，且开启时留命中痕 ─────────────────────────
def _run_cli(pf: str, dbg: Path, extra_env: dict | None = None):
    state = dbg.parent / "s.json"
    if not state.exists():
        state.write_text(json.dumps({"stage": "ECO-EDIT", "r_phase": "R1",
                                     "gate_data": {}}), encoding="utf-8")
    # GK_DBG_LOG 在 CLI L110 是**硬赋值**（不读 env）⟹ 只能读仓内 `scripts/gk_dbg.log`；
    # 故留给「快路命中」行一个**唯一 pidfile 路径**做隔离（并发会话共写该日志）。
    env = {**os.environ, "STATE_FILE": str(state), "GK_WORKER_PIDFILE": pf,
           "GK_BUDGET_OVERRIDE": "1"}
    env.pop("GK_WORKER_DISABLE", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(CLI), "state"], capture_output=True, text=True,
                          timeout=180, env=env)


def _dbg_text() -> str:
    p = SCRIPT_DIR / "gk_dbg.log"
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def test_cli_works_with_and_without_worker(live, tmp_path):
    r_on = _run_cli(live, tmp_path / "on.log")
    assert r_on.returncode == 0, (r_on.stdout + r_on.stderr)[-600:]
    assert ("worker fast path hit pidfile=" + live) in _dbg_text(), (
        "快路未命中 —— 接线未生效或 epoch 判据恒不符")

    # 换一个**新** pidfile 路径跑关闭态：日志里不得出现该路径（隔离并发会话的旧行）
    dead = tmp_path / "off.pid"
    dead.write_text("999999\n1\ntok\nbogus\n", encoding="utf-8")
    r_off = _run_cli(str(dead), tmp_path / "off.log", {"GK_WORKER_DISABLE": "1"})
    assert r_off.returncode == 0, (r_off.stdout + r_off.stderr)[-600:]
    assert ("worker fast path hit pidfile=" + str(dead)) not in _dbg_text()


def test_cli_survives_dead_pidfile(tmp_path):
    """pidfile 存在但 pid 已死 ⟹ CLI 必须照常工作（快路失败不得影响门禁）。"""
    pf = tmp_path / "dead.pid"
    pf.write_text("999999\n1\ndeadtoken\nbogusepoch\n", encoding="utf-8")
    r = _run_cli(str(pf), tmp_path / "dead.log")
    assert r.returncode == 0, (r.stdout + r.stderr)[-600:]
