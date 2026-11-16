#!/usr/bin/env python3
"""red_runtime.runner — 运行时攻防**沙盘骨架**（408 方案 §2 / §7）。

定位：给"攻击剧本"一个**只能伤到自己**的执行面。本文件只做骨架，不实现任何攻击场景，
不读写真实 state / 账本 / worktree。三条元不变量由 `test_red_runtime_sandbox.py` 锁形：

  · **E1 限额**：每一步只经 `gk_sandbox.run`（禁裸 `subprocess`）⟹ 内存 / 超时 / 进程数硬限，
    超限即被杀；`fail_closed=True` ⟹ 限额无法建立时**拒跑**（不静默假装有沙箱）。
  · **E3 隔离**：沙盘根**必须**在 `/tmp`（禁 `/mnt/*` drvfs / 9p —— 本会话实测该 FS 上一次
    rmtree 让进程 `D` 状态 14 分钟）；步骤环境注入沙盘内 `STATE_FILE` / claims / TMPDIR；
    受保护真实件跑前后 sha256 比对，任一变化 ⟹ 判 FAIL（`isolation_violation`）。
  · **E4 判别力**：判定器对守卫臂（无副作用）给 PASS、对真违反不变量给 FAIL，禁恒真。

证据面：`evidence.jsonl` 逐步 append + `fsync`（崩溃后可重建），`summary.json` 原子替换落盘。
同一沙盘根**重跑即拒**（`FileExistsError`）—— append-only，绝不静默覆盖。

用法（骨架，供测试与后续剧本调用）：

    from red_runtime import runner
    rep = runner.run_scenario(scenario, root="/tmp/red-runtime/run-1",
                              limits={"mem_mb": 256, "timeout_s": 30, "max_proc": 2},
                              protected=["/mnt/c/.../src/.gatekeeper.state"])

scenario 形态（最小）：

    {"id": "ledger-poison-01", "kind": "runtime",
     "steps": [{"argv": ["python3", "probe.py"],
                "invariant": {"kind": "file_absent", "path": "leak.txt"}}]}

支持的不变量：`exit_zero` / `exit_nonzero` / `timed_out` / `file_absent` / `file_present`。
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:            # 允许 `from red_runtime import runner` 后直接复用
    sys.path.insert(0, str(_SCRIPTS))

import gk_sandbox  # noqa: E402  —— 唯一执行通道（禁裸 subprocess）

DEFAULTS = {"mem_mb": 512, "timeout_s": 60, "max_proc": 2}
# 并发硬上限（E2）：超过即拒跑，不静默降级。运行时攻防的并行是 OOM 的唯一入口
# （gk_hub_scheduler 文档实测 300 路 fan-out 无管控时的膨胀面）。
MAX_PARALLEL_CAP = 4
_INVARIANT_KINDS = ("exit_zero", "exit_nonzero", "timed_out", "file_absent", "file_present")
_ENV_KEYS = ("STATE_FILE", "GK_STATE_FILE", "GK_WRITE_CLAIMS_PATH", "TMPDIR", "GK_RED_RUNTIME_ROOT")
_OWNED_FILES = ("evidence.jsonl", "summary.json", "state.json", "claims.jsonl")


def _norm(p) -> str:
    return str(p).replace("\\", "/")


def _is_drvfs(p) -> bool:
    """沙盘根是否落在 WSL 的 drvfs / 9p 面（`/mnt/<drive>/…`）。

    Windows 宿主原生盘（`C:/…` NTFS）**不**在此列：慢的是 9p 协议，不是盘符本身。
    """
    return _norm(p).lower().startswith("/mnt/")


def sha256_file(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(paths) -> dict:
    """受保护件快照：{原样路径: sha256 | "ABSENT"}（缺失也记为事实，而非跳过）。"""
    out = {}
    for p in paths or []:
        sp = str(p)
        out[sp] = sha256_file(sp) if Path(sp).is_file() else "ABSENT"
    return out


def ensure_root(root) -> Path:
    """建立沙盘根；落在 drvfs ⟹ ValueError（E3 硬拒绝，不是警告）。"""
    if _is_drvfs(root):
        raise ValueError(
            f"sandbox root must not be on drvfs (/mnt/*): {root} —— "
            "9p 上单次 rmtree 实测可 D 状态 14min，运行时攻防禁写该面")
    rp = Path(root)
    rp.mkdir(parents=True, exist_ok=True)
    return rp


def isolated_env(root, base=None) -> dict:
    """步骤环境：把 state / claims / tmp 全部钉进沙盘根（真实件只读挂载，绝不注入真路径）。"""
    rp = Path(root)
    (rp / "tmp").mkdir(parents=True, exist_ok=True)
    env = dict(os.environ if base is None else base)
    env.update({
        "STATE_FILE": str(rp / "state.json"),
        "GK_STATE_FILE": str(rp / "state.json"),
        "GK_WRITE_CLAIMS_PATH": str(rp / "claims.jsonl"),
        "TMPDIR": str(rp / "tmp"),
        "TEMP": str(rp / "tmp"),
        "TMP": str(rp / "tmp"),
        "GK_RED_RUNTIME_ROOT": str(rp),
    })
    if os.name != "nt":
        env["HOME"] = str(rp)          # 防步骤里 git/ssh 读到真实 home
    return env


def _append_jsonl(path: Path, rec: dict) -> None:
    line = json.dumps(rec, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _atomic_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def check_invariant(inv: dict, *, rc, timed_out: bool, root) -> list:
    """不变量求值：返回 violation 列表（空 = 成立）。未知 kind ⟹ ValueError（禁静默放过）。"""
    kind = (inv or {}).get("kind")
    if kind not in _INVARIANT_KINDS:
        raise ValueError(f"unknown invariant kind: {kind!r}")
    if kind == "exit_zero":
        return [] if rc == 0 else [{"invariant": inv, "detail": f"rc={rc}"}]
    if kind == "exit_nonzero":
        return [] if rc not in (0, None) else [{"invariant": inv, "detail": f"rc={rc}"}]
    if kind == "timed_out":
        return [] if timed_out else [{"invariant": inv, "detail": "step finished before timeout"}]
    target = Path(root) / str(inv.get("path", ""))
    if kind == "file_absent":
        return [] if not target.exists() else [{"invariant": inv, "detail": f"exists: {target}"}]
    return [] if target.exists() else [{"invariant": inv, "detail": f"missing: {target}"}]


def run_step(step: dict, *, root, env, limits) -> dict:
    """执行一步（**唯一**执行通道 = gk_sandbox.run），返回步骤记录（含 violations）。"""
    argv = [str(a) for a in (step.get("argv") or [])]
    sb = gk_sandbox.run(argv, mem_mb=limits["mem_mb"], timeout_s=limits["timeout_s"],
                        max_proc=limits["max_proc"], cwd=str(root), env=env,
                        fail_closed=True)
    violations = []
    if not sb.get("ok"):
        # 限额建立失败 ⟹ 拒跑事实本身记为 violation（绝不把"没跑"当"没被攻破"）
        violations.append({"invariant": {"kind": "sandbox_enforced"},
                           "detail": sb.get("reason") or "sandbox not enforced"})
    else:
        violations.extend(check_invariant(step.get("invariant") or {},
                                          rc=sb.get("rc"), timed_out=bool(sb.get("timed_out")),
                                          root=root))
    return {
        "argv": argv,
        "sandbox": sb,
        "rc": sb.get("rc"),
        "violations": violations,
        "env": {k: env.get(k) for k in _ENV_KEYS},
    }


def run_scenario(scenario: dict, *, root, limits=None, protected=None, base_env=None) -> dict:
    """跑一个运行时场景，返回判定报告（PASS/FAIL）与证据路径。

    FAIL 条件（任一）：某步违反不变量 / 沙箱限额未建立 / 受保护真实件被改动。
    隔离纪律：`protected` 里的路径**只做前后哈希**，本函数不读其内容写盘、也不向其写入。
    """
    lim = dict(DEFAULTS)
    lim.update(limits or {})
    rp = ensure_root(root)
    ev = rp / "evidence.jsonl"
    if ev.exists():
        raise FileExistsError(f"sandbox run root already used (append-only): {ev}")

    protected = [str(p) for p in (protected or [])]
    before = snapshot(protected)
    env = isolated_env(rp, base_env)

    steps = []
    for i, step in enumerate(scenario.get("steps") or []):
        rec = run_step(step, root=rp, env=env, limits=lim)
        rec["index"] = i
        _append_jsonl(ev, {"type": "step", **rec})
        steps.append(rec)

    after = snapshot(protected)
    unchanged = before == after
    failed = (not steps) or any(s["violations"] for s in steps) or (not unchanged)
    report = {
        "ok": True,
        "scenario": scenario.get("id"),
        "kind": scenario.get("kind", "runtime"),
        "verdict": "FAIL" if failed else "PASS",
        "protected_unchanged": unchanged,
        "protected": {"before": before, "after": after},
        "limits": lim,
        "root": str(rp),
        "evidence": str(ev),
        "steps": steps,
    }
    if not unchanged:
        report["isolation_violation"] = [p for p in before if before[p] != after.get(p)]
    _atomic_json(rp / "summary.json", report)
    return report


def run_scenarios(scenarios, *, root_base, max_parallel=3, limits=None,
                  protected=None, base_env=None) -> list:
    """**有界**并行跑多个场景（E2）：每个场景独立根 `<root_base>/<序>-<id>`。

    `max_parallel` 超过 `MAX_PARALLEL_CAP` ⟹ ValueError（拒跑，不静默降级到上限）。
    每个场景内部仍走 `run_scenario`（每步只经 `gk_sandbox.run`）⟹ 限额是按**进程**生效，
    并行只影响同时在跑的数量，不影响单进程上限。
    """
    if not isinstance(max_parallel, int) or max_parallel < 1 or max_parallel > MAX_PARALLEL_CAP:
        raise ValueError(
            "max_parallel must be int in [1, %d]（超限拒跑，防无界并行 OOM）" % MAX_PARALLEL_CAP)
    from concurrent.futures import ThreadPoolExecutor

    base = ensure_root(root_base)
    scns = list(scenarios or [])

    def _one(item):
        i, scn = item
        rid = "%02d-%s" % (i, scn.get("id") or "scn")
        return run_scenario(scn, root=str(base / rid), limits=limits,
                            protected=protected, base_env=base_env)

    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        return list(ex.map(_one, list(enumerate(scns))))


def recover(root) -> dict:
    """**崩溃恢复读数**（E5）：只读 `evidence.jsonl`，半写尾行 / 坏行跳过（不当成事实）。

    返回 `{completed, steps, evidence}`；`completed` = 已完整落盘并 fsync 的步骤数。
    本函数**不写**任何东西（恢复动作是 `discard` 或人工归档）。
    """
    rp = Path(root)
    ev = rp / "evidence.jsonl"
    steps = []
    if ev.exists():
        for ln in ev.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
            except ValueError:
                continue                      # 崩溃半写尾行 ⟹ 跳过
            if isinstance(rec, dict) and rec.get("type") == "step":
                steps.append(rec)
    return {"completed": len(steps), "steps": steps, "evidence": str(ev)}


def discard(root, archive_dir=None) -> dict:
    """**清场**（E5/E6）：把本沙盘根拥有的件（证据 / 摘要 / 沙盘 state / claims）整体移入归档目录。

    用途：① 崩溃后原根可重建；② 被"投毒"（预置伪造 state/claims）的根可清场而不外溢。
    只移动 `_OWNED_FILES`，**不递归**、不删别的文件；同根再跑由 `run_scenario` 的
    append-only 判据把关（证据已被移走 ⟹ 可重建）。
    """
    rp = ensure_root(root)
    dest = Path(archive_dir) if archive_dir else rp / (
        "_discarded-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    moved = []
    for name in _OWNED_FILES:
        src = rp / name
        if not src.exists():
            continue
        dest.mkdir(parents=True, exist_ok=True)
        tgt = dest / name
        n = 1
        while tgt.exists():
            tgt = dest / ("%s.%d" % (name, n))
            n += 1
        os.replace(src, tgt)
        moved.append(str(tgt))
    return {"ok": True, "archived": moved, "dir": str(dest) if moved else ""}
