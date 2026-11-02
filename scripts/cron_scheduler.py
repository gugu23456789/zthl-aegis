"""
Gatekeeper Cron — Scheduler (Tick Loop)
Hermes-agent 1:1 replica: 60s tick, file lock, at-most-once, parallel/sequential split
"""
import json, os, sys, time, datetime, subprocess, threading, hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPT_DIR)
_CRON_DIR = os.path.join(os.path.expanduser("~"), ".gatekeeper", "cron")
# §18.2 判据 c1（2026-10-04）：无 per-state state 时的**回退**锁（零回归）；
#   有 state ⟹ `_lock_file_path()` 派生 per-state 锁（不同域可并发 tick）。
LOCK_FILE = os.path.join(_CRON_DIR, ".tick.lock")
GATEKEEPER_CLI = os.path.join(SKILL_DIR, "gatekeeper-cli.sh")
LOG_FILE = os.path.join(_CRON_DIR, "tick.log")

sys.path.insert(0, SCRIPT_DIR)
from cron_jobs import get_due_jobs, mark_job_run, advance_next_run


def _utcnow():
    """Naive UTC now — 规避 deprecated datetime.utcnow()（3.12 起弃用，__main__ 下弹警告）。"""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# ── §18.2 判据 c1（2026-10-04）：cron per-state 维度 ─────────────────────────
# 病象（遗漏②）：调度器仅全局 `.tick.lock`、0 处 `STATE_FILE` ⟹ 无 per-state 维度；
#   卫星随路由命中的 `STATE_FILE` 落盘时，cron 无法按域隔离 / 复用（α1「复用 cron」不成立）。
# 修法：经**单一事实源**解析 per-state state（env 优先，否则委托 `gk_state`，与 CLI / hook
#   同源，禁第二套判定）⟹ 锁按 state 派生 + 导出 `STATE_FILE` 进 job 子进程。
def _resolve_state_file():
    """解析本调度器服务的 per-state state（单一事实源；失败 fail-safe 回空）。"""
    sf = os.environ.get("STATE_FILE", "")
    if sf:
        return sf
    try:
        # 懒 import：避开导入期副作用 / 与 cron 无关的模块级 git 解析
        from gk_state import _resolve_default_state
        return _resolve_default_state()
    except Exception:
        return ""


def _lock_file_path():
    """per-state tick 锁路径：不同 state ⟹ 不同锁（可并发 tick）；无 state ⟹ 回退全局锁。"""
    sf = _resolve_state_file()
    if not sf:
        return LOCK_FILE
    sid = hashlib.sha1(os.path.abspath(sf).encode("utf-8")).hexdigest()[:12]
    return os.path.join(_CRON_DIR, ".tick.%s.lock" % sid)


def _job_env(base):
    """job 子进程 env：注入 per-state `STATE_FILE`（无 state 不注入，防误塞空值）。"""
    env = dict(base)
    sf = _resolve_state_file()
    if sf:
        env["STATE_FILE"] = sf
    return env

# W10/WSLENV 全覆盖 (2026-08-09): 调度器自身环境缺 key 时注入
# （Windows 计划任务 / WSL 终端直跑 cron 时进程环境可能无 key → agent 子进程 401）
try:
    from gk_env_inject import inject as _gk_inject
    _gk_inject()
except Exception:
    pass

_running_job_ids = set()
_running_lock = threading.Lock()

def _acquire_lock():
    """File lock (cross-platform)，per-state 路径（§18.2 c1）。"""
    lock_path = _lock_file_path()
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    try:
        if os.name == "nt":
            import msvcrt
            fd = open(lock_path, "w")
            try:
                msvcrt.locking(fd.fileno(), msvcrt.LK_NBLCK, 1)
                return fd
            except:
                fd.close()
                return None
        else:
            import fcntl
            fd = open(lock_path, "w")
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except:
                fd.close()
                return None
    except:
        return None

def _release_lock(fd):
    if fd:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            fd.close()
        except:
            pass

def _sanitize_subprocess_env(env):
    """Remove sensitive variables from subprocess environment (Hermes pattern)."""
    sensitive_keys = [
        "DEEPSEEK_API_KEY", "GATEKEEPER_API_KEY", "OPENAI_API_KEY",
        "API_KEY", "API_SECRET", "TOKEN", "PASSWORD", "SECRET",
        "PRIVATE_KEY", "SIGNING_KEY",
    ]
    sanitized = dict(env)
    for key in list(sanitized.keys()):
        upper_key = key.upper()
        for sensitive in sensitive_keys:
            if sensitive in upper_key:
                del sanitized[key]
                break
    return sanitized

def _run_job(job):
    """Execute a single cron job."""
    job_id = job.get("id", "")
    prompt = job.get("prompt", "")
    name = job.get("name", "")
    script = job.get("script", "")
    no_agent = job.get("no_agent", False)

    with _running_lock:
        if job_id in _running_job_ids:
            return
        _running_job_ids.add(job_id)

    try:
        output = ""
        error = ""
        status = "ok"

        if no_agent and script:
            # Script mode (no LLM)
            try:
                # F-REV-94（2026-09-17，用户裁定「其他都同意」）：解释器**按扩展名派发** ——
                #   原实现硬编码 `["bash", script]`，对 `.py` 脚本即"用 bash 执行 Python 源码"。
                #   实测 `external-ref`（`scripts/gk_cron_external_ref.py`）**每小时**报
                #   `.../gk_cron_external_ref.py: line 4: --script: command not found`
                #   —— bash 把 docstring 里的字面量当命令执行 ⟹ 该 job 自建起**从未成功过一次**
                #   （`tick.log` 恒 `Job external-ref (fb2459aa51a8): error`，每小时一条噪声）。
                #   ⚠ 与 `cron_jobs.validate_script_path` 的沙箱**互补**（那只校验路径必须在
                #   `scripts/` 下），二者都保留。
                cmd = ([sys.executable, script] if script.endswith(".py")
                       else ["bash", script])
                safe_env = _job_env(_sanitize_subprocess_env(os.environ.copy()))
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=job.get("timeout", 120),
                    cwd=SKILL_DIR, env=safe_env
                )
                output = result.stdout
                error = result.stderr
                status = "ok" if result.returncode == 0 else "error"
            except subprocess.TimeoutExpired:
                status = "error"
                error = "Script timeout"
            except Exception as e:
                status = "error"
                error = str(e)
            # Wake gate: parse script output to decide if agent should run
            if status == "ok" and output:
                from cron_jobs import parse_wake_gate
                should_run, cleaned = parse_wake_gate(output)
                if not should_run:
                    mark_job_run(job_id, "ok", cleaned, "")
                    _log(f"Job {name} ({job_id}): wake gate=false, skipped agent")
                    return
                output = cleaned
        else:
            # Agent mode: run gatekeeper-cli.sh with the prompt
            try:
                # context_from: inject upstream job output into prompt
                context_from = job.get("context_from", "")
                full_prompt = prompt
                if context_from:
                    from cron_jobs import resolve_context_from
                    ctx = resolve_context_from(context_from)
                    if ctx:
                        full_prompt = f"CONTEXT FROM {context_from}:\n{ctx}\n\nTASK:\n{prompt}"
                # Runtime injection scan (loose mode)
                from cron_jobs import scan_prompt
                scan = scan_prompt(full_prompt, strict=False)
                if not scan.get("ok"):
                    mark_job_run(job_id, "error", "", f"Runtime scan blocked: {scan.get('error')}")
                    return
                full_prompt = scan.get("filtered", full_prompt)
                # Use the CLI to run the prompt through the subagent
                result = subprocess.run(
                    ["bash", GATEKEEPER_CLI, "cron", "run", job_id],
                    capture_output=True, text=True, timeout=600,
                    cwd=SKILL_DIR, env=_job_env({**os.environ, "CRON_PROMPT": full_prompt})
                )
                output = result.stdout[:2000]
                error = result.stderr[:500]
                status = "ok" if result.returncode == 0 else "error"
            except subprocess.TimeoutExpired:
                status = "error"
                error = "Agent timeout (600s)"
            except Exception as e:
                status = "error"
                error = str(e)

        mark_job_run(job_id, status, output, error)
        _log(f"Job {name} ({job_id}): {status}")

        # Outer loop trigger: if job is release-check and status=ok, project state via CLI
        # Phase 7c (2026-08-21): 改走 CLI `cron health` —— checksum-aware + plan 指针感知写入，
        # 修复直写 state 不重算 _checksum → 下次 advance/guard-edit 报 TAMPERED 的 bug。
        if name == "release-check" and status == "ok" and output:
            try:
                import tempfile
                fd, rc_path = tempfile.mkstemp(suffix=".json", dir=SKILL_DIR)
                with os.fdopen(fd, "w") as f:
                    f.write(json.dumps({
                        "timestamp": _utcnow().isoformat() + "Z",
                        "output": output[:2000],
                        "source": "cron",
                    }, ensure_ascii=False))
                health = None
                try:
                    health = subprocess.run(
                        ["bash", GATEKEEPER_CLI, "cron", "health", rc_path],
                        capture_output=True, text=True, timeout=30, cwd=SKILL_DIR,
                    )
                finally:
                    try: os.unlink(rc_path)
                    except OSError: pass
                _log("Outer loop: release-check output projected to state")
                ptype = "standard"
                if health is not None and health.returncode == 0:
                    try:
                        ptype = json.loads(health.stdout).get("project_type", "standard")
                    except Exception:
                        pass
                # Auto-advance: trigger ECO-RESEARCH if standing project
                if ptype == "standing":
                    try:
                        adv = subprocess.run(
                            ["bash", GATEKEEPER_CLI, "advance", "ECO-RESEARCH"],
                            capture_output=True, text=True, timeout=30,
                            cwd=SKILL_DIR,
                        )
                        if adv.returncode == 0:
                            _log("Auto-advance: ECO-RESEARCH triggered")
                        else:
                            _log("Auto-advance: ECO-RESEARCH skipped (gate blocked)")
                    except Exception as ae:
                        _log(f"Auto-advance failed: {ae}")
            except Exception as e:
                _log(f"Outer loop trigger failed: {e}")

    finally:
        with _running_lock:
            _running_job_ids.discard(job_id)

def _log(msg):
    ts = _utcnow().isoformat()[:19]
    line = f"[{ts}] {msg}"
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except:
        pass

def tick(verbose=False):
    """Single tick: check due jobs and execute them."""
    lock_fd = _acquire_lock()
    if not lock_fd:
        if verbose:
            print(json.dumps({"ok": False, "error": "Another tick is running"}))
        return

    try:
        due = get_due_jobs()
        if verbose:
            print(json.dumps({"ok": True, "due": len(due), "jobs": [j.get("name") for j in due]}))

        if not due:
            # 2026-09-01 落痕修复：无 due job 也写日志（此前直接 return，tick.log 恒空，
            # 无法区分"调度器没跑" vs "跑了但无 job"——用户质询 cron 没动静即此因）。
            _log(f"Tick: no due jobs ({datetime.datetime.now().strftime('%H:%M:%S')})")
            return

        # Advance next_run_at first (at-most-once)
        # Phase 7c A1 (2026-08-21): get_due_jobs 已对过期作业 fast-forward（补跑一次），
        # 此处跳过已推进到未来的作业，防二次推进回归导致重复执行。
        now = _utcnow()
        for job in due:
            try:
                nxt = datetime.datetime.fromisoformat(str(job.get("next_run_at", "")).replace("Z", ""))
                if nxt > now:
                    continue
            except Exception:
                pass
            advance_next_run(job)

        # Execute jobs
        threads = []
        for job in due:
            t = threading.Thread(target=_run_job, args=(job,), daemon=True)
            t.start()
            threads.append(t)

        # Wait for all (max 600s)
        for t in threads:
            t.join(timeout=600)

    finally:
        _release_lock(lock_fd)

def run_loop(interval=60, verbose=False):
    """Continuous tick loop (daemon mode)."""
    _log("Cron scheduler started")
    while True:
        try:
            tick(verbose=verbose)
        except Exception as e:
            _log(f"Tick error: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--interval", type=int, default=60, help="Tick interval in seconds")
    p.add_argument("--once", action="store_true", help="Run one tick and exit")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if args.once:
        tick(verbose=args.verbose)
    else:
        run_loop(interval=args.interval, verbose=args.verbose)
