"""
Gatekeeper Cron — Job Storage & Schedule Parsing
Hermes-agent 6.19 1:1 replica: file lock, atomic write, state machine, wake gate, context_from, runtime scan
"""
import json, os, uuid, hashlib, datetime, re, sys, tempfile, shutil, threading

_DEFAULT_JOBS_DIR = os.path.join(os.path.expanduser("~"), ".gatekeeper", "cron")
JOBS_FILE = os.environ.get("CRON_JOBS_FILE", os.path.join(_DEFAULT_JOBS_DIR, "jobs.json"))
JOBS_DIR = os.path.dirname(JOBS_FILE)
OUTPUT_DIR = os.path.join(JOBS_DIR, "output")
ONESHOT_GRACE_SECONDS = 120
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2026-11-04：威胁模式**单一来源**（`scripts/gk_threat_patterns.py`）。
# 宽口径（PROMPT_*）只服务 cron prompt 扫描；编辑载荷闸 Gate R0.19 在同一模块取高置信
# 子集（PAYLOAD_*）。此处只保留旧名别名 ⟹ 外部引用（`cron_jobs._THREAT_PATTERNS`）不断链，
# 且**禁止**在本文件再写一份正则文本（两份表必然漂移）。
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
from gk_threat_patterns import (  # noqa: E402
    INVISIBLE_UNICODE as _INVISIBLE_UNICODE,
    PROMPT_EXFIL_PATTERNS as _EXFIL_PATTERNS,
    PROMPT_THREAT_PATTERNS as _THREAT_PATTERNS,
)


def _utcnow():
    """Naive UTC now — 规避 deprecated datetime.utcnow()（3.12 起弃用）。"""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
# Phase 7c A4/B2 (2026-08-21): jobs.json 校验 sidecar + 输出保留上限
# 2026-09-20 修复（实测缺陷，非推测）：原为 `_JOBS_CHECKSUM_FILE = JOBS_FILE + ".sha256"`
# —— **导入期常量** ⟹ 任何只改 `JOBS_FILE` 的调用方（测试夹具 monkeypatch / 沙箱）仍会把
# 校验和写进**默认（生产）sidecar**，而 jobs.json 写在别处 ⟹ 生产 pair 被**单边改写** ⟹
# 下一次真跑必报 `checksum mismatch (tampered?)`，且 `expected` 指向一个**已被回收的临时文件**
# 的哈希 ⟹ 凭值无法定位（同型报警只能靠猜）。
# 端到端实测：跑一次 `test_cron_jobs.py`（10 passed）后，生产 sidecar 由 1edbf71b8360 变
# 7ff7e390d7c2，而生产 jobs.json 纹丝不动。改为**函数派生**后读写两侧永远同源。
# ⚠ 代码库内 `test_gk_node_guard.py` / 计划文档原以「它是导入期常量，必须 monkeypatch 模块属性」
#   为隔离纪律 —— 该纪律随本次修复**不再必要**（改 JOBS_FILE 一处即可）。
def _jobs_checksum_file():
    return JOBS_FILE + ".sha256"


_OUTPUT_RETENTION_DEFAULT = 50

def _jobs_checksum(path):
    """sha256 of file raw bytes (UTF-8, 与 _atomic_write 产出一致)."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def _prune_outputs(out_dir, keep):
    """Phase 7c B2: per-job 输出文件保留上限（Hermes keep N 模式，默认 50）。"""
    if keep <= 0: return
    try:
        files = sorted(
            (os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.endswith(".md")),
            key=os.path.getmtime,
        )
        for old in files[:-keep]:
            try: os.unlink(old)
            except OSError: pass
    except OSError:
        pass

# --- Cross-process file lock (Hermes pattern: RLock + fcntl/msvcrt) ---
_jobs_lock_state = threading.local()
_jobs_global_lock = threading.RLock()

class _FileLock:
    """Cross-process advisory file lock."""
    def __init__(self, path):
        self.path = path + ".lock"
        self._fd = None
    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._fd = open(self.path, "w")
        try:
            if os.name == "nt":
                import msvcrt; msvcrt.locking(self._fd.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl; fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            self._fd.close(); self._fd = None; raise
        return self
    def __exit__(self, *args):
        if self._fd:
            try:
                if os.name == "nt":
                    import msvcrt; msvcrt.locking(self._fd.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl; fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
                self._fd.close()
            except Exception: pass

def _jobs_lock():
    """Nested context manager: in-process RLock + cross-process file lock."""
    class _NestedLock:
        def __enter__(self):
            _jobs_global_lock.__enter__()
            depth = getattr(_jobs_lock_state, 'depth', 0)
            _jobs_lock_state.depth = depth + 1
            if depth == 0:
                _jobs_lock_state.file_lock = _FileLock(JOBS_FILE)
                _jobs_lock_state.file_lock.__enter__()
            return self
        def __exit__(self, *args):
            _jobs_lock_state.depth -= 1
            if _jobs_lock_state.depth == 0:
                _jobs_lock_state.file_lock.__exit__(*args)
            _jobs_global_lock.__exit__(*args)
    return _NestedLock()

# --- Atomic write (Hermes pattern: tempfile + rename + fsync) ---
def _atomic_write(path, data):
    """Atomic JSON write: tempfile → fsync → rename."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            f.flush(); os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try: os.unlink(tmp)
        except Exception: pass
        raise

def _secure_file(path, mode=0o600):
    """Set restrictive permissions (Hermes pattern)."""
    try: os.chmod(path, mode)
    except Exception: pass

def _secure_dir(path, mode=0o700):
    """Set restrictive directory permissions."""
    try: os.chmod(path, mode)
    except Exception: pass

# --- Prompt Injection Scanning (Hermes 3-layer) ---
# 模式表已迁至 gk_threat_patterns（单一来源，见文件头 import）。
def scan_prompt(prompt, strict=True):
    """3-layer prompt injection scan. strict=True for create, strict=False for runtime."""
    for pat in _THREAT_PATTERNS:
        if pat.search(prompt):
            if strict: return {"ok": False, "error": f"Blocked: threat pattern ({pat.pattern[:40]})"}
            else: prompt = pat.sub("[FILTERED]", prompt)
    for pat in _EXFIL_PATTERNS:
        if pat.search(prompt):
            if strict: return {"ok": False, "error": f"Blocked: exfil pattern ({pat.pattern[:40]})"}
            else: prompt = pat.sub("[FILTERED]", prompt)
    if _INVISIBLE_UNICODE.search(prompt):
        if strict: return {"ok": False, "error": "Blocked: invisible Unicode"}
        else: prompt = _INVISIBLE_UNICODE.sub("", prompt)
    return {"ok": True, "filtered": prompt}

def validate_script_path(script_path):
    """Script path sandbox — must be within SKILL_DIR/scripts/."""
    if not script_path: return {"ok": True}
    if ".." in script_path: return {"ok": False, "error": "Blocked: path traversal"}
    abs_path = os.path.abspath(script_path)
    allowed = os.path.join(SKILL_DIR, "scripts")
    if not abs_path.startswith(allowed): return {"ok": False, "error": f"Blocked: script must be in {allowed}"}
    if not os.path.exists(abs_path): return {"ok": False, "error": "Blocked: script not found"}
    return {"ok": True}

def _job_id_safe(job_id):
    """Reject path traversal in job ID (Hermes pattern)."""
    if ".." in job_id or "/" in job_id or "\\" in job_id or os.path.isabs(job_id):
        return False
    return bool(re.match(r"^[a-f0-9]{12}$", job_id))

# --- Storage ---
def ensure_dir():
    os.makedirs(JOBS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    _secure_dir(JOBS_DIR)
    _secure_dir(OUTPUT_DIR)

def load_jobs():
    ensure_dir()
    if not os.path.exists(JOBS_FILE): return []
    # Phase 7c A4 (2026-08-21): jobs.json 完整性校验（兑现 SKILL.md T7.3(B) 声称的 SHA256 校验）。
    # 非阻塞 WARN：校验失败仍加载，防止校验故障阻塞调度器（对齐 state checksum 的事后篡改检测哲学）。
    # 2026-09-20：① sidecar 路径改函数派生（原导入期常量会把校验和写错地方，见 _jobs_checksum_file）；
    #            ② WARN 补 `path=` —— 原文案不说是哪个文件，实测中它**不可定位**（只能靠猜）。
    ck = _jobs_checksum_file()
    if os.path.exists(ck):
        try:
            with open(ck) as f: expected = f.read().strip()
            actual = _jobs_checksum(JOBS_FILE)
            if expected and expected != actual:
                sys.stderr.write("WARN[cron_jobs]: jobs.json checksum mismatch (tampered? path=%s expected=%s actual=%s)\n" % (JOBS_FILE, expected[:12], actual[:12]))
        except Exception:
            pass
    try:
        with open(JOBS_FILE) as f: return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

def save_jobs(jobs):
    """Atomic save with file lock + checksum sidecar (Phase 7c A4)."""
    _atomic_write(JOBS_FILE, jobs)
    _secure_file(JOBS_FILE)
    try:
        ck = _jobs_checksum_file()
        with open(ck, "w") as f: f.write(_jobs_checksum(JOBS_FILE) + "\n")
        _secure_file(ck)
    except Exception:
        pass

# --- Schedule Parsing (4 formats: duration/interval/cron/ISO) ---
def parse_schedule(expr):
    expr = expr.strip()
    if "T" in expr and ("-" in expr[1:]):
        try:
            dt = datetime.datetime.fromisoformat(expr.replace("Z", ""))
            return {"kind": "once", "run_at": dt.isoformat()}
        except ValueError: pass
    m = re.match(r"^(\d+)([mhd])$", expr)
    if m:
        val, unit = int(m.group(1)), m.group(2)
        minutes = val * {"m": 1, "h": 60, "d": 1440}[unit]
        run_at = _utcnow() + datetime.timedelta(minutes=minutes)
        return {"kind": "once", "run_at": run_at.isoformat() + "Z", "minutes": minutes}
    m = re.match(r"^every\s+(\d+)([mhd])$", expr, re.IGNORECASE)
    if m:
        val, unit = int(m.group(1)), m.group(2)
        minutes = val * {"m": 1, "h": 60, "d": 1440}[unit]
        return {"kind": "interval", "minutes": minutes}
    fields = expr.split()
    if len(fields) == 5:
        return {"kind": "cron", "expr": expr}
    return None

def _cron_next(expr, base_time):
    """最小 cron next 计算器（2026-08-27 内置，替代 croniter——用户环境禁装 pip 包）。

    支持 5 字段: minute hour day-of-month month day-of-week。
    字段语法: * | */n | a-b | a,b,c | 数字。从 base_time 下一秒向后扫描（上限 5 年）。
    返回: datetime（UTC）或 None（无法匹配）。
    """
    def parse_field(field, lo, hi):
        """返回 set[int] 或 None（'*' 全量）→ 用 (lo,hi) 区间表示全通配。"""
        field = field.strip()
        if field == "*":
            return None  # 全通配
        out = set()
        for part in field.split(","):
            part = part.strip()
            step = 1
            if "/" in part:
                part, step_s = part.split("/", 1)
                step = int(step_s)
                if step < 1:
                    return None
            if part == "*":
                lo2, hi2 = lo, hi
            elif "-" in part:
                a, b = part.split("-", 1)
                lo2, hi2 = int(a), int(b)
            else:
                lo2 = hi2 = int(part)
            for v in range(lo2, hi2 + 1, step):
                if lo <= v <= hi:
                    out.add(v)
        return out

    try:
        parts = expr.split()
        if len(parts) != 5:
            return None
        f_min = parse_field(parts[0], 0, 59)
        f_hour = parse_field(parts[1], 0, 23)
        f_dom = parse_field(parts[2], 1, 31)
        f_mon = parse_field(parts[3], 1, 12)
        f_dow = parse_field(parts[4], 0, 6)
    except (ValueError, TypeError):
        return None

    base = base_time.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    for _ in range(5 * 365 * 24 * 60):
        if f_mon is not None and base.month not in f_mon:
            base = (base.replace(day=1) + datetime.timedelta(days=32)).replace(day=1, hour=0, minute=0)
            continue
        if f_dom is not None and base.day not in f_dom:
            base = (base + datetime.timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if f_dow is not None and ((base.weekday() + 1) % 7) not in f_dow:
            # cron DOW 0=Sunday..6=Saturday；Python weekday 0=Monday..6=Sunday
            # 转换: cron_dow = (python_weekday + 1) % 7（避免错位 1 天）
            base = (base + datetime.timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if f_hour is not None and base.hour not in f_hour:
            base = (base + datetime.timedelta(hours=1)).replace(minute=0)
            continue
        if f_min is not None and base.minute not in f_min:
            base = base + datetime.timedelta(minutes=1)
            continue
        return base
    return None


def compute_next_run(schedule, last_run_at=None, base_time=None):
    now = base_time or _utcnow()
    kind = schedule.get("kind")
    if kind == "once":
        run_at = schedule.get("run_at", "")
        if run_at:
            try: return datetime.datetime.fromisoformat(run_at.replace("Z", ""))
            except ValueError: return None
        return None
    if kind == "interval":
        minutes = schedule.get("minutes", 60)
        base = last_run_at or now
        if isinstance(base, str): base = datetime.datetime.fromisoformat(base.replace("Z", ""))
        return base + datetime.timedelta(minutes=minutes)
    if kind == "cron":
        base = last_run_at or now
        if isinstance(base, str): base = datetime.datetime.fromisoformat(base.replace("Z", ""))
        nxt = _cron_next(schedule["expr"], base)
        if nxt is not None:
            return nxt
        try:
            from croniter import croniter  # 兼容：若环境已装 croniter 则优先其完整语义
        except ImportError:
            return None
        # F-REV-94（2026-09-17，用户裁定「其他都同意」）：croniter 对**非法表达式抛 ValueError**
        #   （实测 `not a cron` → "Exactly 5, 6 or 7 columns has to be specified for iterator
        #   expression"）。本函数契约是「不可算 → None」，让异常逃逸会被 `get_due_jobs` 的
        #   per-job 兜底吞成通用 WARN，job 的 `state` / `last_error` 反而**停在旧值**
        #   ⟹ 归因失真（测试 `TestCronErrorStateRecovery` 首次运行即暴露此点）。
        try:
            return croniter(schedule["expr"], base).get_next(datetime.datetime)
        except Exception:
            return None
    return None

def _compute_grace_seconds(job):
    schedule = job.get("schedule", {})
    kind = schedule.get("kind")
    if kind == "interval":
        minutes = schedule.get("minutes", 60)
        grace = minutes * 60 / 2
    elif kind == "cron":
        now = _utcnow()
        nxt = _cron_next(schedule.get("expr", "0 * * * *"), now)
        if nxt is None:
            try:
                from croniter import croniter
                nxt = croniter(schedule.get("expr", "0 * * * *"), now).get_next(datetime.datetime)
            except Exception: nxt = None
        grace = (nxt - now).total_seconds() / 2 if nxt else 3600
    elif kind == "once": return ONESHOT_GRACE_SECONDS
    else: grace = 3600
    return max(120, min(7200, grace))

# --- Job State Machine (Hermes: scheduled/paused/completed/error) ---
def _get_state(job):
    return job.get("state", "scheduled")

def _set_state(job, state):
    job["state"] = state
    if state == "paused":
        job["paused_at"] = _utcnow().isoformat() + "Z"

# --- CRUD ---
def get_due_jobs():
    with _jobs_lock():
        jobs = load_jobs()
        now = _utcnow()
        due = []
        dirty = False
        for job in jobs:
            # Phase 7c A3 (2026-08-21): per-job 容错——单条坏记录只跳过自身，不拖垮整个 tick
            try:
                # F-REV-94（2026-09-17，用户裁定「其他都同意」）：`error` **不是终态**。
                #   原 `not in ("scheduled",)` ⟹ 一旦置 error（唯一置 error 的路径 = "schedule not
                #   computable"）就**永不恢复**，即便根因早已消除（本项目 2026-08-27 起内置
                #   `_cron_next`（见 `compute_next_run`），已**不再依赖 croniter**）。
                #   实测：`release-check`（`0 9 * * *`）自 2026-08-23 起恒 `state=error`、
                #   `next_run_at` 冻在 `2026-08-22T09:00:00Z`，`tick.log` 每小时**静默跳过**
                #   ⟹ 外循环 release-check 长期未触发（I7 语义失效）。
                #   ⚠ 只放行 `error`（= **可自愈的调度面故障**）；`paused` / `completed` 是用户或
                #   设计意图的终态，**不得复活**。
                if _get_state(job) not in ("scheduled", "error"): continue
                if not job.get("enabled", True): continue
                next_run = job.get("next_run_at")
                if not next_run:
                    # Auto-recover missing next_run_at
                    nr = compute_next_run(job.get("schedule", {}))
                    if nr:
                        job["next_run_at"] = nr.isoformat() + "Z"
                        # F-REV-94：算出下一轮 ⟹ `error` 自愈回 `scheduled`（否则永远是"已算得出却仍
                        #   标 error"的矛盾态；清空 last_error 以免陈旧归因误导排查）。
                        if _get_state(job) == "error":
                            _set_state(job, "scheduled")
                            job["last_error"] = ""
                        dirty = True
                    else:
                        # Phase 7c A2 (2026-08-21): 周期作业无法计算下一运行 → 显式 error + 保持
                        # enabled，绝不静默卡死（Hermes jobs.py 2580-2594 语义）。
                        # F-REV-94：错误文案**去掉 croniter 诱导**——内置 `_cron_next` 已覆盖 5 字段
                        # 语法，走到这里只可能是表达式本身非法；原文案会把人引向"装 croniter"，而
                        # 用户环境**禁装 pip 包**（且装了也修不了非法表达式）。
                        job["state"] = "error"
                        job["last_error"] = "schedule not computable (unsupported cron expr?)"
                        dirty = True
                    continue
                try:
                    next_dt = datetime.datetime.fromisoformat(next_run.replace("Z", ""))
                except (ValueError, TypeError):
                    job["state"] = "error"
                    job["last_error"] = "bad next_run_at: %r" % (next_run,)
                    dirty = True
                    continue
                if next_dt <= now:
                    grace = _compute_grace_seconds(job)
                    if grace and (now - next_dt).total_seconds() > grace:
                        # Phase 7c A1 (2026-08-21): Hermes 追赶语义——补跑一次 + fast-forward，
                        # 替代旧的"超宽限期直接跳过"（曾致 key-rotate-check/release-check 永不触发）。
                        # 仅在 fast-forward 成功（时间已到未来）时推进；oneshot 不推进（跑完即完成）。
                        kind = job.get("schedule", {}).get("kind")
                        if kind in ("interval", "cron"):
                            ff = compute_next_run(job.get("schedule", {}), None, base_time=now)
                            if ff and ff > now:
                                job["next_run_at"] = ff.isoformat() + "Z"
                                # F-REV-94：fast-forward 成功即证明**调度可计算** ⟹ `error` 自愈。
                                if _get_state(job) == "error":
                                    _set_state(job, "scheduled")
                                    job["last_error"] = ""
                                dirty = True
                        due.append(job)
                        continue
                    due.append(job)
            except Exception as e:
                sys.stderr.write("WARN[cron_jobs]: skipping broken job %s: %s\n" % (job.get("id", "?"), e))
                continue
        if dirty:
            save_jobs(jobs)
        return due

def advance_next_run(job):
    with _jobs_lock():
        schedule = job.get("schedule", {})
        last_run = job.get("last_run_at")
        next_run = compute_next_run(schedule, last_run)
        if next_run: job["next_run_at"] = next_run.isoformat() + "Z"
        jobs = load_jobs()
        for j in jobs:
            if j.get("id") == job.get("id"):
                j["next_run_at"] = job["next_run_at"]
                break
        save_jobs(jobs)

def mark_job_run(job_id, status, output="", error=""):
    with _jobs_lock():
        jobs = load_jobs()
        now = _utcnow().isoformat() + "Z"
        for job in jobs:
            if job.get("id") == job_id:
                job["last_run_at"] = now
                job["last_status"] = status
                job["last_error"] = error[:500]
                job["run_count"] = job.get("run_count", 0) + 1
                # Phase 7c B1 (2026-08-21): failure_streak 连续失败追踪（Hermes jobs.py 2511-2519）
                if status == "ok":
                    job["failure_streak"] = 0
                else:
                    job["failure_streak"] = job.get("failure_streak", 0) + 1
                # Output to file (Hermes pattern) + Phase 7c B2 保留上限
                out_dir = os.path.join(OUTPUT_DIR, job_id)
                os.makedirs(out_dir, exist_ok=True)
                out_file = os.path.join(out_dir, f"{now.replace(':','-')}.md")
                with open(out_file, "w") as f: f.write(output[:10000])
                job["last_output_file"] = out_file
                _prune_outputs(out_dir, job.get("output_retention", _OUTPUT_RETENTION_DEFAULT))
                schedule = job.get("schedule", {})
                kind = schedule.get("kind")
                if kind == "once":
                    _set_state(job, "completed"); job["enabled"] = False
                else:
                    next_run = compute_next_run(schedule, now)
                    if next_run:
                        job["next_run_at"] = next_run.isoformat() + "Z"
                    else:
                        # Phase 7c A2: 周期作业无法计算下一运行 → error + 保持 enabled
                        # F-REV-94：文案去 croniter 诱导（同 get_due_jobs 处注记）。
                        job["state"] = "error"
                        job["last_error"] = "next run not computable (unsupported cron expr?)"
                # repeat counter
                repeat = job.get("repeat")
                if repeat:
                    repeat["completed"] = repeat.get("completed", 0) + 1
                    if repeat.get("times") and repeat["completed"] >= repeat["times"]:
                        _set_state(job, "completed"); job["enabled"] = False
                break
        save_jobs(jobs)

def create_job(name, prompt, schedule_expr, **kwargs):
    scan = scan_prompt(prompt, strict=True)
    if not scan["ok"]: return {"ok": False, "error": scan["error"]}
    script = kwargs.get("script", "")
    if script:
        sandbox = validate_script_path(script)
        if not sandbox["ok"]: return {"ok": False, "error": sandbox["error"]}
    schedule = parse_schedule(schedule_expr)
    if not schedule: return {"ok": False, "error": f"Invalid schedule: {schedule_expr}"}
    job_id = hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:12]
    if not _job_id_safe(job_id): return {"ok": False, "error": "Invalid job ID generated"}
    next_run = compute_next_run(schedule)
    repeat = kwargs.pop("repeat", None)
    job = {
        "id": job_id, "name": name, "prompt": prompt, "schedule": schedule,
        "schedule_display": schedule_expr,
        "next_run_at": next_run.isoformat() + "Z" if next_run else None,
        "enabled": True, "state": "scheduled",
        "created_at": _utcnow().isoformat() + "Z",
        "last_run_at": None, "last_status": None, "last_output_file": "", "last_error": "",
        "last_delivery_error": "", "run_count": 0, "failure_streak": 0,
        "deliver": kwargs.get("deliver", "local"),
        "script": script, "no_agent": kwargs.get("no_agent", False),
        "context_from": kwargs.get("context_from", ""),
        "workdir": kwargs.get("workdir", ""),
        "repeat": {"times": repeat, "completed": 0} if repeat else None,
        **{k: v for k, v in kwargs.items() if k not in ("deliver", "script", "no_agent", "context_from", "workdir", "repeat")}
    }
    with _jobs_lock():
        jobs = load_jobs()
        jobs.append(job)
        save_jobs(jobs)
    return {"ok": True, "job": job}

def list_jobs():
    return {"ok": True, "jobs": load_jobs()}

def resolve_job_ref(ref):
    """Resolve job by ID or name (Hermes pattern)."""
    jobs = load_jobs()
    # Try ID first
    by_id = [j for j in jobs if j.get("id") == ref]
    if len(by_id) == 1: return by_id[0]
    # Try name (case-insensitive)
    by_name = [j for j in jobs if j.get("name", "").lower() == ref.lower()]
    if len(by_name) == 1: return by_name[0]
    if len(by_name) > 1: return {"error": f"Ambiguous: {len(by_name)} jobs named '{ref}'"}
    return None

def _schedule_display(schedule, raw=""):
    """`schedule_display` 派生（E2 配套，2026-09-18）。

    `create_job` 的 display = **用户原始输入串逐字回显**（实测 `every 24h` / `every 7d` 均按输入
    形态留存，非按分钟反推）⟹ 本函数优先回显 `raw`；仅当更新以 dict 形态给出（原始串不可得）
    时按 kind 派生。非 schedule 字段更新不得改本字段。
    """
    if raw:
        return raw
    if not isinstance(schedule, dict):
        return str(schedule)
    kind = schedule.get("kind")
    if kind == "cron":
        return schedule.get("expr", "")
    if kind == "interval":
        return "every %dm" % schedule.get("minutes", 60)
    if kind == "once":
        return schedule.get("run_at", "")
    return str(kind or "")


def update_job(job_id, **updates):
    """Update job fields (protect immutable fields)."""
    _IMMUTABLE = frozenset({"id", "created_at"})
    with _jobs_lock():
        jobs = load_jobs()
        for job in jobs:
            if job.get("id") == job_id:
                for k, v in updates.items():
                    if k in _IMMUTABLE: continue
                    if k == "prompt":
                        scan = scan_prompt(v, strict=True)
                        if not scan["ok"]: return {"ok": False, "error": scan["error"]}
                    if k == "script" and v:
                        sandbox = validate_script_path(v)
                        if not sandbox["ok"]: return {"ok": False, "error": sandbox["error"]}
                    # E2（ECC-03BA0B44DF91，2026-09-18）：`schedule` 由 CLI `cron edit` 以**字符串**
                    # 形态传入（`**{'schedule': '$value'}`）⟹ 原实现直接赋值后 `compute_next_run`
                    # 立刻 `AttributeError: 'str' object has no attribute 'get'`（实测 rc=1、job 未改
                    # ⟹ 定时表达式无法经 CLI 修改）。此处按 `parse_schedule` 归一（与 `cron create`
                    # 同一单源）；非法表达式 / 非法类型**显式拒绝且不落盘**（不静默写坏账）。
                    if k == "schedule":
                        if isinstance(v, str):
                            parsed = parse_schedule(v)
                            if not parsed:
                                return {"ok": False, "error": "invalid schedule expr: %r" % (v,)}
                            v = parsed
                        elif not isinstance(v, dict):
                            return {"ok": False,
                                    "error": "schedule must be dict or expr string, got %s" % type(v).__name__}
                    job[k] = v
                if "schedule" in updates:
                    nr = compute_next_run(job["schedule"])
                    if nr: job["next_run_at"] = nr.isoformat() + "Z"
                    # E2 配套：display 是派生字段，改 schedule 必须同步（否则台账自相矛盾 ——
                    # 实测 `cron edit … '49 18 * * *'` 后 expr 已变而 display 仍 `0 18 * * *`）。
                    job["schedule_display"] = _schedule_display(
                        job["schedule"],
                        raw=(updates["schedule"] if isinstance(updates["schedule"], str) else ""))
                save_jobs(jobs)
                return {"ok": True, "job": job}
    return {"ok": False, "error": "Job not found"}

def remove_job(ref):
    job = resolve_job_ref(ref) if not _job_id_safe(ref) else None
    job_id = ref if _job_id_safe(ref) else (job.get("id") if job and isinstance(job, dict) and "id" in job else None)
    if not job_id: return {"ok": False, "error": "Job not found"}
    with _jobs_lock():
        jobs = load_jobs()
        before = len(jobs)
        jobs = [j for j in jobs if j.get("id") != job_id]
        save_jobs(jobs)
        # Clean output dir
        out_dir = os.path.join(OUTPUT_DIR, job_id)
        if os.path.isdir(out_dir): shutil.rmtree(out_dir, ignore_errors=True)
        return {"ok": len(jobs) < before, "removed": before - len(jobs)}

def enable_job(ref, enabled=True):
    job = resolve_job_ref(ref) if not _job_id_safe(ref) else None
    job_id = ref if _job_id_safe(ref) else (job.get("id") if job and isinstance(job, dict) and "id" in job else None)
    if not job_id: return {"ok": False, "error": "Job not found"}
    with _jobs_lock():
        jobs = load_jobs()
        for job in jobs:
            if job.get("id") == job_id:
                job["enabled"] = enabled
                if enabled:
                    _set_state(job, "scheduled")
                    if not job.get("next_run_at"):
                        nr = compute_next_run(job.get("schedule", {}))
                        if nr: job["next_run_at"] = nr.isoformat() + "Z"
                else:
                    _set_state(job, "paused")
                    job["paused_at"] = _utcnow().isoformat() + "Z"
                save_jobs(jobs)
                return {"ok": True, "enabled": enabled, "state": _get_state(job)}
    return {"ok": False, "error": "Job not found"}

def trigger_job(ref):
    """Set next_run_at=now for immediate execution (Hermes trigger_job)."""
    job = resolve_job_ref(ref) if not _job_id_safe(ref) else None
    job_id = ref if _job_id_safe(ref) else (job.get("id") if job and isinstance(job, dict) and "id" in job else None)
    if not job_id: return {"ok": False, "error": "Job not found"}
    with _jobs_lock():
        jobs = load_jobs()
        for job in jobs:
            if job.get("id") == job_id:
                job["next_run_at"] = _utcnow().isoformat() + "Z"
                if _get_state(job) == "paused": _set_state(job, "scheduled"); job["enabled"] = True
                save_jobs(jobs)
                return {"ok": True, "triggered": job_id}
    return {"ok": False, "error": "Job not found"}

# --- Wake Gate (Hermes: parse last line of script output) ---
def parse_wake_gate(output):
    """Parse wake gate from script output. Returns (should_run_agent, cleaned_output)."""
    lines = output.strip().split("\n")
    if not lines: return True, output
    last = lines[-1].strip()
    try:
        parsed = json.loads(last)
        if isinstance(parsed, dict) and "wakeAgent" in parsed:
            return parsed["wakeAgent"], "\n".join(lines[:-1]).strip()
    except Exception: pass
    return True, output

# --- context_from (cross-task data pipeline) ---
def resolve_context_from(context_from):
    """Resolve context_from reference: inject other job's latest output."""
    if not context_from: return ""
    # Reload to get latest state
    job = None
    jobs = load_jobs()
    for j in jobs:
        if j.get("name","").lower() == context_from.lower() or j.get("id") == context_from:
            job = j; break
    if not job: return ""
    out_file = job.get("last_output_file", "")
    if out_file and os.path.exists(out_file):
        with open(out_file) as f: return f.read()[:4000]
    return ""

# --- CLI interface ---
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action")
    sub.add_parser("list")
    sub.add_parser("status")
    c = sub.add_parser("create"); c.add_argument("name"); c.add_argument("schedule"); c.add_argument("prompt")
    c.add_argument("--script", default=""); c.add_argument("--no-agent", action="store_true")
    r = sub.add_parser("remove"); r.add_argument("ref")
    e = sub.add_parser("enable"); e.add_argument("ref")
    d = sub.add_parser("disable"); d.add_argument("ref")
    t = sub.add_parser("trigger"); t.add_argument("ref")
    # B6（2026-10-27，RED-MIGRATE-INLINE）：取代 gatekeeper-cli.sh 的内联选片/投影薄壳
    g = sub.add_parser("get"); g.add_argument("ref")
    pr = sub.add_parser("prompt"); pr.add_argument("ref")
    ed = sub.add_parser("edit"); ed.add_argument("ref"); ed.add_argument("field")
    ed.add_argument("value")
    args = p.parse_args()
    if args.action == "list": print(json.dumps(list_jobs(), indent=2, default=str))
    elif args.action == "status":
        jobs = load_jobs()
        enabled = sum(1 for j in jobs if j.get("enabled"))
        print(json.dumps({"ok": True, "total": len(jobs), "enabled": enabled,
                          "jobs": [{"id": j["id"], "name": j["name"],
                                    "enabled": j.get("enabled"),
                                    "next_run": j.get("next_run_at"),
                                    "last_status": j.get("last_status")}
                                   for j in jobs]}, indent=2, default=str))
    elif args.action == "create":
        print(json.dumps(create_job(args.name, args.prompt, args.schedule,
                                    script=args.script, no_agent=args.no_agent),
                         indent=2, default=str))
    elif args.action == "remove": print(json.dumps(remove_job(args.ref), indent=2))
    elif args.action == "enable": print(json.dumps(enable_job(args.ref, True), indent=2))
    elif args.action == "disable": print(json.dumps(enable_job(args.ref, False), indent=2))
    elif args.action == "trigger": print(json.dumps(trigger_job(args.ref), indent=2))
    elif args.action == "get":
        job = next((j for j in load_jobs() if j.get("id") == args.ref), None)
        if job:
            print(json.dumps({"prompt": job.get("prompt", ""),
                              "script": job.get("script", ""),
                              "no_agent": bool(job.get("no_agent"))},
                             ensure_ascii=False))
    elif args.action == "prompt":
        job = next((j for j in load_jobs() if j.get("id") == args.ref), None)
        print(job.get("prompt", "") if job else "")
    elif args.action == "edit":
        job = resolve_job_ref(args.ref)
        if not job or (isinstance(job, dict) and "error" in job):
            print(json.dumps({"ok": False, "error": "Job not found"}))
        else:
            print(json.dumps(update_job(job["id"], **{args.field: args.value}),
                             indent=2, default=str))
    else: p.print_help()
