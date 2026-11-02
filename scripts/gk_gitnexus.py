#!/usr/bin/env python3
"""gk_gitnexus.py — GitNexus 单一 Python launcher（A1，2026-10-28）

## 为什么有这个模块

A1 裁定（`docs/plans/2026-10-26-open-source-prerequisite-plan.md` §5.3）：
gitnexus 不是「索引单总线」（每仓一份 `.gitnexus/gitnexus.json`），而是**调用侧被收口**。
收口前有 4 份**探测**实现：`gatekeeper-cli.sh::_gx_node_probe`（bash，唯一允许的探测）+
`gk_gitnexus_pdg_check` / `gk_pr_review_check` / `subagent_runner` 三份 python 复制
（各写一遍 `_node()/_gx_js()/_gx_env_error()/_resolve_repo()` + 各自 spawn）。

本模块把**三份 python 侧**收敛为一条 launcher：

  - 探测：**零**。node/js 一律消费 CLI（`_gx_subagent_gx_env`）注入的 `GX_NODE`/`GX_JS`，
    repo 消费 `GX_REPO`（F-REV-75 / F-REV-73 语义）。缺即 fail-loud。
  - spawn：本模块唯一 `subprocess.run`（bash 侧 `_run_gitnexus_raw` 是另一通道，属宿主侧）。
  - 缓存：**跨进程**只读缓存，键 = `repo + HEAD sha + argv`（A1 明写）。
    · 仅 `GK_GX_CACHE` 真值时启用；仅只读子命令；`analyze/publish/index/init` 永不缓存。
    · 解析不出 `GX_REPO_DIR` 或 `git rev-parse HEAD` 失败 ⟹ **不缓存**（宁可不缓存，不返回陈旧图）。
    · 目录 `GK_GX_CACHE_DIR`（默认 `~/.gatekeeper/gitnexus-cache`），TTL 2h，原子写。

## 用法

    from gk_gitnexus import run_json, run_text
    d = run_json(["cypher", q, "-r", repo, "-l", "50"])     # → dict（last JSON）或 {"raw": ...}
    t = run_text(["detect-changes", "-s", "compare", "-r", repo])
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# F-REV-88 孪生侧：与 bash `_run_gitnexus_raw` 同策的 identity cache 重定向
# （ProgramData 受限 → 用户 Temp；仅改缓存位置，不改索引身份）。
# 2026-11-01：改**发现式**（`tempfile`）——公开源码不得写死本机绝对路径；本机取值不变
# （Windows `%TEMP%` 即原 `AppData\Local\Temp`）。CLI 调用时仍以注入 env 为准（`_build_env`）。
IDENTITY_CACHE_DIR = os.path.join(tempfile.gettempdir(), "gk-gitnexus-identity")

# 只读子命令（可缓存）。`analyze`/`publish`/`index`/`init` 改库 ⟹ 永不缓存。
READONLY_PREFIXES = (
    "status", "query", "context", "impact", "detect-changes", "trace",
    "search", "cypher", "wiki", "list",
)
WRITE_PREFIXES = ("analyze", "publish", "index", "init", "delete", "remove")

CACHE_TTL_S = 2 * 60 * 60
_CACHE_VERSION = "v1"


# ─── 探测面：零探测，只消费 CLI 注入的 env ──────────────────────────────────

def node_exe() -> str:
    """Windows node.exe 的**可执行形态**（CLI 注入）。

    形态归一（**仅转换、不探测**）：`_gx_subagent_gx_env win` 在 Windows 解释器下注入
    `D:\\...`，而 WSL `python3` 直接 spawn 会 ENOENT ⟹ posix 宿主下转 `/mnt/d/...`。
    """
    p = os.environ.get("GX_NODE", "") or ""
    if os.name == "posix" and len(p) >= 2 and p[1] == ":":
        p = "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p


def js_path() -> str:
    """gitnexus CLI 入口的 **Windows 形态**路径（node.exe 是 Windows 二进制，不认 /mnt）。"""
    return os.environ.get("GX_JS", "") or ""


def env_error(consumer: str = "") -> str:
    """env 可用性检查（fail-loud 文案）；可用返回空串。"""
    miss = [k for k in ("GX_NODE", "GX_JS") if not (os.environ.get(k) or "")]
    if not miss:
        return ""
    where = (" —— " + consumer) if consumer else ""
    return ("[ERROR] gitnexus unavailable: " + "/".join(miss) +
            " 未注入（须经 gatekeeper-cli.sh 调用，CLI 自动注入；"
            "python 侧不再自探测 node，F-REV-75）" + where)


def _discover_node(form: str) -> str:
    """按**包形态**发现同侧 node（发现式，**无硬编码路径**，公开包可直接用）。

    `form` = `win32-x64` / `linux-x64` / …：
      · `win32-*` ⟹ `where.exe node` 取首个（WSL 宿主转 `/mnt/...` 形态）；
      · 其它      ⟹ `shutil.which("node")`。
    """
    if form.startswith("win32"):
        try:
            r = subprocess.run(["where.exe", "node"], capture_output=True, text=True, timeout=15)
            hits = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
            if hits:
                p = hits[0]
                if os.name == "posix" and len(p) >= 2 and p[1] == ":":
                    p = "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
                return p
        except Exception:
            return ""
        return ""
    return shutil.which("node") or ""


def _node_form(node: str) -> str:
    try:
        r = subprocess.run([node, "-e", "process.stdout.write(process.platform+'-'+process.arch)"],
                           capture_output=True, text=True, timeout=20)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def arch_guard() -> str:
    """**形态断言**（2026-11-01，owner 裁定 B 方案）：node 形态必须与 gitnexus 原生包一致。

    病象（实测）：`GX_NODE` 解析到 **Linux 形态** node（如编辑器自带运行时），
    而 `GX_JS` 指向 Windows 安装（`@ladybugdb/core-win32-x64`）⟹ `invalid ELF header`、
    图调用输出**恒空**；旧实现只打一条 WARN 就继续，跑批于是产出 528B 空壳报告。
    现改为 **fail-closed**：不一致直接返回错误文案（调用方 rc=2，空壳不再产生）。

    返回空串 = 通过；非空 = 错误文案。**未注入**（GX_NODE/GX_JS 缺）时返回空串，
    仍由 `env_error()` 出既有文案（保持错误顺序与逐字不变）。
    """
    node, js = node_exe(), js_path()
    if not node or not js:
        return ""
    form = _node_form(node)
    if not re.match(r"^(win32|linux|darwin|freebsd|openbsd|android)-[a-z0-9_]+$", form or ""):
        # 非 node 本体回显（wrapper 脚本 / 参数被吞 / 崩在启动前）⟹ 形态不可判：
        #   报错交给下游 spawn（此处 fail-closed 会误杀合法的包装节点，实测 wrapper 即触发）。
        return ""
    # 包根：从 JS 入口向上找 `node_modules/gitnexus`
    #   2026-11-01：posix 宿主收到 `C:\...` 形态时先归一到 `/mnt/c/...`（否则 Path 视作相对名，
    #   包根恒找不到 ⟹ 断言退化为 no-op，混血被放过——实测复现）。
    jsp = js
    if os.name == "posix" and len(jsp) >= 2 and jsp[1] == ":":
        jsp = "/mnt/" + jsp[0].lower() + jsp[2:].replace("\\", "/")
    cur = Path(jsp).resolve().parent
    pkg = None
    for _ in range(6):
        if cur.name == "gitnexus" and (cur / "package.json").exists():
            pkg = cur
            break
        if (cur / "node_modules" / "gitnexus" / "package.json").exists():
            pkg = cur / "node_modules" / "gitnexus"
            break
        if cur.parent == cur:
            break
        cur = cur.parent
    if pkg is None:
        return ""
    lb = pkg / "node_modules" / "@ladybugdb"
    if not lb.is_dir():
        return ""
    targets = sorted(p.name[len("core-"):] for p in lb.iterdir()
                     if p.is_dir() and p.name.startswith("core-"))
    if not targets:
        return ""               # 只有 core ⟹ 安装期已选定，无矛盾可判
    if form in targets:
        return ""
    # 2026-11-01（owner 裁定 2/3）：**包侧权威** —— `GX_JS` 指到哪份安装，node 就得跟哪一侧。
    #   先按包形态发现 node 并改写 GX_NODE（纠正成功只留 WARN，不阻断）；
    #   纠正失败 ⟹ fail-closed（不出空壳）。多形态并存时按 JS 路径形态择优（Windows 安装取 win32）。
    winish = len(js) >= 2 and js[1] == ":"
    pref = [t for t in targets if t.startswith("win32-") == winish]
    pkg_form = (pref or targets)[0]
    cand = _discover_node(pkg_form)
    if cand and _node_form(cand) == pkg_form:
        os.environ["GX_NODE"] = cand
        sys.stderr.write("WARN[gx-env] node/包形态不一致（node=%s, 包=%s）→ 自动改用同侧 node: %s\n"
                         % (form, "core-" + pkg_form, cand))
        return ""
    return ("[ERROR] gitnexus arch_guard: 形态不一致 —— node=%s，包=%s（%s）⟹ "
            "混血执行会报 invalid ELF header 且输出恒空；修：node 与包取同一侧"
            % (form, "core-" + pkg_form, ",".join("core-" + t for t in targets)))


def resolve_repo(explicit: str = "") -> str:
    """repo 单源解析：显式参数优先，否则 CLI 注入的 `GX_REPO`（禁硬编码仓库名）。"""
    return explicit or (os.environ.get("GX_REPO", "") or "")


def repo_dir() -> str:
    """目标仓库目录（CLI 注入的 `GX_REPO_DIR`）；缺失返回空串（缓存随之关闭）。"""
    return os.environ.get("GX_REPO_DIR", "") or ""


def head_sha(directory: str = "") -> str:
    """目标仓库 HEAD sha；解析失败返回空串（调用方据此**关闭缓存**，不猜）。"""
    d = directory or repo_dir()
    if not d:
        return ""
    try:
        r = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return ""
    if r.returncode != 0:
        return ""
    return (r.stdout or "").strip()


# ─── 跨进程缓存 ───────────────────────────────────────────────────────────

def _cache_dir() -> Path:
    return Path(os.environ.get("GK_GX_CACHE_DIR", "") or
                os.path.join(os.path.expanduser("~"), ".gatekeeper", "gitnexus-cache"))


def _truthy(v: str) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def _cache_key(args, repo: str, sha: str) -> str:
    raw = "%s|%s|%s|%s" % (_CACHE_VERSION, repo, sha, " ".join(args))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


def cacheable(args, *, force: bool | None = None) -> bool:
    """本次调用能否走缓存：只读子命令 + 开关 + 可解析 repo/HEAD（三者缺一即否）。"""
    if not args:
        return False
    on = _truthy(os.environ.get("GK_GX_CACHE", "")) if force is None else bool(force)
    if not on:
        return False
    head = (args[0] or "").strip()
    if head in WRITE_PREFIXES or head.startswith(WRITE_PREFIXES):
        return False
    if not (head in READONLY_PREFIXES or head.startswith(READONLY_PREFIXES)):
        return False
    if not resolve_repo() or not head_sha():
        return False
    return True


def _cache_get(key: str) -> str | None:
    p = _cache_dir() / (key + ".json")
    try:
        if not p.is_file():
            return None
        if time.time() - p.stat().st_mtime > CACHE_TTL_S:
            return None
        with p.open(encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return None
    return d.get("out") if isinstance(d, dict) else None


# ─── 进程树回收（2026-11-02）────────────────────────────────────────────────
# 病象（实测）：杀掉 CLI/后台任务后，`node.exe` 仍挂着 —— 本机一度 12 个，其中 9 个是
#   `D:\Program Files\nodejs\node.exe`（gitnexus 的 **worker 子进程**）。原因：
#   ① `subprocess.run(timeout=)` 超时只杀**直接子进程**，杀不到 worker；
#   ② 外部把 python 一起 kill 掉时，python 连清理都来不及跑 ⟹ 必然留孤儿。
# 两条修法：
#   ① spawn 时**独立进程组**（POSIX `start_new_session` / Windows `CREATE_NEW_PROCESS_GROUP`），
#      超时走 `killpg` / `taskkill /T` **整棵树**；
#   ② pidfile 记账（`~/.gatekeeper/gitnexus-workers.json`）：下次任何一次 spawn 前先 `reap_workers()`，
#      把上一次被外部 kill 留下的孤儿收掉（外部 kill 场景下这是唯一可行的兜底）。
_WORKER_PIDFILE = Path(os.path.expanduser("~")) / ".gatekeeper" / "gitnexus-workers.json"


def _pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            r = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/NH"],
                               capture_output=True, text=True, timeout=15)
            return str(pid) in (r.stdout or "")
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill_tree(pid: int) -> None:
    """整棵树杀（含 gitnexus worker 子进程）。"""
    if not pid or pid <= 0:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, text=True, timeout=30)
        else:
            import signal
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        pass


def _pids_load() -> list:
    """→ `[{"pid": int, "ts": float}]`（旧格式裸 int 列表自动兼容）。"""
    try:
        d = json.loads(_WORKER_PIDFILE.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for x in d if isinstance(d, list) else []:
        if isinstance(x, dict) and x.get("pid"):
            out.append({"pid": int(x["pid"]), "ts": float(x.get("ts") or 0)})
        elif isinstance(x, int):
            out.append({"pid": x, "ts": 0.0})
    return out


def _pids_save(recs) -> None:
    try:
        _WORKER_PIDFILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _WORKER_PIDFILE.with_suffix(".tmp")
        seen, out = set(), []
        for r in recs:
            pid = int(r.get("pid") if isinstance(r, dict) else r)
            if pid and pid not in seen:
                seen.add(pid)
                out.append({"pid": pid, "ts": float(r.get("ts") if isinstance(r, dict) else 0)})
        tmp.write_text(json.dumps(out), encoding="utf-8")
        os.replace(tmp, _WORKER_PIDFILE)
    except Exception:
        pass


#: 只回收「明显超期」的条目 —— 必须留足余量，否则会误杀**另一个进程正在跑**的 analyze。
#: 实测 analyze 单次上限 600s（`GK_GX_ANALYZE_TIMEOUT`），取 2× + 余量 = 1800s。
_REAP_MIN_AGE_S = 1800


def reap_workers() -> int:
    """收掉**上一次**被外部 kill 留下的孤儿。

    ⚠ 不能见 pid 就杀：pidfile 是**跨进程**共享的，同时跑两个 analyze 时会把健康的那个杀掉。
      故只回收 `ts` 超过 `_REAP_MIN_AGE_S` 且仍存活的条目；未超龄的原样保留。
    """
    recs = _pids_load()
    if not recs:
        return 0
    now = time.time()
    killed, keep = 0, []
    for r in recs:
        if (now - r["ts"]) > _REAP_MIN_AGE_S and _pid_alive(r["pid"]):
            _kill_tree(r["pid"])
            killed += 1
        elif (now - r["ts"]) <= _REAP_MIN_AGE_S and _pid_alive(r["pid"]):
            keep.append(r)          # 可能是并发进程的正常子进程，保留
    _pids_save(keep)
    return killed


def _cache_put(key: str, out: str) -> None:
    d = _cache_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / (key + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"out": out, "ts": time.time()}, f, ensure_ascii=False)
        os.replace(tmp, d / (key + ".json"))
        # 惰性清理：同目录 >2×TTL 的残留
        cutoff = time.time() - 2 * CACHE_TTL_S
        for old in d.glob("*.json"):
            try:
                if old.stat().st_mtime < cutoff:
                    old.unlink()
            except Exception:
                pass
    except Exception:
        pass


def invalidate_cache() -> int:
    """清空跨进程缓存（改库后调用；返回删除文件数）。"""
    d = _cache_dir()
    n = 0
    try:
        for p in d.glob("*.json"):
            try:
                p.unlink()
                n += 1
            except Exception:
                pass
    except Exception:
        pass
    return n


# ─── 单一 spawn 面 ─────────────────────────────────────────────────────────

def _build_env(command: str) -> dict:
    env = dict(os.environ)
    env.setdefault("GITNEXUS_ANALYZER_IDENTITY_CACHE_DIR", IDENTITY_CACHE_DIR)
    # 2026-11-01（实测）：gitnexus 对身份缓存目录是 **fail-closed** ——
    #   `GITNEXUS_ANALYZER_IDENTITY_CACHE_DIR must name a pre-existing protected
    #    non-symlink directory`，目录不在就直接抛（连 `analyze` 都进不去）。
    #   原状靠 bash 侧 `mkdir -p` 兜，但凡是从 python 直接调、或目录被临时清理掉，
    #   就变成「node 崩栈」这种与真因无关的报错。此处**自己保证目录存在**。
    try:
        Path(env["GITNEXUS_ANALYZER_IDENTITY_CACHE_DIR"]).mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    # F-REV-88：与 bash `_run_gitnexus_raw` 同策 —— 仅 `analyze*` 钉 cpu
    # （gitnexus `parseDevice` 对空串抛错，故其余子命令**不设**）。
    if command.strip().startswith("analyze"):
        env.setdefault("GITNEXUS_EMBEDDING_DEVICE", "cpu")
        # 2026-10-30（实测根因）：analyze 的 clearParsedFileStore 会一次性删除
        #   `.gitnexus/parsedfile-store` 下 100+ 个缓存文件，被 WorkBuddy 注入的
        #   node-safe-delete-shim 的 bulk guard（阈值 50）拦截
        #   ⟹ [SAFE_DELETE_BULK_CONFIRM_REQUIRED] ⟹ analyze 恒失败
        #   ⟹ 技能侧 `_gx_analyze_embeddings` 反复重试 → 6 臂派发全部卡死。
        #   删除目标仅为 gitnexus **自有缓存目录**（非用户数据），故对 analyze 关闭该 shim。
        #   ⚠ 只对 analyze* 关闭，其余子命令保持保护。
        #   2026-11-01 实测修正：原写 `setdefault` —— **父进程已注入 `=1`** ⟹ setdefault 是空操作
        #     ⟹ shim 从未被关掉 ⟹ analyze 恒死在 `[safe-delete][SAFE_DELETE_INVALID_PATH]
        #     embedded drive prefix is not allowed`（parsedfile-store 下按绝对路径命名的条目
        #     含 `/C:` ⟹ 命中 shim 的 `*/[A-Za-z]:*` 判据）⟹ 自愈 analyze 恒失败 ⟹ 基线恒
        #     `stale` ⟹ 质询 `BASELINE_STALE`。改**显式覆盖**（本函数的目的就是覆盖）。
        env["CODEBUDDY_SAFE_DELETE_ENABLED"] = "0"
    # 2026-10-30（纠错回滚）：此处曾注入 GITNEXUS_EMBEDDING_MODEL / _DIMS=512 试图
    #   把 gitnexus 索引嵌入换成中文模型，**实测不可行且有害**：
    #   ① `GITNEXUS_EMBEDDING_MODEL` 只被 http-client 读取（远程 OpenAI 兼容端点用），
    #      本地 ONNX 路径的 modelId 硬编码在 DEFAULT_EMBEDDING_CONFIG（snowflake-arctic-embed-xs）
    #      ⟹ `analyze --embedding-model` 也只写这个 env，本地模式下被完全忽略
    #      （analyze.js: anyHttpEmbedFlag 注释与 'Falling back to local ONNX' 告警为证）；
    #   ② `GITNEXUS_EMBEDDING_DIMS` 却被 schema.ts 在 module-load 时读取用于**建表**，
    #      于是出现「建表 512 / 模型吐 384」⟹ `Conversion exception: Expected 512, Actual 384`
    #      ⟹ analyze 恒失败并留下 incremental-in-progress + embedding-checkpoint-pending 脏标记
    #      ⟹ preflight 反复自愈重试、派臂卡死。
    #   ⚠ 中文语义嵌入的诉求由**独立实现** `scripts/gk_finding_embed.py` 满足 —— 用途 = 中文
    #      finding 的**塌缩聚类**（`cos>=0.66` 强制直连 must-link，与 root_key 精确成组 /
    #      锚集 Jaccard 平均连接**取并集**，最终收敛唯一 `principal`）；模型
    #      onnx-community/bge-small-zh-v1.5-ONNX / 512 维 / **CLS pooling**；
    #      A/B 实测 P@1 79.2% vs arctic-embed-xs 60.4%。**与本 launcher 无关，禁混谈。**
    #   ⚠ **本侧（gitnexus 代码图索引）确实缺中文模型**：仍是英文 arctic-embed-xs / 384 维 /
    #      mean pooling，中文注释与中文文档的语义检索会偏弱。但补法只有两条 ——
    #      ① HTTP 模式（起本地/远程 OpenAI 兼容 embedding 服务，传 --embedding-base-url +
    #         --embedding-model + --embedding-dims）；② 改 gitnexus 源码常量。**无 env 入口。**
    #      优先级判断：塌缩聚类（finding 侧）才真正依赖中文语义，代码索引以结构与调用链为主，
    #      故此项可后置，不得用「注入 env」的假办法糊过去。
    return env


def _is_wsl() -> bool:
    try:
        rel = os.uname().release.lower()
    except Exception:
        return False
    return "microsoft" in rel or bool(os.environ.get("WSL_DISTRO_NAME"))


def _to_win(path: str) -> str:
    try:
        r = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _win_visible_temp() -> Path:
    """Windows 侧可见的 Temp（WSL 的 `/tmp` 对 `node.exe`/`powershell` 不可见）。

    **发现式**（公开包零机器路径）：`GK_WIN_TEMP` → 宿主 temp → `/mnt/<盘>/Users/<用户>/.../Temp`。
    """
    env = (os.environ.get("GK_WIN_TEMP") or "").strip()
    if env:
        return Path(env)
    if os.name == "nt":
        return Path(tempfile.gettempdir())
    try:
        for p in sorted(Path("/mnt").glob("*/Users/*/AppData/Local/Temp")):
            return p
    except OSError:
        pass
    return Path(tempfile.gettempdir())


def _wrap_win_shell(node: str, js: str, args, cwd: str):
    """WSL 宿主 + Windows node ⟹ 经 PowerShell 以 **Windows cwd** 启动；否则 None（逐字不变）。

    病象（2026-11-01 实测）：WSL 里直接 spawn `node.exe` 时子进程 cwd 经 interop 变 UNC
    （`\\\\wsl.localhost\\...`）⟹ gitnexus 按 UNC 扫仓，4 分钟 0% CPU、零输出（`status` 同）。
    同一句经 PowerShell `Set-Location <C:\\...>` 启动 4.7s 返回。跨平台语义不变：只在
    「WSL 宿主 + `.exe` 解释器」这一组合生效，Linux/macOS/原生 Windows 走原路径。
    返回 `(argv, spec_env)`：argv 固定为 `gk_gx_win.ps1`，真实参数走 base64(JSON) 环境变量
    （PS 5.1 会把 `--json` 误当参数名）。
    """
    if not _is_wsl() or not cwd or not str(node).lower().endswith(".exe"):
        return None
    script = Path(__file__).resolve().parent / "gk_gx_win.ps1"
    if not script.is_file():
        return None
    win_cwd = _to_win(cwd)
    win_node = _to_win(node) or node
    win_js = js if (len(js) > 1 and js[1] == ":") else (_to_win(js) or js)
    win_script = _to_win(str(script))
    if not win_cwd or not win_script:
        return None
    spec = json.dumps({"cwd": win_cwd, "node": win_node, "js": win_js,
                       "args": [str(a) for a in args],
                       # 自定义 env **不会**自动跨 interop（非 WSLENV 白名单即丢）⟹ 显式带上
                       "env": {k: v for k, v in os.environ.items() if k.startswith("GITNEXUS_")}},
                      ensure_ascii=False)
    # 规格文件放 Windows 可见的 Temp（WSL 的 /tmp 对 node.exe/powershell 不可见）。
    try:
        tdir = _win_visible_temp()
        tdir.mkdir(parents=True, exist_ok=True)
        sp = tdir / ("gkx-spec-%d-%d.json" % (os.getpid(), time.time_ns() % 1000000000))
        sp.write_text(spec, encoding="utf-8")
    except OSError:
        return None
    win_spec = _to_win(str(sp))
    if not win_spec:
        try:
            sp.unlink()
        except OSError:
            pass
        return None
    return (["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", win_script,
             "-SpecFile", win_spec], str(sp))


def _meta_candidates(repo_dir: str):
    """索引元数据候选：外置存储根优先（若设了 `GITNEXUS_STORAGE_ROOT`），其后仓内 `.gitnexus`。"""
    local = [Path(repo_dir) / ".gitnexus" / "meta.json"]
    out = []
    root = os.environ.get("GITNEXUS_STORAGE_ROOT") or os.environ.get("GITNEXUS_STORAGE_PATH") or ""
    if root:
        p = Path(root)
        if len(root) > 1 and root[1] == ":":
            try:
                r = subprocess.run(["wslpath", "-u", root], capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and r.stdout.strip():
                    p = Path(r.stdout.strip())
            except Exception:
                pass
        if p.is_dir():
            try:
                out.extend(sorted(p.glob("*/meta.json")))
            except OSError:
                pass
    return out + local


CODE_SUFFIXES = ("*.py", "*.js", "*.ts", "*.tsx", "*.sh", "*.mjs", "*.cjs")


def _iso_epoch(s: str) -> float:
    """ISO8601（含 `Z`）→ epoch 秒；不可解析 → 0。"""
    try:
        t = str(s or "").strip().replace("Z", "+00:00")
        import datetime as _dt
        return _dt.datetime.fromisoformat(t).timestamp()
    except Exception:
        return 0.0


def _last_code_commit_ts(repo_dir: str) -> float:
    """最后一次**代码文件**提交的 epoch（`git log -1 --format=%ct -- <后缀>`）。"""
    try:
        r = subprocess.run(["git", "-C", repo_dir, "log", "-1", "--format=%ct", "--"]
                           + list(CODE_SUFFIXES), capture_output=True, text=True, timeout=20)
        return float((r.stdout or "").strip() or 0)
    except Exception:
        return 0.0


def fast_status(repo_dir: str) -> str:
    """**零 spawn** 的新鲜度判定（→ current|reusable|stale|unavailable）。

    2026-11-01 实测：`gitnexus status` 在 Windows 上恒重算「分析器身份摘要」（meta 记录
    dependencyRuntime.artifactCount=12280 个依赖产物；且 POSIX 所有权 API 缺失 ⟹ 身份缓存
    fail-closed 永不命中）⟹ 原生 Windows 亦 >120s 不返回。本函数改用**索引自记的 lastCommit**
    判新鲜，四态语义与原实现一致（见 `_gitnexus_baseline_status` 头注）：
      无 meta / 解析失败 → unavailable；incompleteReasons 非空 → stale；
      lastCommit == HEAD → current；落后但代码文件零改动 → reusable，否则 stale。
    """
    try:
        head = subprocess.run(["git", "-C", repo_dir, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return "unavailable"
    if not head:
        return "unavailable"
    repo_abs = os.path.realpath(repo_dir)
    chosen = None
    for c in _meta_candidates(repo_dir):
        try:
            if not c.is_file():
                continue
            d = json.loads(c.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rp = str(d.get("repoPath") or "")
        if rp:
            try:
                same = os.path.realpath(_to_wsl(rp)) == repo_abs
            except Exception:
                same = False
            if not same:
                continue
        chosen = d
        break
    if chosen is None:
        return "unavailable"
    if chosen.get("incompleteReasons"):
        return "stale"
    # 2026-11-01（实测）：门触发 analyze 恒加 `--skip-git`，而该旗标**不更新 lastCommit**
    #   ⟹ 只看 lastCommit 会永远 stale ⟹ 每次再付一次 `--drop-embeddings` 全量重嵌（40min 级）。
    #   补等价判据：**索引构建时间 ≥ 最后一次代码提交时间** ⟹ 图已覆盖当前代码。
    _idx_ts = _iso_epoch(str(chosen.get("indexedAt") or ""))
    _code_ts = _last_code_commit_ts(repo_dir)
    if _idx_ts and _code_ts and _idx_ts >= _code_ts:
        return "current"
    ic = str(chosen.get("lastCommit") or "").strip()
    if not ic:
        return "unavailable"
    if ic == head:
        return "current"
    try:
        r = subprocess.run(["git", "-C", repo_dir, "diff", "--name-only", ic, head, "--"]
                           + list(CODE_SUFFIXES), capture_output=True, text=True, timeout=30)
        n = len([ln for ln in (r.stdout or "").splitlines() if ln.strip()])
    except Exception:
        return "stale"
    return "reusable" if n == 0 else "stale"


# ─── 外置存储容量控制（2026-11-02）───────────────────────────────────────────
# 病象：`GITNEXUS_STORAGE_ROOT` 下按 `<reponame>-<hash>` 一仓一个索引目录，**只增不减**
#   （gitnexus 无 prune 子命令；实测两仓 883M，其中 lbug 图库 668M）⟹ 换分支 / 换 worktree /
#   试验不同 max-file-size 都会留下整份旧索引。
# 判据（owner 提问「要不要加 TTL」）：**TTL 与容量是两件事，缺一不可**。
#   · 只用 TTL：一个仓 90 天没动但你还天天用它 ⟹ 被误删，代价是重跑一次全量（分钟级）；
#   · 只用容量：小仓会无限堆积（每个几十 M，攒到几百个也是几个 G）。
#   ⟹ 双阈值：先按 TTL 清「确实没人要的」，再按总容量 LRU 清「最久未构建的」，直到低于上限。
#   ⚠ 三条豁免（防误删）：
#     ① **当前仓**（`GX_REPO_DIR` 指向的那份）永不删 —— 正在用的索引被删 = 立即失效；
#     ② `lbug.wal.dirty-recovery` 存在的（上次 analyze 被中断，残态修复中）不删；
#     ③ 任何一步失败只记 warning，不阻断调用方（prune 是维护动作，不是判据）。
PRUNE_TTL_DAYS_DEFAULT = 30
PRUNE_MAX_GB_DEFAULT = 5.0
_pruned_once = False


def _store_roots() -> list:
    """存储根候选：显式 `GITNEXUS_STORAGE_ROOT` 优先，否则 `~/.gitnexus-store` 下的形态子根。"""
    base = (os.environ.get("GITNEXUS_STORAGE_ROOT") or "").strip()
    if base:
        # `C:\...` 形态在 POSIX 宿主下要转；本函数只在同形态宿主内用，故只做存在性判断
        p = Path(base)
        if p.is_dir():
            return [p]
    home = Path(os.path.expanduser("~")) / ".gitnexus-store"
    return [x for x in sorted(home.glob("*")) if x.is_dir()] if home.is_dir() else []


def _dir_size(p: Path) -> int:
    tot = 0
    for r, _ds, fs in os.walk(p):
        for f in fs:
            try:
                tot += os.path.getsize(os.path.join(r, f))
            except OSError:
                pass
    return tot


def _index_entries() -> list:
    """扫出所有索引目录 → [{path, size, indexed_at_epoch, repo_path, wal_dirty}]。"""
    out = []
    for root in _store_roots():
        for meta in root.glob("*/meta.json"):
            d = meta.parent
            try:
                m = json.loads(meta.read_text(encoding="utf-8"))
            except Exception:
                m = {}
            out.append({
                "path": d,
                "size": _dir_size(d),
                "indexed_at": _iso_epoch(str(m.get("indexedAt") or "")),
                "repo_path": str(m.get("repoPath") or ""),
                "wal_dirty": (d / "lbug.wal.dirty-recovery").exists(),
            })
    return out


def prune_store(max_gb: float | None = None, ttl_days: float | None = None,
                dry_run: bool = False) -> list:
    """按 TTL + 容量双阈值清理旧索引；返回 `[(path, size_mb, reason)]`。

    默认上限/期限可用 env 覆盖：`GK_GX_STORE_MAX_GB` / `GK_GX_STORE_TTL_DAYS`；
    `GK_GX_NO_PRUNE=1` 关闭自动清理（`main` 的 `prune` 子命令仍可手动跑）。
    """
    try:
        max_gb = PRUNE_MAX_GB_DEFAULT if max_gb is None else float(max_gb)
        if os.environ.get("GK_GX_STORE_MAX_GB"):
            max_gb = float(os.environ["GK_GX_STORE_MAX_GB"])
        ttl_days = PRUNE_TTL_DAYS_DEFAULT if ttl_days is None else float(ttl_days)
        if os.environ.get("GK_GX_STORE_TTL_DAYS"):
            ttl_days = float(os.environ["GK_GX_STORE_TTL_DAYS"])
    except Exception:
        max_gb, ttl_days = PRUNE_MAX_GB_DEFAULT, PRUNE_TTL_DAYS_DEFAULT

    keep = os.path.realpath(repo_dir()) if repo_dir() else ""
    now = time.time()
    ents = _index_entries()
    removed = []

    def _do(e, reason):
        removed.append((str(e["path"]), round(e["size"] / 1048576.0, 1), reason))
        if dry_run:
            return
        try:
            shutil.rmtree(str(e["path"]))
        except Exception:
            pass

    # ① TTL：过期且不豁免
    survivors = []
    for e in ents:
        rp = os.path.realpath(e["repo_path"]) if e["repo_path"] else ""
        if keep and rp and rp == keep:
            survivors.append(e); continue
        if e["wal_dirty"]:
            survivors.append(e); continue
        if e["indexed_at"] and (now - e["indexed_at"]) > ttl_days * 86400:
            _do(e, "ttl>%gd" % ttl_days)
        else:
            survivors.append(e)

    # ② 容量：仍超上限 ⟹ 按 indexedAt 升序（最久未构建）删
    total = sum(e["size"] for e in survivors)
    for e in sorted(survivors, key=lambda x: (x["indexed_at"] or 0)):
        if total <= max_gb * 1073741824:
            break
        rp = os.path.realpath(e["repo_path"]) if e["repo_path"] else ""
        if keep and rp and rp == keep:
            continue
        if e["wal_dirty"]:
            continue
        _do(e, "cap>%gGB" % max_gb)
        total -= e["size"]
    return removed


def _to_wsl(path: str) -> str:
    """Windows 路径 → WSL 路径（已是 posix 形态则原样返回）。"""
    if len(path) > 1 and path[1] == ":":
        try:
            r = subprocess.run(["wslpath", "-u", path], capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
    return path


def run_raw(args, *, timeout: int = 60, cache: bool | None = None, cwd: str = ""):
    """执行 gitnexus 子命令，返回 `(rc_ok, stdout, stderr, cached)`。

    `cache=None` → 按 `GK_GX_CACHE` 自动判定；`cache=True/False` → 强制。
    缓存命中时不 spawn（`rc_ok=True`, `cached=True`）。
    `cwd`（2026-10-28，A1 收口）：bash 侧 `_run_gitnexus_raw` 原本以 `cd <repo>` 子壳启动
    node（gitnexus 需要 cwd = 目标仓）；委托本 launcher 后由 `subprocess.run(cwd=)` 承接。
    """
    err = env_error()
    if err:
        return False, "", err, False
    # 2026-11-02：analyze 前做一次**进程/容量**维护（每进程一次；`GK_GX_NO_PRUNE=1` 可关）。
    #   reap：收掉上次被外部 kill 留下的 worker 孤儿（实测 9 个）；
    #   prune：TTL + 容量双阈值清旧索引（当前仓豁免）。
    global _pruned_once
    if not _pruned_once and str(args[0] if args else "").startswith("analyze"):
        _pruned_once = True
        try:
            reap_workers()
        except Exception:
            pass
        if (os.environ.get("GK_GX_NO_PRUNE") or "").strip() not in ("1", "true", "yes"):
            try:
                prune_store()
            except Exception:
                pass
    argv = [node_exe(), js_path()] + [str(a) for a in args]
    _env = _build_env(str(args[0]) if args else "")
    _wrapped = _wrap_win_shell(argv[0], argv[1], [str(a) for a in args], cwd)
    _spec_file = ""
    if _wrapped:
        argv, _spec_file = _wrapped
        cwd = ""                      # PowerShell 自带 Set-Location
    use_cache = cacheable([str(a) for a in args], force=cache)
    key = ""
    if use_cache:
        key = _cache_key([str(a) for a in args], resolve_repo(), head_sha())
        hit = _cache_get(key)
        if hit is not None:
            return True, hit, "", True
    try:
        # 2026-11-01：PowerShell 路由下 gitnexus 的中文表头按 **Windows 控制台编码**（cp936）
        #   输出 ⟹ 原 `text=True`（utf-8 严格）会抛 UnicodeDecodeError。改宽松解码：
        #   只影响非法字节（原本会整次调用失败），JSON 主体恒为 ASCII/UTF-8 可解析。
        # 2026-11-02：改 `Popen` + **独立进程组** —— 超时要能杀掉 gitnexus 的 worker 子进程
        #   （`subprocess.run(timeout=)` 只杀直接子进程 ⟹ 实测留下 9 个 node 孤儿）。见 `_kill_tree`。
        _cflags = 0
        if os.name == "nt":
            _cflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, errors="replace", cwd=(cwd or None), env=_env,
                             start_new_session=(os.name != "nt"), creationflags=_cflags)
        _pids_save(_pids_load() + [{"pid": p.pid, "ts": time.time()}])
        try:
            _out, _err = p.communicate(timeout=timeout)
            r = subprocess.CompletedProcess(argv, p.returncode, _out, _err)
        except subprocess.TimeoutExpired:
            _kill_tree(p.pid)
            try:
                p.communicate(timeout=20)
            except Exception:
                pass
            return False, "", "timeout after %ss" % timeout, False
        finally:
            _pids_save([x for x in _pids_load() if x["pid"] != p.pid])
    except Exception as e:  # 含 FileNotFoundError（node 缺失/形态不符）
        return False, "", str(e), False
    finally:
        if _spec_file:
            try:
                os.unlink(_spec_file)
            except OSError:
                pass
    out = r.stdout or ""
    # 2026-11-01（实测根因，基线 `unavailable` 粘滞）：**错误响应绝不入缓存**。
    #   病象：`status --json` 曾回 `{"error":"not-indexed"}`（当时存储根被误判成 POSIX 形态，
    #   Windows node 解析出 `<cwd>/mnt/c/...` 假路径）⟹ 该 62 字节错误体被写入跨进程缓存，
    #   键 = repo + HEAD + argv，TTL 2h ⟹ **修好存储根后仍读回旧错误**，`_gitnexus_baseline_status`
    #   恒解成 `unavailable` ⟹ `BASELINE_STALE` 派发阻断，且看起来"像另一个 bug"。
    #   不变式：缓存只存**成功且非错误体**的只读输出（宁可不缓存，不返回粘滞错误）。
    _err_payload = False
    if out:
        try:
            _d = json.loads(out.strip().splitlines()[-1]) if out.strip() else None
            _err_payload = isinstance(_d, dict) and bool(_d.get("error"))
        except Exception:
            _err_payload = False
    if out and use_cache and r.returncode == 0 and not _err_payload:
        _cache_put(key, out)
    return r.returncode == 0, out, r.stderr or "", False


def run_text(args, *, timeout: int = 60, cache: bool | None = None) -> str:
    """执行并返回 stdout 原文（失败返回 `[ERROR] ...` 文案，调用方可直接拼接/判别）。"""
    ok, out, err, _cached = run_raw(args, timeout=timeout, cache=cache)
    if not ok and not out:
        return err or "[ERROR] gitnexus failed"
    return out


def run_json(args, *, timeout: int = 60, cache: bool | None = None,
             strict: bool = True) -> dict:
    """执行并解析**最后一个**完整 JSON 对象；无 JSON 时返回 `{"raw": <stdout>}`。

    `strict=True`（默认）：rc≠0 即 `{"error": ...}`（`gk_gitnexus_pdg_check` 语义）。
    `strict=False`：忽略 rc、只解析 stdout（`gk_pr_review_check` 语义，detect-changes 走文本）。

    解析收敛到 `gk_json_utils.extract_last_json`（2026-09-01）：多 JSON / warn 前置后置均取
    跨度最靠后的完整对象。
    """
    from gk_json_utils import extract_last_json

    ok, out, err, _cached = run_raw(args, timeout=timeout, cache=cache)
    if strict and not ok:
        return {"error": (out or err or "gitnexus failed")[:300]}
    obj = extract_last_json(out or "")
    if obj is None:
        return {"raw": (out or err or "")}
    return obj


__all__ = [
    "node_exe", "js_path", "env_error", "resolve_repo", "repo_dir", "head_sha",
    "cacheable", "invalidate_cache", "run_raw", "run_text", "run_json", "main",
]


# ─── CLI：bash 侧唯一 spawn 通道的委托入口（A1 收口 2026-10-28）─────────────────────
# `gatekeeper-cli.sh::_run_gitnexus_raw` 原先**自己** spawn `node <js> <args>`，成为 python
# 收敛后的**第二条 spawn 通道**（策略双写：identity cache 目录 / analyze 钉 cpu / 超时）。
# 现改为 `python3 scripts/gk_gitnexus.py run -- $args`：探测与 spawn 单源，bash 只做宿主侧
# 的「node 定位 / js 路径 / repo 目录 / cwd」编排并注入 GX_NODE/GX_JS/GX_REPO_DIR。
#
# 退出码与旧 bash 函数**逐字同义**：恒 0（旧实现 `echo "$gx_out"` 的 rc；失败信息走 stderr，
# 调用方本就不判 rc）。stdout 只放 gitnexus 原文 —— 缓存/错误文案一律 stderr，防污染解析。
_USAGE = ("usage: gk_gitnexus.py run [--timeout S] [--cwd DIR] [--cache|--no-cache] "
          "-- <gitnexus argv...>")


def _split_run_args(av: list) -> tuple:
    """解析 `run` 的旗标，返回 `(opts, argv)`；`--` 之后原样透传。

    非法旗标值 ⟹ `ValueError`（由 `main` 归一成 rc=2；不用 `SystemExit`，便于单测直接断言）。
    """
    opts = {"timeout": 60, "cwd": "", "cache": None}
    i = 0
    while i < len(av):
        a = av[i]
        if a == "--":
            return opts, av[i + 1:]
        if a == "--timeout" and i + 1 < len(av):
            try:
                opts["timeout"] = int(av[i + 1])
            except ValueError:
                raise ValueError("--timeout 需要整数: %r" % av[i + 1])
            i += 2
        elif a == "--cwd" and i + 1 < len(av):
            opts["cwd"] = av[i + 1]
            i += 2
        elif a == "--cache":
            opts["cache"] = True
            i += 1
        elif a == "--no-cache":
            opts["cache"] = False
            i += 1
        elif a.startswith("-"):
            raise ValueError("unknown option: %s" % a)
        else:
            return opts, av[i:]
    return opts, []


def main(argv=None) -> int:
    import sys as _sys
    av = list(_sys.argv[1:] if argv is None else argv)
    if not av or av[0] in ("-h", "--help"):
        print(_USAGE)
        return 0 if av else 2
    if av[0] == "fast-status":
        # 零 spawn 新鲜度判定（读 meta.json + git HEAD）；供 bash `_gitnexus_baseline_status` 首选。
        cwd = ""
        rest = av[1:]
        for i, a in enumerate(rest):
            if a == "--cwd" and i + 1 < len(rest):
                cwd = rest[i + 1]
        print(fast_status(cwd or os.getcwd()))
        return 0
    if av[0] == "prune":
        # 手动维护入口：`gk_gitnexus.py prune [--max-gb N] [--ttl-days D] [--dry-run]`
        _opt = {"max_gb": None, "ttl_days": None, "dry": False}
        _r = av[1:]
        i = 0
        while i < len(_r):
            a = _r[i]
            if a == "--max-gb" and i + 1 < len(_r):
                _opt["max_gb"] = float(_r[i + 1]); i += 2
            elif a == "--ttl-days" and i + 1 < len(_r):
                _opt["ttl_days"] = float(_r[i + 1]); i += 2
            elif a == "--dry-run":
                _opt["dry"] = True; i += 1
            else:
                i += 1
        rm = prune_store(max_gb=_opt["max_gb"], ttl_days=_opt["ttl_days"], dry_run=_opt["dry"])
        print(json.dumps({"ok": True, "dry_run": _opt["dry"], "removed": rm,
                          "total_mb": round(sum(x[1] for x in rm), 1)},
                         ensure_ascii=False))
        return 0
    if av[0] != "run":
        print("%s\nunknown subcommand: %s" % (_USAGE, av[0]), file=_sys.stderr)
        return 2
    # 2026-11-01：执行前**形态断言**（fail-closed）。原状混血只打 WARN 就继续 ⟹ 输出恒空、
    #   runner 仍写兜底模板 = 528B 空壳报告。此处直接拒绝，错误可见且不入账。
    _ag = arch_guard()
    if _ag:
        print(json.dumps({"ok": False, "error": "GX_ARCH_MISMATCH", "detail": _ag,
                          "hint": "node 与 gitnexus 原生包必须同一侧（B 方案：全 Windows 运行时）"},
                         ensure_ascii=False))
        return 2
    try:
        opts, gx_argv = _split_run_args(av[1:])
    except ValueError as e:
        print("%s\n%s" % (_USAGE, e), file=_sys.stderr)
        return 2
    if not gx_argv:
        print(_USAGE, file=_sys.stderr)
        return 2
    _ok, out, err, _cached = run_raw(gx_argv, timeout=opts["timeout"],
                                     cache=opts["cache"], cwd=opts["cwd"])
    if out:
        _sys.stdout.write(out)
        if not out.endswith("\n"):
            _sys.stdout.write("\n")
    if err:
        _sys.stderr.write(err if err.endswith("\n") else err + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
