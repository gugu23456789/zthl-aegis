#!/usr/bin/env python3
"""gk_worker_client.py — `gk_worker.py` 的客户端（A7，2026-10-28）

解决原 bash `_py_worker_start` 的两个死结（见 `gk_worker.py` 头部）：

1. **命令替换恒挂** —— 原式 `port=$(python3 worker …)` 要等 worker 退出才返回（rc=124）。
   本客户端用 `Popen(..., start_new_session=True)` **detached 启动**，再**轮询 pidfile**，
   绝不捕获子进程 stdout。
2. **与 CLI 同生命周期** —— pidfile 默认落 `~/.gatekeeper/worker.pid`（**仓库外、跨调用**），
   worker 有 TTL 自退，不靠父进程的 `trap EXIT` 收尸。

**鉴权**：pidfile 第 3 行是 token（`0600`），请求必须带 `auth`；token 不进 argv。
**版本**（2026-10-29 A7 接线）：pidfile 第 4 行是 `code_epoch`（见 `gk_worker_epoch.py`）。
客户端 `--epoch-auto` 时本地重算并比对，不符即视为不可用 ⟹ 调用方回退直读（禁静默用旧代码）。

用法（CLI）：
    python3 gk_worker_client.py op ping
    python3 gk_worker_client.py op state_view --state ~/.gatekeeper.state --path stage
    python3 gk_worker_client.py warm            # 显式预热（**唯一**允许 autostart 的入口）
    python3 gk_worker_client.py stop

关键路径纪律（A7 接线，2026-10-29）：
    CLI 启动面**只许** `op ... --if-alive --epoch-auto --timeout 0.25 --unwrap`：
      · `--if-alive` ⟹ 绝不 autostart（冷启 1.7s > 它要省的 600ms）；
      · `--timeout 0.25` ⟹ daemon 卡死也不得阻塞门禁；
      · 任何失败（未启/epoch 不符/超时/坏包）⟹ 非零退出，bash 走原路径（fail-closed 面不变）。
"""
import json
import os
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(_HERE, "gk_worker.py")

# 转发给 daemon 的环境变量（前缀白名单）：`resolve_state` 的域路由/指针判定读这些 env，
# 而 daemon 的 env 是**首次启动时冻结**的 ⟹ 必须按请求携带（见 gk_worker._op_resolve_state_cli）。
_ENV_PREFIXES = ("GK_", "GATEKEEPER_")
_ENV_EXACT = ("STATE_FILE", "STATE_FILE_EXPLICIT", "PLAN_POINTER", "PLAN_FILE", "HOME", "PWD")


def env_snapshot() -> dict:
    """本进程环境里与路由/门禁相关的子集（前缀白名单，非全量 ⟹ 不夹带无关密钥）。"""
    out = {}
    for k, v in os.environ.items():
        if k in _ENV_EXACT or k.startswith(_ENV_PREFIXES):
            out[k] = v
    return out


def local_epoch() -> str:
    """本机代码指纹（与 daemon 启动时写入 pidfile 的值同一口径）。"""
    try:
        from gk_worker_epoch import code_epoch
    except Exception:      # noqa: BLE001 — 缺模块 ⟹ 空（调用方按不校验处理）
        return ""
    return code_epoch(_HERE)


def default_pidfile() -> str:
    return os.environ.get("GK_WORKER_PIDFILE") or os.path.join(
        os.path.expanduser("~"), ".gatekeeper", "worker.pid")


def read_pidfile(path: str = "") -> dict:
    """读 pidfile ⟹ `{"pid","port","token","epoch"}`；缺失/损坏返回 `{}`。

    第 4 行（epoch）可选：旧 daemon 只有 3 行 ⟹ `epoch=""`（调用方按「不校验」处理，
    但 `--epoch-auto` 下空 epoch 会被判不符 ⟹ 自动失效并回退，这是期望行为）。
    """
    p = path or default_pidfile()
    try:
        with open(p, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f.read().splitlines()]
    except OSError:
        return {}
    if len(lines) < 3:
        return {}
    try:
        info = {"pid": int(lines[0]), "port": int(lines[1]), "token": lines[2]}
    except ValueError:
        return {}
    info["epoch"] = lines[3] if len(lines) > 3 else ""
    return info


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def ensure_daemon(pidfile: str = "", ttl: float = 900.0, wait_s: float = 5.0) -> dict:
    """确保 daemon 在跑（不跑就以 detached 方式拉起）。返回 pidfile 内容（失败 `{}`）。"""
    p = pidfile or default_pidfile()
    info = read_pidfile(p)
    if info and _alive(info["pid"]):
        return info
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    try:
        # `subprocess` 延迟导入（2026-10-29）：实测顶层 import 使客户端冷启 0.06→0.11s，
        # 而关键路径**永不** autostart ⟹ 这笔税 99% 的调用白付。启动时才付。
        import subprocess
        subprocess.Popen(
            [sys.executable, WORKER, "--pidfile", p, "--ttl", str(ttl)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,      # detached：CLI 退出不连带杀 worker
            close_fds=True,
        )
    except Exception:
        return {}
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        info = read_pidfile(p)
        if info and _alive(info["pid"]):
            return info
        time.sleep(0.02)
    return {}


def call(op: str, args: dict | None = None, pidfile: str = "", timeout: float = 10.0,
         autostart: bool = True, expected_epoch: str = "", forward_env: bool = False) -> dict:
    """发一条 op 请求；daemon 不在则按 `autostart` 拉起。返回响应 dict（失败 `{"ok":False,...}`）。

    `expected_epoch`（A7 接线，2026-10-29）：非空时要求 pidfile 第 4 行**逐字相等**，否则直接
    返回 `epoch_mismatch` —— 代码改过的旧 daemon 不得继续作答（不得静默用旧逻辑）。
    `forward_env`：把本进程的路由相关 env 快照塞进 `args.env`（daemon 的 env 是冻结的）。
    """
    p = pidfile or default_pidfile()
    info = ensure_daemon(p) if autostart else read_pidfile(p)
    if not info:
        return {"ok": False, "error": "worker 不可用（pidfile 缺失或进程已死）"}
    if expected_epoch and info.get("epoch") != expected_epoch:
        return {"ok": False, "error": "epoch_mismatch（daemon 代码版本不符，已回退直读）"}
    req_args = dict(args or {})
    if forward_env:
        req_args["env"] = env_snapshot()
    req = {"auth": info["token"], "op": op, "args": req_args}
    try:
        with socket.create_connection(("127.0.0.1", info["port"]), timeout=timeout) as s:
            s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except OSError as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    try:
        return json.loads(buf.decode("utf-8", errors="replace").strip() or "{}")
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "响应不可解析: %s" % e}


def stop(pidfile: str = "") -> bool:
    """停 daemon（SIGTERM + 等 pidfile 消失）。"""
    p = pidfile or default_pidfile()
    info = read_pidfile(p)
    if not info:
        return False
    try:
        os.kill(info["pid"], 15)
    except OSError:
        pass
    for _ in range(100):
        if not _alive(info["pid"]):
            break
        time.sleep(0.02)
    try:
        os.unlink(p)
    except OSError:
        pass
    return True


_VALUE_LESS = ("--if-alive", "--epoch-auto", "--unwrap", "--forward-env")


def main(argv=None) -> int:
    av = list(sys.argv[1:] if argv is None else argv)
    if not av:
        print(json.dumps({"ok": False, "error": "usage: gk_worker_client.py op <name> [--k v] | warm | stop"}))
        return 2
    if av[0] == "warm":
        # **唯一**允许 autostart 的入口（显式预热）。关键路径禁用（冷启 1.7s > 要省的 600ms）。
        try:
            _ttl = float(os.environ.get("GK_WORKER_TTL", "900"))
        except ValueError:
            _ttl = 900.0
        info = ensure_daemon(default_pidfile(), ttl=_ttl)
        print(json.dumps({"ok": bool(info), "pid": info.get("pid"),
                          "epoch": info.get("epoch", "")}, ensure_ascii=False))
        return 0 if info else 1
    if av[0] == "stop":
        print(json.dumps({"ok": True, "stopped": stop()}))
        return 0
    if av[0] != "op" or len(av) < 2:
        print(json.dumps({"ok": False, "error": "usage: gk_worker_client.py op <name> [--k v]"}))
        return 2
    op = av[1]
    flags = set()
    args = {}
    i = 2
    while i < len(av):
        a = av[i]
        if a in _VALUE_LESS:
            flags.add(a)
            i += 1
        elif a.startswith("--") and i + 1 < len(av):
            args[a[2:]] = av[i + 1]
            i += 2
        else:
            i += 1
    pidfile = args.pop("pidfile", "")
    try:
        timeout = float(args.pop("timeout", "10"))
    except ValueError:
        timeout = 10.0
    field = args.pop("field", "")
    resp = call(op, args, pidfile=pidfile, timeout=timeout,
                autostart=("--if-alive" not in flags),
                expected_epoch=(local_epoch() if "--epoch-auto" in flags else ""),
                forward_env=("--forward-env" in flags))
    if "--unwrap" in flags:
        # 值通道纪律（对齐 `gk_state_query`）：成功 ⟹ stdout 只放**值**；失败 ⟹ **stderr** 放错误、
        # stdout 留空、非零退出。bash 侧据此 `[ -z "$out" ] && 回退` 才成立 —— 若把错误 JSON
        # 写到 stdout，回退判据会被「非空的错误对象」骗过（实测：CLI 直接 rc=1 中断）。
        if resp.get("ok"):
            # 字节级对齐 `gk_route_center.main` 的回包（`ensure_ascii` 缺省 True）
            print(json.dumps(resp.get("result")))
            return 0
        sys.stderr.write("worker: %s\n" % (resp.get("error") or "unknown"))
        return 1
    if field:
        # `--field <k>`：只取 result 的一个**字符串**字段（启动块用；值通道纪律同上）。
        if resp.get("ok"):
            val = (resp.get("result") or {}).get(field)
            if isinstance(val, str):
                print(val)
                return 0
            sys.stderr.write("worker: 字段 %r 不存在或非字符串\n" % field)
            return 1
        sys.stderr.write("worker: %s\n" % (resp.get("error") or "unknown"))
        return 1
    print(json.dumps(resp, ensure_ascii=False))
    return 0 if resp.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
