#!/usr/bin/env python3
"""Persistent Python worker for gatekeeper-cli.sh（A7，2026-10-28 加固）

## 定位

`ECC-4622609810E7` 登记的 **ZH 预留设施**（zthl-adapter §2.10「ACP 守护进程」仓内原型）。
稳态往返 **5ms** vs 冷启 python3 **206ms**（≈41×）。

## A7 裁定：三条历史阻塞逐条解除

1. **无鉴权**（本机任意进程可经 TCP 执行任意 Python）⟹ 现要求 `--token`；请求必须带对
   `auth`。令牌写 pidfile 第 3 行（`0600`），**不进命令行**（避免 `ps` 泄漏）。
2. **任意代码执行** ⟹ 默认**只暴露白名单 op**（`ping` / `state_view` / `resolve_state`）；
   `eval` 需显式 `--allow-eval`（仅排障）且 builtins 收窄为只读白名单。
3. **命令替换恒挂 + 与 CLI 同生命周期** ⟹ 启动改 **detached（`start_new_session`）+ pidfile
   轮询**（不再捕获 stdout）；pidfile 建议放 `~/.gatekeeper/`，使 worker **跨 CLI 调用存活**。

## 协议（JSON Lines，单请求单连接）

    请求：{"auth": "<token>", "op": "state_view", "args": {...}}
    响应：{"ok": true, "result": ..., "error": "", "stdout": ""}

## 用法

    python3 gk_worker.py --pidfile ~/.gatekeeper/worker.pid --ttl 900
    → pidfile 三行：pid / port / token（0600）
    python3 gk_worker_client.py op state_view --state ~/.gatekeeper.state

## 只读面的新鲜度（2026-10-29 加固）

`state_view` 走 `_load_state`：判据 = `(st_mtime_ns, st_size)` 相等 **且** 不在 racy 窗口
（`now - mtime_ns < 2s`；本机 `/tmp` 实测时间戳只有 1s 粒度，同秒改写三字段全等），
结果必带 `stamp{path,mtime_ns,size,sha256}`（sha256 对**实际服务字节**取）。
⟹ worker 的缓存不再是「无校验读」：调用方拿到的视图可自证对应哪份字节。
实测（常驻后，420KB state）：`state_view` 3.6–3.9ms / `resolve_state` 13.6ms
（vs 冷启 python `resolve-state` ~600ms），冷启动 daemon 一次性 1.7s、TTL 自退。

## 现状：**未接生产调用点**（A7 裁定「不贸然接」）

CLI 启动路径（`resolve-state`）是 fail-closed 关键路径；接 worker = 在启动面多引入一个
可失败点。故本版只把**设施**修到「可用且有鉴权」，接线留待 §2.10 正式落地时统一设计。
"""

import json
import sys
import socket
import os
import io
import secrets
import time

# ── Pre-import common modules (the whole point of persistence) ──
import re
import hashlib
import datetime
import base64
from pathlib import Path

# ── Pre-import batch8 gk_* modules if available ──
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

# code_epoch 指纹（A7 接线，2026-10-29）：pidfile 第 4 行，客户端据此拒绝**旧代码 daemon**。
from gk_worker_epoch import code_epoch as _code_epoch  # noqa: E402

_GK_MODULES = {}
for _mod_name in [
    "gk_state",
    "gk_route_center",     # A7：resolve_state op 的宿主模块
    "gk_adjudicate",
    "gk_appeal",
    "gk_gate_checksum",
    "gk_gate_adjudicate",
    "gk_gate_project_type",
]:
    try:
        _GK_MODULES[_mod_name] = __import__(_mod_name)
    except Exception:      # noqa: BLE001 — 可选依赖：缺了只是该 op 不可用
        pass

# `--allow-eval` 下的 builtins 白名单（只读意图；无 open/exec/import/input）
_SAFE_BUILTINS = {
    "abs": abs, "all": all, "any": any, "bool": bool, "dict": dict, "enumerate": enumerate,
    "float": float, "int": int, "len": len, "list": list, "max": max, "min": min, "range": range,
    "repr": repr, "round": round, "set": set, "sorted": sorted, "str": str, "sum": sum,
    "tuple": tuple, "zip": zip, "print": print, "Exception": Exception, "ValueError": ValueError,
}

MAX_REQUEST_BYTES = 1 << 20     # 1MB：请求体硬上限（防内存打爆）

# ── State cache（stamp 校验，只读）────────────────────────────────────────
# 2026-10-29（A7 只读面加固）：原判据 `mtime <= cached_mtime` 有两个洞 ——
#   ① 只有 mtime（float 秒）：本机实测 `/tmp` 时间戳只有 **1s 粒度**（同秒两次改写
#      mtime/size 完全相同），`<=` 会把同秒改写判成命中 = **陈旧读**（预算/门禁误判）；
#   ② 没有内容指纹：调用方拿到的「视图」无法自证对应哪份字节。
# 现：stamp = `(st_mtime_ns, st_size)` 相等 **且** 不在 racy 窗口 + 随结果回吐
#   `sha256`（对**实际读出的字节**取，不是对重序列化的 dict 取），调用方可据此判新鲜。
_RACY_NS = 2 * 10 ** 9            # 与 gk_state_route 同一 racy 口径（1s 粒度 + 抖动）
_state_cache = {"path": None, "stamp": None, "data": None, "sha": ""}


def _load_state(path):
    """按 stamp 校验的只读 state 载入 ⟹ `(data, stamp)`；不可读/坏 JSON ⟹ `(None, None)`。

    stamp = `{"mtime_ns","size","sha256","path"}`；`sha256` 对应**served 数据**本身。
    racy（`now - mtime_ns < 2s`）时既不读也不写缓存 —— 同秒改写可能不换 stamp。
    """
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    key = (st.st_mtime_ns, st.st_size)
    racy = (time.time_ns() - st.st_mtime_ns) < _RACY_NS
    if (not racy and path == _state_cache["path"] and key == _state_cache["stamp"]
            and _state_cache["data"] is not None):
        return _state_cache["data"], {"path": path, "mtime_ns": key[0],
                                      "size": key[1], "sha256": _state_cache["sha"]}
    try:
        with open(path, "rb") as f:
            raw = f.read()
        data = json.loads(raw.decode("utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None, None
    sha = hashlib.sha256(raw).hexdigest()
    if not racy:
        _state_cache.update({"path": path, "stamp": key, "data": data, "sha": sha})
    return data, {"path": path, "mtime_ns": key[0], "size": key[1], "sha256": sha}


# ── op 白名单（A7：默认无任意代码执行面）─────────────────────────────────
def _op_ping(args):
    return {"pid": os.getpid(), "ts": time.time()}


def _op_state_view(args):
    """只读投影：`args.state` + 可选点路径 `args.path`（空则返回顶层键名）。

    2026-10-29（A7 只读面加固）：结果必带 `stamp`（mtime_ns / size / **sha256**）——
    调用方据此可判「这份视图对应哪份字节」，worker 的缓存不再是无校验面。
    """
    sp = (args.get("state") or os.environ.get("STATE_FILE", "") or "").strip()
    if not sp:
        raise ValueError("state_view: 需要 args.state")
    d, stamp = _load_state(sp)
    if d is None:
        raise ValueError("state_view: state 不可读 %s" % sp)
    path = (args.get("path") or "").strip()
    if not path:
        return {"keys": sorted(d.keys()), "stamp": stamp}
    cur = d
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return {"missing": path, "stamp": stamp}
    return {"value": cur, "stamp": stamp}


def _op_resolve_state(args):
    """`gk_route_center resolve-state` 的只读入口；缺失即 fail-loud（不猜）。"""
    mod = _GK_MODULES.get("gk_route_center")
    if mod is None:
        raise RuntimeError("resolve_state: gk_route_center 不可导入")
    fn = getattr(mod, "resolve_state", None)
    if not callable(fn):
        raise RuntimeError("resolve_state: gk_route_center.resolve_state 不存在")
    return fn(**{k: v for k, v in (args or {}).items() if v is not None})


def _op_resolve_state_cli(args):
    """`gk_route_center resolve-state --derive-domain` 的**逐字等价**入口（A7 接线，2026-10-29）。

    为什么不是直接调 `resolve_state()`：CLI 的 `resolve-state` 分支还要做 `--derive-domain`
    的计划来源解析（`plan_override or plan_file or env GK_PLAN_FILE`）⟹ 那段逻辑已抽成
    `gk_route_center.resolve_state_cli`（**单一实现**，`main()` 与本 op 共用）。本模块只做参数
    转发，**禁第二实现**。

    环境面（关键）：`resolve_state` 读 `STATE_FILE` / `PLAN_POINTER` / `GK_PLAN_FILE` 等 env，
    而 daemon 的 env 是**首次启动时冻结**的 —— 与本调用方可能不同（域化 state、会话计划）。
    故请求里带 `env`（客户端按前缀白名单快照），本 op 在调用期间临时替换 `os.environ`，
    finally 复原。服务端单线程串行 ⟹ 不存在并发窗口。
    """
    mod = _GK_MODULES.get("gk_route_center")
    if mod is None:
        raise RuntimeError("resolve_state_cli: gk_route_center 不可导入")
    fn = getattr(mod, "resolve_state_cli", None)
    if not callable(fn):
        raise RuntimeError("resolve_state_cli: gk_route_center.resolve_state_cli 不存在")
    env = args.get("env") if isinstance(args, dict) else None
    env = env if isinstance(env, dict) else {}
    saved = {}
    try:
        for k, v in env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            saved[k] = os.environ.get(k)
            os.environ[k] = v
        return fn(skill_dir=str(args.get("skill_dir") or ""),
                  derive_domain=bool(args.get("derive_domain")))
    finally:
        # 复原 daemon 的原始 env（禁把某次调用的 STATE_FILE/计划上下文泄漏给后续请求）
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _op_prelude(args):
    """启动块前两读合一：`session_identity` 的 sid（2026-10-29 A7 接线）。

    单源 = `gk_session_identity.derive`（禁第二实现）；`is_valid_token` 过滤口径与 CLI 一致
    （CLI 拿到非法字符会丢弃 ⟹ 这里直接返回空串，语义相同）。
    """
    import gk_session_identity as SI          # 重依赖：daemon 只付一次 import 成本
    r = SI.derive(str(args.get("pwd") or ""))
    tok = r.get("token") or ""
    return {"sid": tok if SI.is_valid_token(tok) else ""}


def _op_route_flat(args):
    """`resolve-state --derive-domain` + 12 字段格式化，**一次往返**（省 route+parse 两次冷启）。

    环境同 `resolve_state_cli`（请求带 env 快照，调用期间临时替换）。
    兼容 `env__<K>` 扁平形态（bash `/dev/tcp` 快路用：bash 侧构造嵌套 JSON 易错，
    故把 env 拆成顶层 `env__K=V`，此处还原成 `args["env"]`）。
    """
    a = dict(args or {})
    if "env" not in a:
        a["env"] = {k[5:]: v for k, v in a.items() if k.startswith("env__")}
    out = _op_resolve_state_cli(a)
    mod = _GK_MODULES.get("gk_route_center")
    flat = getattr(mod, "flat_route", None)
    if not callable(flat):
        raise RuntimeError("route_flat: gk_route_center.flat_route 不存在")
    return {"flat": flat(out), "json": out}


_OPS = {
    "ping": _op_ping,
    "state_view": _op_state_view,
    "resolve_state": _op_resolve_state,
    "resolve_state_cli": _op_resolve_state_cli,
    "route_flat": _op_route_flat,
    "prelude": _op_prelude,
}


def _run_eval(code: str, args: dict) -> dict:
    """排障用 eval（**仅 `--allow-eval`**）：builtins 收窄 + stdout 捕获。"""
    ns = {"__builtins__": _SAFE_BUILTINS, "json": json, "re": re, "os": os,
          "hashlib": hashlib, "datetime": datetime, "base64": base64, "Path": Path}
    ns.update({k: v for k, v in (args or {}).items()})
    old, buf = sys.stdout, io.StringIO()
    sys.stdout = buf
    try:
        try:
            result = eval(code, ns)
        except SyntaxError:
            exec(code, ns)
            result = None
        return {"ok": True, "result": repr(result), "stdout": buf.getvalue()}
    except Exception as e:  # noqa: BLE001 — 边界：回包，不崩 daemon
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                "stdout": buf.getvalue()}
    finally:
        sys.stdout = old


def handle_payload(payload, token: str, allow_eval: bool = False) -> dict:
    """处理一条请求（**纯函数**：单测可直接调用，不起 socket）。"""
    if not isinstance(payload, dict):
        return {"ok": False, "error": "request must be a JSON object"}
    if not token or payload.get("auth") != token:
        return {"ok": False, "error": "unauthorized"}
    op = (payload.get("op") or "").strip()
    if op == "eval":
        if not allow_eval:
            return {"ok": False, "error": "eval disabled（排障请显式 --allow-eval）"}
        return _run_eval(str(payload.get("code") or ""), payload.get("args") or {})
    fn = _OPS.get(op)
    if fn is None:
        return {"ok": False, "error": "unknown op %r（白名单：%s）" % (op, sorted(_OPS))}
    try:
        return {"ok": True, "result": fn(payload.get("args") or {})}
    except Exception as e:  # noqa: BLE001 — 边界：op 失败必须回包
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


def _read_line(conn, limit: int = MAX_REQUEST_BYTES) -> bytes:
    data = b""
    while len(data) < limit:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    return data


def main(argv=None):
    av = list(sys.argv[1:] if argv is None else argv)
    port = 0
    pidfile = ""
    ttl = 900.0
    allow_eval = False
    token = ""
    i = 0
    while i < len(av):
        a = av[i]
        if a == "--port" and i + 1 < len(av):
            port = int(av[i + 1]); i += 2
        elif a == "--pidfile" and i + 1 < len(av):
            pidfile = av[i + 1]; i += 2
        elif a == "--ttl" and i + 1 < len(av):
            ttl = float(av[i + 1]); i += 2
        elif a == "--token" and i + 1 < len(av):
            token = av[i + 1]; i += 2
        elif a == "--allow-eval":
            allow_eval = True; i += 1
        else:
            i += 1

    token = token or secrets.token_hex(16)
    # 启动时的代码指纹（第 4 行写 pidfile；同时作**每请求漂移自退**的基准，见下方循环）。
    epoch_start = _code_epoch()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))     # 只监听回环（不暴露到网络）
    server.listen(16)
    server.settimeout(1.0)
    actual_port = server.getsockname()[1]

    if pidfile:
        d = os.path.dirname(os.path.abspath(pidfile))
        os.makedirs(d, exist_ok=True)
        # 0600 + 五行：pid / port / token / code_epoch / transport（token 不进 argv，避免 ps 泄漏）
        # 第 4 行 = 本 daemon **实际 import 的那份代码** 的指纹；客户端每次比对（A7 接线，
        # 2026-10-29）—— 代码改动后旧 daemon 不得继续按旧逻辑作答（见 gk_worker_epoch.py）。
        # 第 5 行 = 传输协议标记：`transport2` 才允许 bash `/dev/tcp` 直连（免 python 客户端）；
        #   旧 daemon 无此行 ⟹ bash 快路自动不启用（回退 python 客户端，其仍做 epoch 比对）。
        fd = os.open(pidfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("%d\n%d\n%s\n%s\ntransport2\n" % (os.getpid(), actual_port, token, epoch_start))
    print("WORKER_READY:%d" % actual_port, flush=True)

    deadline = time.monotonic() + ttl if ttl and ttl > 0 else None
    # TTL 语义 = **空闲**超时（2026-10-29 修正）：原实现是「自启动起绝对截止」⟹ 一批连续调用
    #   跑到第 15 分钟时 daemon 仍在服务却被判过期，随后的调用白白吃一次冷启（1.7s）。
    #   现每次成功处理请求即续期（`last_activity`）。
    last_activity = time.monotonic()
    while True:
        if deadline is not None and (time.monotonic() - last_activity) > ttl:
            break
        try:
            conn, _addr = server.accept()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
        except Exception:      # noqa: BLE001
            continue
        try:
            conn.settimeout(30)
            raw = _read_line(conn)
            if not raw:
                continue
            try:
                payload = json.loads(raw.decode("utf-8", errors="replace").strip())
            except Exception:
                payload = None
            # 代码漂移自退（A7，2026-10-29）：每次请求前重算 epoch（8 次 stat，进程内 ~0.02s）。
            # 与启动时不符 ⟹ 回 ERR 并退出循环，让下一次 warm 拉起新代码（旧 daemon 绝不续答）。
            if _code_epoch() != epoch_start:
                conn.sendall(b"ERR epoch_changed\n")
                print("WORKER_RETIRE:epoch_changed", flush=True)
                break
            resp = handle_payload(payload, token, allow_eval)
            if isinstance(payload, dict) and payload.get("text"):
                # bash `/dev/tcp` 快路（transport2）：只回单行 `OK <字段值>` / `ERR <原因>`，
                # 免去 bash 侧解析 JSON（bash 无可靠 JSON 解析器）。
                if resp.get("ok"):
                    _v = (resp.get("result") or {}).get(str(payload.get("text")))
                    conn.sendall(("OK %s\n" % (_v if isinstance(_v, str) else "")).encode())
                else:
                    conn.sendall(("ERR %s\n" % str(resp.get("error") or "")[:200]
                                  .replace("\n", " ")).encode())
            else:
                conn.sendall(json.dumps(resp, ensure_ascii=False).encode() + b"\n")
            last_activity = time.monotonic()
        except Exception:      # noqa: BLE001 — 单连接失败不得拖垮 daemon
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    server.close()
    if pidfile:
        try:
            os.unlink(pidfile)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    main()
