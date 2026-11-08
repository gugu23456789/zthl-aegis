#!/usr/bin/env python3
"""
Gatekeeper State Manager -- Shared state read/write + SHA256 checksum
====================================================================
Adapted from bridge-cli.py _read_state/_write_state pattern.
Format: JSON (not YAML -- consistent with Gatekeeper's existing scripts/*.py).

Usage:
  python3 scripts/gk_state.py read [--path <state_file>]
  python3 scripts/gk_state.py write <json_data> [--path <state_file>]
  python3 scripts/gk_state.py verify [--path <state_file>]
  python3 scripts/gk_state.py checksum [--path <state_file>]

Exit codes:
  0 = OK
  1 = Error (JSON output with error field)
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# R2（2026-09-22）：state 序列化单一事实源 —— 勿再内联 json.dump 直写 state。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_json_utils import dump_state, read_state_file  # noqa: E402
# B5（2026-10-27，RED-MIGRATE-INLINE）：`get` 子命令复用 `field` 的同一取值语义
# （区分「缺键」与「值恰为 null」）⟹ 不复制第二套 lookup（单源）。
from gk_json_utils import _MISSING, _cli_lookup  # noqa: E402
# §4.13.5③ 单源（`ECC-1EC0E0732F0D`）：默认落点解析不再自持第二套「env→指针→默认」判定，
# 统一委托 `gk_state_route`（指针选择 + 解析）。`gk_state_route` 模块级只依赖 stdlib ⟹ 无环。
from gk_state_route import resolve_state as _spp_resolve  # noqa: E402
from gk_state_route import select_plan_pointer as _spp_select  # noqa: E402

_SKILL_ROOT = Path(__file__).resolve().parent.parent

# Default state file path — 2026-08-13 修复：不再硬编码门卫项目路径。
# 解析顺序与 bash 侧（gatekeeper-cli.sh L75-87）一致：环境变量 STATE_FILE → plan 指针(.gatekeeper.plan) → 技能目录默认。
# 此前硬编码门卫项目导致 gk_escalate_resolve.py 与 bash cmd_resolve 双写入者写不同 state（不一致 bug）。
def _resolve_default_state() -> str:
    """薄壳：委托单一解析链（§4.13.5③ 单源，`ECC-1EC0E0732F0D`）。

    收敛前：本函数自持**第二套**「env → 全局指针 → 默认」判定（无 TTL / 无会话分片 / 无命令对账 /
    无域）⟹ 与 bash 链可得出**不同** state。现只做一次委托（指针选择 + 解析都在 `gk_state_route`）。
    """
    return os.environ.get("STATE_FILE", "") or (
        _spp_resolve(str(_SKILL_ROOT), os.environ.get("STATE_FILE", ""),
                     _spp_select(str(_SKILL_ROOT),
                                 session_id=os.environ.get("GK_SESSION_ID", ""),
                                 cmd_target_plan=os.environ.get("GK_CMD_TARGET_PLAN", ""),
                                 env_pointer=os.environ.get("PLAN_POINTER", ""),
                                 strict=os.environ.get("GK_PLAN_POINTER_STRICT", "0") == "1",
                                 domain_route=os.environ.get("GK_STATE_DOMAIN_ROUTE", "1"),
                                 state_file_explicit=bool(os.environ.get("STATE_FILE", ""))
                                 ).get("pointer", "")
                     ).get("expected") or str(_SKILL_ROOT / ".gatekeeper.state"))

DEFAULT_STATE_FILE = _resolve_default_state()


def _read_state(state_path: str) -> dict:
    """Read state file with SHA256 checksum verification.
    
    Returns state dict or error dict with 'error' key.
    Sets _checksum_warning if checksum mismatch detected.
    """
    p = Path(state_path)
    if not p.exists():
        return {"error": "state_file_not_found", "path": str(p)}
    
    # 2026-11-03（M1）：state 读 = checkpoint + WAL replay（与 update_state 写路径对称）。
    data = read_state_file(state_path)
    if "error" in data:
        return {"error": "json_decode_error", "detail": str(data["error"]), "path": str(p)}
    
    # Checksum verification
    stored_hash = data.get("_checksum", "")
    if stored_hash:
        gate_dump = json.dumps(data.get("gate_data", {}), sort_keys=True, ensure_ascii=True)
        computed = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
        if computed != stored_hash:
            data["_checksum_warning"] = (
                f"Checksum mismatch — gate_data may have been tampered. "
                f"Expected {stored_hash}, computed {computed}"
            )
    
    return data


def _write_state(data: dict, state_path: str) -> dict:
    """Write state file with automatic SHA256 checksum update.
    
    Returns {"ok": true} or error dict.
    """
    p = Path(state_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    
    # Update timestamp (bridge-cli.py pattern)
    data.setdefault("current", {})
    data["current"]["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Update checksum
    gate_dump = json.dumps(data.get("gate_data", {}), sort_keys=True, ensure_ascii=True)
    data["_checksum"] = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
    
    try:
        _ok = dump_state(p, data)
    except Exception as e:
        return {"error": "write_failed", "detail": str(e), "path": str(p)}
    # F-REV-20 禁静默：dump_state → write_json_file 的失败是**返回 False**（不抛）⟹
    # 原 try/except 只兜异常，会把"没写成"报成 ok:true。显式判返回值。
    if not _ok:
        return {"error": "write_failed", "detail": "dump_state returned False", "path": str(p)}
    
    return {"ok": True, "checksum": data["_checksum"]}


def _verify_checksum(state_path: str) -> dict:
    """Verify state file checksum without modifying it.
    
    Returns {"ok": true, "checksum": "..."} or error dict.
    If no checksum exists, returns {"ok": true, "checksum": computed, "verified": "no_checksum"}.
    """
    p = Path(state_path)
    if not p.exists():
        return {"error": "state_file_not_found", "path": str(p)}
    
    # 2026-11-03（M1）：校验**权威态**（checkpoint + WAL replay），不是旧 checkpoint。
    data = read_state_file(state_path)
    if "error" in data:
        return {"error": "json_decode_error", "detail": str(data["error"])}
    
    stored_hash = data.get("_checksum", "")
    gate_dump = json.dumps(data.get("gate_data", {}), sort_keys=True, ensure_ascii=True)
    computed = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
    
    if not stored_hash:
        # No checksum stored - not an error, just no verification possible
        return {"ok": True, "checksum": computed, "verified": "no_checksum"}
    elif stored_hash == computed:
        return {"ok": True, "checksum": computed, "verified": True}
    else:
        return {"ok": False, "stored": stored_hash, "computed": computed, "verified": False}


def _compute_checksum(state_path: str) -> dict:
    """Compute and update checksum for state file.
    
    Returns {"ok": true, "checksum": "..."} or error dict.
    """
    p = Path(state_path)
    if not p.exists():
        return {"error": "state_file_not_found", "path": str(p)}
    
    # 2026-11-03（M1）：基于**权威态**重算（checkpoint + WAL replay）。
    data = read_state_file(state_path)
    if "error" in data:
        return {"error": "json_decode_error", "detail": str(data["error"])}
    
    gate_dump = json.dumps(data.get("gate_data", {}), sort_keys=True, ensure_ascii=True)
    data["_checksum"] = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
    
    if not dump_state(p, data):
        return {"error": "write_failed", "detail": "dump_state returned False",
                "path": str(p)}

    return {"ok": True, "checksum": data["_checksum"]}


def _cmd_get(argv: list, state_path: str) -> int:
    """`get <dotted.path> [--default X] [--default-invalid Y] [--default-falsy Z]
    [--json [--indent N]] [--as T:F] [--path FILE]`。

    唯一读入口 = `_read_state`（checksum 校验只加 `_checksum_warning`，**不**改输出）：
      - 缺文件 / 坏 JSON / 根非 dict ⟹ `--default-invalid`（缺省回落 `--default`）
      - 缺键 ⟹ `--default`；`--default-falsy Z` 对齐旧 `... or Z`
      - `--json`：`json.dumps(val)`（`--indent N` 透传；`ensure_ascii` 保持默认 True）
        —— 值缺失时仍打印 `--default` 原文（对齐旧 `print(default)`）
      - `--as T:F`：真值判定后打印 T/F 且恒 exit 0（对齐旧 `print('yes' if cl else 'no')`）
    """
    usage = ("usage: gk_state.py get <dotted.path> [--default X] "
             "[--default-invalid Y] [--default-falsy Z] [--json [--indent N]] "
             "[--as T:F] [--path FILE]")
    if not argv:
        print(usage, file=sys.stderr)
        return 2
    path = argv[0]
    default = ""
    invalid_default = None
    falsy_default = None
    as_pair = None
    as_json = False
    indent = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--path" and i + 1 < len(argv):
            state_path = argv[i + 1]
            i += 2
        elif a == "--default" and i + 1 < len(argv):
            default = argv[i + 1]
            i += 2
        elif a == "--default-invalid" and i + 1 < len(argv):
            invalid_default = argv[i + 1]
            i += 2
        elif a == "--default-falsy" and i + 1 < len(argv):
            falsy_default = argv[i + 1]
            i += 2
        elif a == "--json":
            as_json = True
            i += 1
        elif a == "--indent" and i + 1 < len(argv):
            try:
                indent = int(argv[i + 1])
            except ValueError:
                print("get: --indent requires int", file=sys.stderr)
                return 2
            i += 2
        elif a == "--as" and i + 1 < len(argv):
            as_pair = argv[i + 1]
            i += 2
        else:
            print(usage, file=sys.stderr)
            return 2
    if as_pair is not None and ":" not in as_pair:
        print("get: --as requires T:F", file=sys.stderr)
        return 2
    try:
        data = _read_state(state_path)
    except (AttributeError, TypeError):
        # 根非 dict ⟹ `_read_state` 内 `data.get('_checksum')` 抛 AttributeError；
        # 对齐旧内联 `d.get(...)` 的同位失败（落默认档，不冒 traceback）
        data = {"error": "non_dict_root"}
    bad = (not isinstance(data, dict)) or ("error" in data)
    val = _MISSING if bad else _cli_lookup(data, path)
    if as_pair is not None:
        true_txt, _, false_txt = as_pair.partition(":")
        print(true_txt if (val is not _MISSING and bool(val)) else false_txt)
        return 0
    if val is _MISSING:
        # 读失败（缺文件/坏 JSON/根非 dict）走 `--default-invalid`；**缺键**走 `--default`
        print(invalid_default if (bad and invalid_default is not None) else default)
        return 0
    if falsy_default is not None and not val:
        print(falsy_default)
    elif as_json:
        print(json.dumps(val, indent=indent) if indent is not None else json.dumps(val))
    else:
        print(val)
    return 0


def main(argv=None):
    av = list(sys.argv[1:] if argv is None else argv)
    if len(av) < 1:
        print(json.dumps({"error": "usage: gk_state.py <read|write|verify|checksum|get> [--path <file>]"}))
        sys.exit(1)
    
    cmd = av[0]
    state_path = DEFAULT_STATE_FILE
    
    # Parse --path argument
    if "--path" in av:
        idx = av.index("--path")
        if idx + 1 < len(av):
            state_path = av[idx + 1]
    
    if cmd == "get":
        # 单路径投影：走 `_read_state` 唯一读入口（checksum 校验）；输出 = 单行值
        sys.exit(_cmd_get(av[1:], state_path))

    if cmd == "read":
        result = _read_state(state_path)
    elif cmd == "write":
        if len(av) < 2:
            print(json.dumps({"error": "usage: gk_state.py write <json_data> [--path <file>]"}))
            sys.exit(1)
        try:
            data = json.loads(av[1])
        except json.JSONDecodeError as e:
            print(json.dumps({"error": "invalid_json_input", "detail": str(e)}))
            sys.exit(1)
        result = _write_state(data, state_path)
    elif cmd == "verify":
        result = _verify_checksum(state_path)
    elif cmd == "checksum":
        result = _compute_checksum(state_path)
    else:
        print(json.dumps({"error": f"unknown command: {cmd}", "valid": ["read", "write", "verify", "checksum", "get"]}))
        sys.exit(1)
    
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result.get("ok", False) or "error" not in result else 1)


if __name__ == "__main__":
    main()
