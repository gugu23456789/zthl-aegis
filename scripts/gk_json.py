#!/usr/bin/env python3
"""gk_json.py — stdin JSON 通用工具（batch8 批次 2 高频内联聚类，2026-08-25）。

替代 gatekeeper-cli.sh 里"echo x | python3 -c 'import sys,json;...'" 高频模式：
- get:     stdin JSON → 提取字段（点路径，数字=列表索引；支持默认值）——L2382/2513/2400/3117 等
- count:   stdin JSON → 数组长度（len）——L1643/2570 等
- build:   构造 JSON（k=v，值支持 true/false/数字/字符串）——L2654/2668/2676 等 j= 构造
- pretty:  stdin JSON → indent=2 重排——L3005/3028 等

只读纯函数，零外部依赖。测试: scripts/test_gk_json.py。
"""
import json
import sys


def _dig(node, path_parts):
    """沿点路径取节点：dict 用键，list 用数字索引，缺失返回 None。"""
    for part in path_parts:
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if node is None:
            return None
    return node


def _split_path(path: str):
    return [p for p in path.split(".") if p]


def _default_coerce(raw: str):
    """CLI 默认值字符串 → 类型（true/false 大小写不敏感/数字/原样）。"""
    low = raw.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(raw.strip())
    except ValueError:
        pass
    try:
        return float(raw.strip())
    except ValueError:
        pass
    return raw


def cmd_get(stream, path: str, default: str | None = None) -> dict:
    data = json.load(stream)
    v = _dig(data, _split_path(path))
    if v is None and default is not None:
        v = _default_coerce(default)
    return {"ok": True, "value": v}


def cmd_count(stream, path: str) -> dict:
    data = json.load(stream)
    v = _dig(data, _split_path(path))
    return {"ok": True, "count": len(v) if isinstance(v, (list, dict)) else 0}


def cmd_build(pairs: list[tuple[str, str]]) -> dict:
    out = {}
    for k, v in pairs:
        out[k] = _default_coerce(v)
    return {"ok": True, "value": out}


def cmd_pretty(stream) -> dict:
    data = json.load(stream)
    return {"ok": True, "value": json.dumps(data, ensure_ascii=False, indent=2)}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.splitlines()[0])
        return 1
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "get" and rest:
            out = cmd_get(sys.stdin, rest[0], rest[1] if len(rest) > 1 else None)
            v = out["value"]
            if v is None:
                print("")
            elif isinstance(v, bool):
                # Python repr True/False（对齐原内联 print(get(k, False))，shell 侧 = "False" 判断依赖大写）
                print(v)
            elif isinstance(v, (dict, list)):
                # 复合值输出 JSON（对齐原内联 json.dumps(v) 语义，如 violations 数组）
                print(json.dumps(v, ensure_ascii=False))
            else:
                print(v)
            return 0
        if cmd == "count" and rest:
            out = cmd_count(sys.stdin, rest[0])
            print(out["count"])
            return 0
        if cmd == "build" and rest:
            pairs = [tuple(p.split("=", 1)) for p in rest if "=" in p]
            out = cmd_build(pairs)
            print(json.dumps(out["value"], ensure_ascii=False))
            return 0
        if cmd == "pretty":
            out = cmd_pretty(sys.stdin)
            s = out["value"]
            if rest and rest[0].isdigit():
                s = s[: int(rest[0])]   # 对齐原内联 [:3000] 截断（LLM 输出上限）
            print(s)
            return 0
    except json.JSONDecodeError as e:
        print(f'{{"ok":false,"error":"invalid json: {e}"}}')
        return 2
    except Exception as e:  # noqa: BLE001 — CLI 边界显式失败
        print(f'{{"ok":false,"error":"{type(e).__name__}: {e}"}}')
        return 2
    print('{"ok":false,"error":"usage: get <path> [default] | count <path> | build k=v... | pretty"}')
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
