#!/usr/bin/env python3
"""gk_req_body.py — LLM 请求体构造（batch8 批次 2 剩余，2026-08-26）。

替代 cmd_advance/monitor 的 req_body 内联 python3（L2403/L2405/L3714/L3716 语义等价）：
固定结构 {model, response_format:{type:json_object}, messages:[system,user]}，
reasoning_effort 非空时附加。content 由 json.dumps 自动 JSON 转义（保留 prompt 引号/换行）。

用法: SYSTEM_PROMPT=<sys> USER_PROMPT=<usr> python3 gk_req_body.py <model> [reasoning_effort]
输出: 紧凑 JSON（ensure_ascii 对齐原内联 json.dumps 默认 True）。
"""
import json
import os
import sys


def main(argv: list[str]) -> int:
    model = argv[0] if argv else ""
    effort = argv[1] if len(argv) > 1 else ""
    body = {
        "model": model,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": os.environ.get("SYSTEM_PROMPT", "")},
            {"role": "user", "content": os.environ.get("USER_PROMPT", "")},
        ],
    }
    if effort:
        body["reasoning_effort"] = effort
    print(json.dumps(body))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
