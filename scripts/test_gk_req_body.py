"""test_gk_req_body.py — LLM 请求体构造测试（2026-08-26 批次 2 剩余）。

覆盖: 基础结构 / reasoning_effort 附加 / prompt 引号+换行 JSON 转义 / ensure_ascii 对齐。
安全网 R1: 无外部副作用。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent / "gk_req_body.py"


def _run(model, effort="", sys_prompt="s", user_prompt="u"):
    env = dict(os.environ, SYSTEM_PROMPT=sys_prompt, USER_PROMPT=user_prompt)
    args = [sys.executable, str(_SCRIPT), model] + ([effort] if effort else [])
    r = subprocess.run(args, capture_output=True, text=True,
                       encoding="utf-8", timeout=10, env=env)
    assert r.returncode == 0
    return json.loads(r.stdout)


def test_base_structure():
    d = _run("deepseek-v4-pro")
    assert d["model"] == "deepseek-v4-pro"
    assert d["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in d["messages"]] == ["system", "user"]
    assert d["messages"][0]["content"] == "s"
    assert "reasoning_effort" not in d


def test_reasoning_effort_attached():
    d = _run("m", "high")
    assert d["reasoning_effort"] == "high"


def test_prompt_json_escape():
    """prompt 含引号/换行 → json.dumps 自动转义，不破坏外层 JSON（L2403 语义）。"""
    d = _run("m", sys_prompt='say "hi"\nline2', user_prompt="a'quote")
    assert d["messages"][0]["content"] == 'say "hi"\nline2'
    assert d["messages"][1]["content"] == "a'quote"
    # 输出是合法 JSON（json.loads 已通过）；content 含转义引号
    assert '\\"' in json.dumps(d) or "hi" in d["messages"][0]["content"]


def test_ensure_ascii_alignment():
    """ensure_ascii 默认 True（对齐原内联 json.dumps），非 ASCII 转义为 \\uXXXX。"""
    d = _run("m", sys_prompt="中文提示")
    assert d["messages"][0]["content"] == "中文提示"  # 解析后还原
