#!/usr/bin/env python3
"""test_gk_context_build.py — B10g：`context --update` 的上下文构建器。

旧实现是 gatekeeper-cli.sh 内 ~60 行 `python3 -c`；本测试用**沙箱假 skill 目录**
复刻扫描面（行号生成、RED 引擎注入、gitnexus 层、失败/缺失降级）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_context_build.py"


def _run(*args, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(CLI)] + list(args),
                          input="", capture_output=True, text=True,
                          encoding="utf-8", env=e)


def _skill(tmp_path, with_runner=True, runner_markers=True, with_red=False,
           red_payload='{"findings": 2, "details": ["d1", "d2"]}'):
    sk = tmp_path / "skill"
    (sk / "scripts").mkdir(parents=True)
    lines = ["#!/bin/bash", "# fixture"]
    lines += ["cmd_advance() {", "  d.setdefault('rejected_edits', [])", "}"]
    lines += ["monitor_mode=api", "# tail"]
    (sk / "gatekeeper-cli.sh").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if with_runner:
        rl = ["import uuid"]
        if runner_markers:
            rl += ["class EccOutput(BaseModel):", "pass",
                   "nonce=uuid.uuid4().hex", "sig=hmac.new(k, m, 'sha256')",
                   "TOOL_REGISTRY = {'x': 1}", "# evidence 格式要求：每条 evidence 含 hash"]
        else:
            rl += ["pass"]
        (sk / "scripts" / "subagent_runner.py").write_text("\n".join(rl) + "\n",
                                                           encoding="utf-8")
    if with_red:
        (sk / "scripts" / "_red_attacks.py").write_text(
            "import json\nprint(json.dumps(%s))\n" % red_payload, encoding="utf-8")
    return str(sk)


def _state(tmp_path, obj):
    p = tmp_path / "state.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


class TestBuild:
    def test_full_scan(self, tmp_path):
        sk = _skill(tmp_path, with_red=True)
        st = _state(tmp_path, {"r_phase": "R7"})
        out = str(tmp_path / "ctx.json")
        p = _run("build", sk, st, out, env={"GK_GN_STATUS": "fresh"})
        assert p.returncode == 0, p
        res = json.loads(p.stdout)
        ctx = json.loads(Path(out).read_text(encoding="utf-8"))
        assert res == {"ok": True, "context_file": out, "files": len(ctx["files"])}
        assert ctx["r_phase"] == "R7"
        assert "scripts/subagent_runner.py L2-20 (EccOutput Pydantic model)" in ctx["files"]
        assert any("nonce generation" in f for f in ctx["files"])
        assert any("HMAC-SHA256 signing" in f for f in ctx["files"])
        assert any("TOOL_REGISTRY" in f for f in ctx["files"])
        assert any("evidence format requirements" in f for f in ctx["files"])
        assert any("cmd_advance — stage transition machine" in f for f in ctx["files"])
        assert any("rejected_edits cap=20 FIFO" in f for f in ctx["files"])
        assert any("monitor_mode --local/--api switching" in f for f in ctx["files"])
        assert ctx["red_findings"] == ["d1", "d2"] and ctx["red_count"] == 2
        assert ctx["gitnexus"] == {"repo": "spz-gatekeeper-r-sequence",
                                   "index_status": "fresh",
                                   "usage": "用 gx_query 语义搜索定位符号 → gx_context 看调用链"
                                            " → gx_impact 看爆破半径 → read 读文件行号"}
        assert Path(out).read_text(encoding="utf-8").startswith('{\n  "'), "indent=2"

    def test_no_red_engine_no_gitnexus_layer(self, tmp_path):
        """旧式的 gitnexus 注入嵌在 `if os.path.exists(red_attacks)` 内 ⟹ 无引擎则无该键。"""
        sk = _skill(tmp_path, with_red=False)
        st = _state(tmp_path, {})
        out = str(tmp_path / "ctx.json")
        assert _run("build", sk, st, out).returncode == 0
        ctx = json.loads(Path(out).read_text(encoding="utf-8"))
        assert "gitnexus" not in ctx and "red_findings" not in ctx
        # 空 state：r_phase 缺、stage 缺 ⟹ 默认 'IDLE'（'unknown' 只在读侧异常时保留）
        assert ctx["r_phase"] == "IDLE"

    def test_runner_missing(self, tmp_path):
        sk = _skill(tmp_path, with_runner=False)
        st = _state(tmp_path, {"stage": "ECO-DOC"})
        out = str(tmp_path / "ctx.json")
        _run("build", sk, st, out)
        ctx = json.loads(Path(out).read_text(encoding="utf-8"))
        assert ctx["r_phase"] == "ECO-DOC"
        assert ctx["files"][0] == "scripts/subagent_runner.py not found"

    def test_runner_without_markers(self, tmp_path):
        sk = _skill(tmp_path, runner_markers=False)
        out = str(tmp_path / "ctx.json")
        _run("build", sk, _state(tmp_path, {}), out)
        ctx = json.loads(Path(out).read_text(encoding="utf-8"))
        assert ctx["files"][0] == ("scripts/subagent_runner.py "
                                   "(auto-scan incomplete, run context --update again)")

    def test_red_engine_bad_output_swallowed(self, tmp_path):
        sk = _skill(tmp_path, with_red=True, red_payload="{oops")
        out = str(tmp_path / "ctx.json")
        p = _run("build", sk, _state(tmp_path, {}), out)
        assert p.returncode == 0, p
        ctx = json.loads(Path(out).read_text(encoding="utf-8"))
        assert "red_findings" not in ctx
        assert "gitnexus" in ctx          # 引擎存在 ⟹ gitnexus 层仍注入

    def test_usage_exit_2(self):
        assert _run().returncode == 2
        assert _run("build", "a", "b").returncode == 2
