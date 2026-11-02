"""test_gk_json.py — stdin JSON 通用工具测试（2026-08-25 批次 2 高频聚类）。

覆盖: get 嵌套路径/默认值/布尔/缺失 / count 数组与字典 / build 类型 coerce /
pretty indent / CLI 退出码与无效 JSON。纯函数直测（无 patch 标准库）。
"""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_json as gj


class TestGet:
    def test_nested_path(self):
        stream = io.StringIO('{"choices":[{"message":{"content":"hi"}}]}')
        out = gj.cmd_get(stream, "choices.0.message.content")
        assert out == {"ok": True, "value": "hi"}

    def test_default_false(self):
        stream = io.StringIO('{"allowed": false}')
        out = gj.cmd_get(stream, "allowed")
        assert out == {"ok": True, "value": False}

    def test_missing_with_default(self):
        stream = io.StringIO('{}')
        out = gj.cmd_get(stream, "ok", "False")
        assert out == {"ok": True, "value": False}

    def test_missing_no_default_none(self):
        stream = io.StringIO('{"a": 1}')
        out = gj.cmd_get(stream, "b.c")
        assert out["value"] is None

    def test_default_coerce_numeric(self):
        stream = io.StringIO('{}')
        out = gj.cmd_get(stream, "x", "0.5")
        assert out["value"] == 0.5


class TestCount:
    def test_list_length(self):
        stream = io.StringIO('{"findings": [1, 2, 3]}')
        out = gj.cmd_count(stream, "findings")
        assert out["count"] == 3

    def test_missing_path_zero(self):
        stream = io.StringIO('{}')
        out = gj.cmd_count(stream, "nope")
        assert out["count"] == 0


class TestBuild:
    def test_type_coerce(self):
        out = gj.cmd_build([("wt", "true"), ("n", "3"), ("s", "abc")])
        assert out["value"] == {"wt": True, "n": 3, "s": "abc"}

    def test_float_coerce(self):
        out = gj.cmd_build([("score", "0.75")])
        assert out["value"] == {"score": 0.75}


class TestPretty:
    def test_indent(self):
        stream = io.StringIO('{"a":1}')
        out = gj.cmd_pretty(stream)
        assert out["value"] == '{\n  "a": 1\n}'

    def test_ensure_ascii_false(self):
        stream = io.StringIO('{"k":"中文"}')
        out = gj.cmd_pretty(stream)
        assert "中文" in out["value"]


class TestCli:
    def test_get_prints_value(self, capsys):
        import subprocess
        r = subprocess.run([sys.executable, str(Path(gj.__file__)),
                            "get", "choices.0.message.content"],
                           input='{"choices":[{"message":{"content":"hi"}}]}',
                           capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 0 and r.stdout.strip() == "hi"

    def test_get_prints_python_bool_repr(self, capsys):
        """bool 输出 Python repr（True/False 大写），对齐原内联 print(get(k, False))。"""
        import subprocess
        r = subprocess.run([sys.executable, str(Path(gj.__file__)),
                            "get", "allowed", "false"],
                           input='{"allowed": false}',
                           capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 0 and r.stdout.strip() == "False"

    def test_invalid_json_exit_2(self):
        import subprocess
        r = subprocess.run([sys.executable, str(Path(gj.__file__)), "get", "a"],
                           input="not json",
                           capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 2
        assert "invalid json" in r.stdout
