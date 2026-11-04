"""test_gk_json_utils.py — 专业 JSON 工具边界测试（2026-09-01）

覆盖用户质询的 cypher 多行 JSON 解析 bug 场景：
  - warn 行在结果之后（行首 `{` 定位的旧实现会取到 warn）
  - 多个 JSON 混杂（FTS warn + 结果）
  - 无 JSON（纯文本 detect-changes 输出）
  - 非 dict JSON（数组/标量）
  - 编码/多行嵌套/行内 `{` 不误判
  - 读取/写原子性
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_json_utils as u


class TestExtractLastJson:
    def test_warn_after_result(self):
        """warn 行在结果之后 → 取结果（旧"行首 {" 实现会误取 warn）。"""
        out = ('{\n  "markdown": "| c |\\n|---|\\n| 42 |",\n  "row_count": 1\n}\n'
               '{"level":40,"msg":"FTS warn"}\n')
        obj = u.extract_last_json(out)
        assert obj is not None
        assert obj["row_count"] == 1

    def test_warn_before_result(self):
        """warn 行在结果之前 → 取结果。"""
        out = ('{"level":40,"msg":"warn"}\n'
               '{"markdown": "| c |\\n|---|\\n| 7 |", "row_count": 1}\n')
        obj = u.extract_last_json(out)
        assert obj["row_count"] == 1

    def test_multiple_json_takes_last(self):
        """多个 JSON 混杂 → 取结束位置最靠后的完整对象。"""
        out = ('{"a": 1}\n'
               '{"a": 2, "b": [1,2,3]}\n'
               '{"markdown": "x", "row_count": 9}\n')
        obj = u.extract_last_json(out)
        assert obj == {"markdown": "x", "row_count": 9}

    def test_nested_multi_line_json(self):
        """多行嵌套 JSON（pretty-print）→ 完整解析。"""
        out = ('{\n  "stats": {\n    "cdg": 8062,\n    "inner": {"deep": true}\n  },\n'
               '  "row_count": 3\n}\n')
        obj = u.extract_last_json(out)
        assert obj["stats"]["cdg"] == 8062
        assert obj["stats"]["inner"]["deep"] is True
        assert obj["row_count"] == 3

    def test_no_json_pure_text(self):
        """纯文本（detect-changes 输出形态）→ None。"""
        out = "变更：12 个文件，50 个符号\n受影响流程：8\n风险等级：high\n"
        assert u.extract_last_json(out) is None

    def test_empty_input(self):
        assert u.extract_last_json("") is None
        assert u.extract_last_json(None) is None

    def test_non_dict_json(self):
        """JSON 数组/标量 → None（只认 dict 结果）。"""
        assert u.extract_last_json("[1, 2, 3]") is None
        assert u.extract_last_json('"hello"') is None
        assert u.extract_last_json("42") is None

    def test_brace_in_text_not_confused(self):
        """文本内 `{`（如 markdown 表格 `| {"a":1} |`）不误判为 JSON 起点。"""
        out = '| {"a":1} | {"b":2} |\n{"markdown": "ok", "row_count": 5}\n'
        obj = u.extract_last_json(out)
        assert obj == {"markdown": "ok", "row_count": 5}

    def test_dict_inside_text_value(self):
        """结果 JSON 内字符串值含 { }（escaped）→ 完整解析。"""
        out = '{"detail": "saw {x} and {y}", "row_count": 2}\n'
        obj = u.extract_last_json(out)
        assert obj["detail"] == "saw {x} and {y}"

    def test_unicode_chinese(self):
        out = '{"markdown": "风险等级：high", "row_count": 1}\n'
        obj = u.extract_last_json(out)
        assert obj["markdown"] == "风险等级：high"


class TestReadWrite:
    def test_read_missing(self, tmp_path):
        d = u.read_json_file(tmp_path / "nope.json")
        assert "error" in d

    def test_read_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        d = u.read_json_file(p)
        assert "error" in d

    def test_read_ok(self, tmp_path):
        p = tmp_path / "ok.json"
        p.write_text('{"a": 1}', encoding="utf-8")
        d = u.read_json_file(p)
        assert d == {"a": 1}

    def test_write_atomic_roundtrip(self, tmp_path):
        p = tmp_path / "out.json"
        assert u.write_json_file(p, {"中文": "值", "n": 3}) is True
        d = u.read_json_file(p)
        assert d == {"中文": "值", "n": 3}

    def test_write_mkdir_parents(self, tmp_path):
        p = tmp_path / "sub" / "dir" / "out.json"
        assert u.write_json_file(p, {"a": 1}) is True
        assert p.exists()

    def test_write_overwrites_existing(self, tmp_path):
        p = tmp_path / "out.json"
        u.write_json_file(p, {"a": 1})
        u.write_json_file(p, {"a": 2})
        assert u.read_json_file(p) == {"a": 2}


class TestReplaceRetry:
    """2026-10-07 压测长尾：os.replace 瞬态 PermissionError 的有界重试（回归臂）。"""

    def test_transient_permission_error_is_retried(self, tmp_path, monkeypatch):
        calls = {"n": 0}
        real = u.os.replace

        def flaky(a, b):
            calls["n"] += 1
            if calls["n"] <= 3:
                raise PermissionError(13, "拒绝访问。")
            return real(a, b)

        monkeypatch.setattr(u.os, "replace", flaky)
        p = tmp_path / "out.json"
        assert u.write_json_file(p, {"a": 1}) is True
        assert calls["n"] == 4, "瞬态失败应重试至成功"
        assert u.read_json_file(p) == {"a": 1}

    def test_persistent_permission_error_fails_loud(self, tmp_path, monkeypatch):
        monkeypatch.setattr(u, "_REPLACE_RETRY_MAX", 3)

        def always(a, b):
            raise PermissionError(13, "拒绝访问。")

        monkeypatch.setattr(u.os, "replace", always)
        p = tmp_path / "out.json"
        assert u.write_json_file(p, {"a": 1}) is False, "耗尽重试后仍 fail-loud"

    def test_non_transient_error_not_retried(self, tmp_path, monkeypatch):
        calls = {"n": 0}

        def err(a, b):
            calls["n"] += 1
            raise OSError(2, "no such file")       # ENOENT：非瞬态

        monkeypatch.setattr(u.os, "replace", err)
        p = tmp_path / "out.json"
        assert u.write_json_file(p, {"a": 1}) is False
        assert calls["n"] == 1, "非瞬态错误不得重试"


class TestExtractMarkdownInt:
    def test_standard_table(self):
        assert u.extract_markdown_int({"markdown": "| c |\n|---|\n| 42 |"}) == 42

    def test_no_markdown_field(self):
        assert u.extract_markdown_int({}) is None

    def test_non_numeric_tail(self):
        assert u.extract_markdown_int({"markdown": "| c |\n|---|\n| N/A |"}) is None

    def test_markdown_absent_in_dict(self):
        d = {"markdown": None}
        assert u.extract_markdown_int(d) is None


class TestExtractMarkdownTable:
    """专业 markdown 表格解析（2026-09-01 用户质询 _count 需表格解析函数）。"""

    def test_multi_column(self):
        md = "| a | b |\n|---|---|\n| 1 | x |\n| 2 | y |"
        rows = u.extract_markdown_table(md)
        assert rows == [["1", "x"], ["2", "y"]]

    def test_count_multi_column_last_row(self):
        """多列表格计数：取末行第一个整数单元格。"""
        md = "| file | cnt |\n|------|-----|\n| a.py | 7 |\n| b.py | 3 |"
        assert u.extract_markdown_int({"markdown": md}) == 3

    def test_count_first_int_col(self):
        """多列但数字在首列 → 取到数字。"""
        md = "| cnt | name |\n|-----|------|\n| 12 | main.py |"
        assert u.extract_markdown_int({"markdown": md}) == 12

    def test_separator_variants(self):
        """分隔行变体（:-: / --- / :--）均跳过。"""
        md = "| a | b |\n|:-:|:--|\n| 1 | 2 |"
        assert u.extract_markdown_table(md) == [["1", "2"]]

    def test_no_table(self):
        assert u.extract_markdown_table("纯文本\n无表格") == []

    def test_empty_cells(self):
        md = "| a | b |\n|---|----|\n| 1 | |"
        assert u.extract_markdown_table(md) == [["1", ""]]

    def test_negative_count(self):
        md = "| c |\n|---|\n| -3 |"
        assert u.extract_markdown_int({"markdown": md}) == -3


class TestJsonGet:
    def test_nested_path(self):
        obj = {"a": {"b": [10, 20]}}
        assert u.json_get(obj, "a.b.1") == 20

    def test_missing_default(self):
        assert u.json_get({}, "x.y", "dft") == "dft"

    def test_empty_path_returns_obj(self):
        obj = {"k": 1}
        assert u.json_get(obj, "") == obj

    def test_list_index_out_of_range(self):
        assert u.json_get([1], "5", "d") == "d"


class TestCliField:
    """CLI 面（2026-10-26，锚 RED-MIGRATE-INLINE）：`field` 子命令。

    `gatekeeper-cli.sh` 实测 212 处 `python3 -c`，其中「纯取字段」形态（load → 单
    `.get(k, d)` → print）约 30 处（转义地狱 / 不可单测）。本子命令 = 其公共收敛点：
    非法 JSON / 缺字段 / 非 dict ⟹ 输出 default 且 **exit 0**（与旧 `except: print(default)` 等价）。
    """

    def _run(self, args, stdin_text="", env=None):
        import subprocess
        p = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_json_utils.py")] + args,
            input=stdin_text, capture_output=True, text=True, encoding="utf-8", env=env)
        return p

    def test_field_plain(self):
        p = self._run(["field", "path", "--default", ""], '{"path": "/repo/x"}')
        assert p.returncode == 0 and p.stdout.strip() == "/repo/x", p

    def test_field_dotted_and_index(self):
        p = self._run(["field", "a.b.0", "--default", "-"], '{"a": {"b": ["z"]}}')
        assert p.stdout.strip() == "z", p

    def test_field_missing_uses_default(self):
        p = self._run(["field", "nope", "--default", "unknown repo"], '{"a": 1}')
        assert p.returncode == 0 and p.stdout.strip() == "unknown repo", p

    def test_field_bad_json_uses_default(self):
        p = self._run(["field", "x", "--default", ""], "not json at all")
        assert p.returncode == 0 and p.stdout.strip() == "", p

    def test_field_empty_stdin_uses_default(self):
        p = self._run(["field", "x", "--default", "d"], "")
        assert p.returncode == 0 and p.stdout.strip() == "d", p

    def test_field_file_input(self, tmp_path):
        f = tmp_path / "d.json"
        f.write_text('{"k": "v"}', encoding="utf-8")
        p = self._run(["field", "k", "--file", str(f)])
        assert p.stdout.strip() == "v", p

    def test_field_default_invalid_only_on_parse_error(self):
        """`--default-invalid` 只覆盖解析失败；缺字段仍走 `--default`。

        旧实现两档分离：`d.get('k','missing')` vs `except: print('unparsable')`；
        单 `--default` 会把「合法 JSON 但缺键」错报成解析失败档。
        实测样本 `_resolve_repo_path` L827：`get('error','unknown repo')` /
        `except: 'unknown repo: <name>'`。
        """
        args = ["field", "error", "--default", "unknown repo",
                "--default-invalid", "unknown repo: supply-chain"]
        p1 = self._run(args, '{"repo": "supply-chain"}')
        assert p1.returncode == 0 and p1.stdout.strip() == "unknown repo", p1
        p2 = self._run(args, "")
        assert p2.returncode == 0 and p2.stdout.strip() == "unknown repo: supply-chain", p2
        p3 = self._run(args, '{"error": "unknown repo \'x\'"}')
        assert p3.stdout.strip() == "unknown repo 'x'", p3

    def test_field_non_dict_root_uses_default_invalid(self):
        """根不是 dict ⟹ 走「解析失败」档（对齐旧 `d.get()` 抛 AttributeError）。"""
        args = ["field", "path", "--default", "unknown repo",
                "--default-invalid", "unknown repo: r"]
        for raw in ("[]", '"scalar"', "null", "42"):
            p = self._run(args, raw)
            assert p.returncode == 0 and p.stdout.strip() == "unknown repo: r", (raw, p)

    def test_field_explicit_null_prints_none(self):
        """显式 `null` **不是**缺字段：旧 `d.get('k', 0)` 返回 None ⟹ `print` 出 "None"。

        `json_get` 把 None 当缺失（对其他消费者是对的）⟹ CLI 必须自己区分，
        否则 `{"count": null}` 会被静默改成 "0"（值域变化）。
        """
        p = self._run(["field", "count", "--default", "0"], '{"count": null}')
        assert p.returncode == 0 and p.stdout.strip() == "None", p
        p2 = self._run(["field", "ok", "--default", "False"], '{"ok": null}')
        assert p2.stdout.strip() == "None", p2
        p3 = self._run(["field", "ok", "--default", "False"], '{}')
        assert p3.stdout.strip() == "False", p3

    # ── B2（2026-10-27，RED-MIGRATE-INLINE 批次 2）：`--env` / `--default-falsy` ──

    def test_field_env_source_ignores_stdin(self):
        """`--env` 从环境变量读 JSON，**不**读 stdin（stdin 喂垃圾也不影响）。"""
        import os
        env = dict(os.environ, GK_TEST_PAYLOAD='{"lock": "abc"}')
        p = self._run(["field", "lock", "--env", "GK_TEST_PAYLOAD", "--default", ""],
                      "NOT JSON AT ALL", env=env)
        assert p.returncode == 0 and p.stdout.strip() == "abc", p

    def test_field_env_unset_or_empty_means_empty_dict(self):
        """空/未设 ⟹ `{}`（对齐旧 `os.environ.get(VAR) or '{}'`），缺键走 `--default`。"""
        import os
        for raw in (None, "", "   "):
            env = dict(os.environ)
            env.pop("GK_TEST_PAYLOAD", None)
            if raw is not None:
                env["GK_TEST_PAYLOAD"] = raw
            p = self._run(["field", "lock", "--env", "GK_TEST_PAYLOAD", "--default", "-"],
                          "", env=env)
            assert p.returncode == 0 and p.stdout.strip() == "-", (raw, p)

    def test_field_env_bad_json_and_non_dict_root(self):
        """坏 JSON / 非 dict 根 ⟹ `--default-invalid`（对齐旧实现抛异常后的空输出）。"""
        import os
        for raw in ("garbage", "null", "[]", "42"):
            env = dict(os.environ, GK_TEST_PAYLOAD=raw)
            p = self._run(["field", "lock", "--env", "GK_TEST_PAYLOAD", "--default", "D",
                           "--default-invalid", "INV"], "", env=env)
            assert p.returncode == 0 and p.stdout.strip() == "INV", (raw, p)

    def test_field_env_and_file_are_mutually_exclusive(self, tmp_path):
        f = tmp_path / "d.json"
        f.write_text('{"k": "v"}', encoding="utf-8")
        p = self._run(["field", "k", "--env", "GK_TEST_PAYLOAD", "--file", str(f)])
        assert p.returncode == 2, p

    def test_field_default_falsy_matches_or_chain(self):
        """`--default-falsy` = 旧 `.get(k, D) or Z`：falsy 值一律出 Z，非空值原样出。"""
        args = ["field", "tier", "--default", "", "--default-falsy", ""]
        for raw in ('{"tier": null}', '{"tier": false}', '{"tier": 0}',
                    '{"tier": ""}', '{"tier": []}'):
            p = self._run(args, raw)
            assert p.returncode == 0 and p.stdout.strip() == "", (raw, p)
        # 未带 `--default-falsy` 时保持旧 `print(val)` 语义（null → "None"）
        p = self._run(["field", "tier", "--default", ""], '{"tier": null}')
        assert p.stdout.strip() == "None", p
        # 非空值不被压成空串
        for raw, want in (('{"tier": "T2"}', "T2"), ('{"tier": "0"}', "0"),
                          ('{"tier": 3}', "3"), ('{"tier": [1]}', "[1]")):
            p = self._run(args, raw)
            assert p.stdout.strip() == want, (raw, p)

    def test_field_default_falsy_does_not_shadow_missing_default(self):
        """缺键仍走 `--default`（不是 `--default-falsy`）—— 对齐 `.get(k, D)` 的取值顺序。"""
        p = self._run(["field", "nope", "--default", "D", "--default-falsy", "Z"], '{}')
        assert p.returncode == 0 and p.stdout.strip() == "D", p


class TestCliPredicate:
    """谓词通道（2026-10-27，RED-MIGRATE-INLINE 批次 3）：`test` / `valid`。

    这批站点**rc 就是输出**（`if ... ; then` 直接消费退出码）⟹ 语义逐位对齐：
    `test` 默认真值判定；`--is/--not-is` 用 isinstance；`--as T:F` 打印且恒 exit 0；
    `--first-line` 对齐旧 `json.loads(sys.stdin.readline())`；`valid` 对齐旧 `json.load`。
    """

    def _run(self, args, stdin_text=""):
        import subprocess
        p = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_json_utils.py")] + args,
            input=stdin_text, capture_output=True, text=True, encoding="utf-8")
        return p

    def test_truthiness_exit_code(self):
        for raw, want in (('{"ok": true}', 0), ('{"ok": 1}', 0), ('{"ok": "x"}', 0),
                          ('{"ok": ""}', 1), ('{"ok": 0}', 1), ('{"ok": null}', 1),
                          ('{}', 1), ('[]', 1), ('"scalar"', 1), ('null', 1),
                          ('42', 1), ('', 1), ('garbage', 1)):
            p = self._run(["test", "ok"], raw)
            assert p.returncode == want, (raw, p)
            assert p.stdout == "", (raw, p)

    def test_dotted_path_truthiness(self):
        assert self._run(["test", "a.b"], '{"a": {"b": [1]}}').returncode == 0
        assert self._run(["test", "a.b"], '{"a": {"b": []}}').returncode == 1
        assert self._run(["test", "a.0"], '{"a": [0]}').returncode == 1
        assert self._run(["test", "a.1"], '{"a": [0, 1]}').returncode == 0

    def test_is_str_is_instance_not_truthiness(self):
        """`--is str` 沿用旧 `isinstance`：空串判真、缺键判假。"""
        for raw, want in (('{"error": "x"}', 0), ('{"error": ""}', 0),
                          ('{"error": 1}', 1), ('{"error": null}', 1),
                          ('{}', 1), ('{"error": ["x"]}', 1), ('garbage', 1)):
            p = self._run(["test", "error", "--is", "str"], raw)
            assert p.returncode == want, (raw, p)

    def test_not_is_str(self):
        """`--not-is str`：缺键/非 str 判真；解析失败仍判假（对齐旧 `except: sys.exit(1)`）。"""
        for raw, want in (('{"error": 1}', 0), ('{}', 0), ('{"error": null}', 0),
                          ('{"error": "x"}', 1), ('{"error": ""}', 1),
                          ('garbage', 1), ('[]', 1)):
            p = self._run(["test", "error", "--not-is", "str"], raw)
            assert p.returncode == want, (raw, p)

    def test_first_line_only(self):
        """`--first-line` 对齐旧 `json.loads(sys.stdin.readline())`：多行 JSON 判假。"""
        assert self._run(["test", "error", "--is", "str", "--first-line"],
                         '{"error": "x"}\n{"junk": 1}').returncode == 0
        assert self._run(["test", "error", "--is", "str", "--first-line"],
                         '{"error":\n"x"}').returncode == 1
        # 不带 `--first-line` 时整份解析 ⟹ 同一输入判真
        assert self._run(["test", "error", "--is", "str"],
                         '{"error":\n"x"}').returncode == 0

    def test_as_prints_and_always_zero(self):
        p = self._run(["test", "ok", "--as", "1:0"], '{"ok": true}')
        assert p.returncode == 0 and p.stdout == "1\n", p
        p = self._run(["test", "ok", "--as", "1:0"], '{"ok": false}')
        assert p.returncode == 0 and p.stdout == "0\n", p
        p = self._run(["test", "ok", "--as", "1:0"], "garbage")
        assert p.returncode == 0 and p.stdout == "0\n", p

    def test_bad_args_exit_2(self):
        assert self._run(["test", "ok", "--is", "wat"], "{}").returncode == 2
        assert self._run(["test", "ok", "--as", "nocolon"], "{}").returncode == 2
        assert self._run(["test"], "{}").returncode == 2

    def test_valid_accepts_any_json_root(self):
        for raw in ("{}", "[]", '"s"', "null", "42", "true", '{"a":\n 1}'):
            p = self._run(["valid"], raw)
            assert p.returncode == 0 and p.stdout == "", (raw, p)
        for raw in ("", "  ", "garbage", '{"a": }', "{"):
            p = self._run(["valid"], raw)
            assert p.returncode == 1 and p.stdout == "", (raw, p)


class TestCliEscape:
    """`escape` 子命令（2026-10-27，RED-MIGRATE-INLINE 批次 4）。

    对齐旧 `print(json.dumps(sys.stdin.read()[:N]))` / `... .strip()`：
    `json.dumps` 默认 `ensure_ascii=True`（中文出 `\\uXXXX`），顺序 = 先 strip 后截断。
    """

    def _run(self, args, stdin_text=""):
        import subprocess
        p = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_json_utils.py")] + args,
            input=stdin_text, capture_output=True, text=True, encoding="utf-8")
        return p

    def test_escape_plain(self):
        p = self._run(["escape"], "abc")
        assert p.returncode == 0 and p.stdout == '"abc"\n', p

    def test_escape_empty(self):
        p = self._run(["escape"], "")
        assert p.returncode == 0 and p.stdout == '""\n', p

    def test_escape_strip(self):
        p = self._run(["escape", "--strip"], "  abc \n\n")
        assert p.stdout == '"abc"\n', p

    def test_escape_limit(self):
        p = self._run(["escape", "--limit", "3"], "abcdef")
        assert p.stdout == '"abc"\n', p
        p = self._run(["escape", "--limit", "0"], "abcdef")
        assert p.stdout == '""\n', p

    def test_escape_strip_then_limit(self):
        p = self._run(["escape", "--strip", "--limit", "3"], "  abcdef  ")
        assert p.stdout == '"abc"\n', p

    def test_escape_unicode_ascii_escaped(self):
        """`ensure_ascii=True` 默认值必须保留（旧式逐字节一致）。"""
        p = self._run(["escape"], "中文")
        assert p.stdout == '"\\u4e2d\\u6587"\n', p

    def test_escape_control_chars_and_quotes(self):
        p = self._run(["escape"], 'a"b\\c\nd\te')
        assert p.stdout == '"a\\"b\\\\c\\nd\\te"\n', p

    def test_escape_bad_args_exit_2(self):
        assert self._run(["escape", "--limit", "x"], "a").returncode == 2
        assert self._run(["escape", "--bogus"], "a").returncode == 2


class TestCliFieldDerive:
    """`field` 派生投影（2026-10-27，RED-MIGRATE-INLINE 批次 7）。

    覆盖旧式「单键 + 派生」（len / bool / join / keys / first / b64）与
    `--strict-path`（中间节点缺失 ⟹ 解析失败档，对齐旧 `['a']['b']` 的 KeyError）。
    """

    def _run(self, args, stdin_text=""):
        import subprocess
        p = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_json_utils.py")] + args,
            input=stdin_text, capture_output=True, text=True, encoding="utf-8")
        return p

    def _run_bytes(self, args, stdin_text=""):
        import subprocess
        p = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_json_utils.py")] + args,
            input=stdin_text.encode("utf-8"), capture_output=True)
        return p

    # ── --len ──────────────────────────────────────────────
    def test_len_list(self):
        p = self._run(["field", "v", "--len"], '{"v": [1, 2, 3]}')
        assert p.returncode == 0 and p.stdout == "3\n", p

    def test_len_missing_and_falsy_zero(self):
        assert self._run(["field", "v", "--len"], '{"a": 1}').stdout == "0\n"
        for val in ('null', 'false', '0', '""', '[]', '{}'):
            p = self._run(["field", "v", "--len"], '{"v": %s}' % val)
            assert p.stdout == "0\n", (val, p)

    def test_len_invalid_uses_default_invalid(self):
        p = self._run(["field", "v", "--len", "--default-invalid", "0"], "not json")
        assert p.returncode == 0 and p.stdout == "0\n", p

    # ── --len-list ────────────────────────────────────────
    def test_len_list_only_counts_lists(self):
        assert self._run(["field", "v", "--len-list"], '{"v": [1, 2]}').stdout == "2\n"
        assert self._run(["field", "v", "--len-list"], '{"v": {"a": 1, "b": 2}}').stdout == "0\n"
        assert self._run(["field", "v", "--len-list"], '{"v": "abc"}').stdout == "0\n"
        assert self._run(["field", "v", "--len-list"], '{"a": 1}').stdout == "0\n"
        assert self._run(["field", "v", "--len-list", "--default-invalid", "0"],
                         "bad").stdout == "0\n"

    # ── --bool-tf ─────────────────────────────────────────
    def test_bool_tf(self):
        assert self._run(["field", "v", "--bool-tf"], '{"v": true}').stdout == "true\n"
        assert self._run(["field", "v", "--bool-tf"], '{"v": false}').stdout == "false\n"
        assert self._run(["field", "v", "--bool-tf"], '{"a": 1}').stdout == "false\n"
        assert self._run(["field", "v", "--bool-tf", "--default-invalid", ""],
                         "bad").stdout == "\n"

    # ── --join / --subkey ─────────────────────────────────
    def test_join_root_list_subkey(self):
        p = self._run(["field", "", "--join", "; ", "--subkey", "label"],
                      '[{"label": "a"}, {"label": "b"}]')
        assert p.returncode == 0 and p.stdout == "a; b\n", p

    def test_join_subkey_missing_yields_empty_part(self):
        p = self._run(["field", "", "--join", "; ", "--subkey", "label"],
                      '[{"label": "a"}, {"x": 1}]')
        assert p.stdout == "a; \n", p

    def test_join_non_dict_item_uses_default_invalid(self):
        p = self._run(["field", "", "--join", "; ", "--subkey", "label",
                       "--default-invalid", "FALLBACK"], '["a"]')
        assert p.returncode == 0 and p.stdout == "FALLBACK\n", p

    def test_join_invalid_json_uses_default_invalid(self):
        p = self._run(["field", "", "--join", "; ", "--subkey", "label",
                       "--default-invalid", "FALLBACK"], "bad")
        assert p.stdout == "FALLBACK\n", p

    # ── --keys-join ───────────────────────────────────────
    def test_keys_join(self):
        p = self._run(["field", "incoming", "--keys-join", ","],
                      '{"incoming": {"a": 1, "b": 2}}')
        assert p.returncode == 0 and p.stdout == "a,b\n", p

    def test_keys_join_missing_and_non_dict_empty(self):
        assert self._run(["field", "incoming", "--keys-join", ","],
                         '{"x": 1}').stdout == "\n"
        assert self._run(["field", "incoming", "--keys-join", ","],
                         '{"incoming": [1]}').stdout == "\n"
        assert self._run(["field", "incoming", "--keys-join", ","],
                         "bad").stdout == "\n"

    # ── --first-json ──────────────────────────────────────
    def test_first_json(self):
        p = self._run(["field", "checks", "--first-json"],
                      '{"checks": [{"check": "a", "status": "PASS"}, {"check": "b"}]}')
        assert p.returncode == 0 and p.stdout == '{"check": "a", "status": "PASS"}\n', p

    def test_first_json_empty_or_missing(self):
        assert self._run(["field", "checks", "--first-json"], '{"checks": []}').stdout == "\n"
        assert self._run(["field", "checks", "--first-json"], '{"x": 1}').stdout == "\n"
        assert self._run(["field", "checks", "--first-json"], "bad").stdout == "\n"

    # ── --strict-path ─────────────────────────────────────
    def test_strict_path_intermediate_missing_is_invalid(self):
        args = ["field", "shellcheck_scan.counts.sc2034_unused",
                "--strict-path", "--default", "0", "--default-invalid", "INVALID"]
        assert self._run(args, '{"shellcheck_scan": {"total": 3}}').stdout == "INVALID\n"
        assert self._run(args, '{"x": 1}').stdout == "INVALID\n"
        assert self._run(args, "bad").stdout == "INVALID\n"

    def test_strict_path_final_missing_uses_default(self):
        args = ["field", "shellcheck_scan.counts.sc2034_unused",
                "--strict-path", "--default", "0", "--default-invalid", "INVALID"]
        assert self._run(args, '{"shellcheck_scan": {"counts": {}}}').stdout == "0\n"
        assert self._run(
            args, '{"shellcheck_scan": {"counts": {"sc2034_unused": 7}}}').stdout == "7\n"

    def test_strict_path_non_dict_intermediate_is_invalid(self):
        args = ["field", "a.b", "--strict-path", "--default", "D", "--default-invalid", "I"]
        assert self._run(args, '{"a": 1}').stdout == "I\n"

    # ── --b64 ─────────────────────────────────────────────
    def test_b64_raw_bytes(self):
        p = self._run_bytes(["field", "sig", "--b64"], '{"sig": "aGVsbG8="}')
        assert p.returncode == 0 and p.stdout == b"hello", p

    def test_b64_missing_or_invalid_empty(self):
        assert self._run_bytes(["field", "sig", "--b64"], '{"x": 1}').stdout == b""
        assert self._run_bytes(["field", "sig", "--b64"], "bad").stdout == b""
