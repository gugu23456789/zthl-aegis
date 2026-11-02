#!/usr/bin/env python3
"""
test_gk_state_query.py -- Tests for scripts/gk_state_query.py (batch8 R-T6 收尾批次 0)
=====================================================================================
Covers: --get (str/digit/bool/dict repr/default/nested-missing), --dump (indent/missing),
--len (list/dict/non-container), STATE_FILE env, missing state file, usage error.
CLI 契约：输出 + exit code 与旧 `python3 -c "import json;d=json.load(open(...));print(...)"` 等价。
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_state_query as gsq  # noqa: E402

SCRIPT = str(Path(__file__).resolve().parent / "gk_state_query.py")


def _run(args, state_file):
    env = dict(os.environ)
    env["STATE_FILE"] = state_file
    return subprocess.run(
        [sys.executable, SCRIPT] + args,
        capture_output=True, text=True, encoding="utf-8", env=env,
    )


@pytest.fixture
def rich_state(tmp_path):
    """含嵌套 gate_data/monitor_scores/history/appeal_records 的 state。"""
    sf = tmp_path / "state.json"
    data = {
        "r_phase": "R7.1",
        "stage": "STAGE_1",
        "gate_data": {
            "edit_count": 5,
            "entropy_called": True,
            "l4_review": "PASS",
            "best": {"score": 0.83},
            "commit_history": ["a1", "b2", "c3"],
        },
        "monitor_scores": {"STAGE_1": {"score": 0.6}},
        "appeal_records": {"G1": {"count": 2}},
        "history": ["h1", "h2"],
    }
    sf.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(sf)


# ---------- 函数级（import 直测） ----------

class TestGetPath:
    def test_nested_hit(self, rich_state):
        data = gsq._read_state(rich_state)
        assert gsq._get_path(data, "gate_data.edit_count") == 5

    def test_nested_miss(self, rich_state):
        data = gsq._read_state(rich_state)
        assert gsq._get_path(data, "gate_data.nonexistent") is None

    def test_root_miss(self, rich_state):
        data = gsq._read_state(rich_state)
        assert gsq._get_path(data, "no_such_root") is None

    def test_dotted_through_list_fails(self, rich_state):
        data = gsq._read_state(rich_state)
        assert gsq._get_path(data, "history.len") is None


class TestPyprint:
    def test_str_verbatim(self):
        assert gsq._pyprint("PASS") == "PASS"

    def test_bool_py_repr(self):
        assert gsq._pyprint(True) == "True"

    def test_int(self):
        assert gsq._pyprint(5) == "5"

    def test_dict_py_repr(self):
        # print({'a': 1}) → "{'a': 1}"（python repr，非 JSON）
        assert gsq._pyprint({"a": 1}) == "{'a': 1}"

    def test_list_py_repr(self):
        assert gsq._pyprint(["a", "b"]) == "['a', 'b']"


# ---------- CLI 级（subprocess，契约验证） ----------

class TestCliGet:
    def test_get_str(self, rich_state):
        r = _run(["--get", "gate_data.l4_review"], rich_state)
        assert r.returncode == 0 and r.stdout == "PASS\n"

    def test_get_int(self, rich_state):
        r = _run(["--get", "gate_data.edit_count"], rich_state)
        assert r.returncode == 0 and r.stdout == "5\n"

    def test_get_bool(self, rich_state):
        # 原 print(d.get(...)) 布尔 → "True"
        r = _run(["--get", "gate_data.entropy_called"], rich_state)
        assert r.returncode == 0 and r.stdout == "True\n"

    def test_get_nested_missing_with_default(self, rich_state):
        r = _run(["--get", "gate_data.no_field", "--default", "IDLE"], rich_state)
        assert r.returncode == 1 and r.stdout == "IDLE\n"

    def test_get_digit_default(self, rich_state):
        r = _run(["--get", "gate_data.no_count", "--default", "0"], rich_state)
        assert r.returncode == 1 and r.stdout == "0\n"


class TestCliDump:
    def test_dump_indent(self, rich_state):
        r = _run(["--dump", "gate_data.best"], rich_state)
        assert r.returncode == 0
        assert json.loads(r.stdout) == {"score": 0.83}
        assert r.stdout.startswith("{\n")  # indent=2 生效

    def test_dump_missing_returns_empty_dict(self, rich_state):
        # 路径缺失 → d.get(path, {}) 语义：旧 print(json.dumps({}, indent=2)) 输出 "{}"
        r = _run(["--dump", "gate_data.missing"], rich_state)
        assert r.returncode == 0 and r.stdout == "{}\n"

    def test_dump_state_not_readable_empty_stdout(self, tmp_path):
        # state 文件缺失 → 对齐旧 `2>/dev/null` 静默失败：空输出 + exit 1
        env = dict(os.environ)
        env["STATE_FILE"] = str(tmp_path / "missing.json")
        r = subprocess.run(
            [sys.executable, SCRIPT, "--dump", "gate_data"],
            capture_output=True, text=True, encoding="utf-8", env=env,
        )
        assert r.returncode == 1 and r.stdout == ""


class TestCliLen:
    def test_len_list(self, rich_state):
        r = _run(["--len", "gate_data.commit_history"], rich_state)
        assert r.returncode == 0 and r.stdout == "3\n"

    def test_len_dict(self, rich_state):
        r = _run(["--len", "appeal_records"], rich_state)
        assert r.returncode == 0 and r.stdout == "1\n"

    def test_len_non_container_default(self, rich_state):
        r = _run(["--len", "gate_data.edit_count", "--default", "0"], rich_state)
        assert r.returncode == 0 and r.stdout == "0\n"


class TestCliStateFile:
    def test_state_file_env_used(self, rich_state):
        # STATE_FILE 指向 rich_state，读顶层 stage
        r = _run(["--get", "stage"], rich_state)
        assert r.returncode == 0 and r.stdout == "STAGE_1\n"

    def test_state_not_found_default(self, tmp_path):
        env = dict(os.environ)
        env["STATE_FILE"] = str(tmp_path / "missing.json")
        r = subprocess.run(
            [sys.executable, SCRIPT, "--get", "stage", "--default", "IDLE"],
            capture_output=True, text=True, encoding="utf-8", env=env,
        )
        assert r.returncode == 1 and r.stdout == "IDLE\n"

    def test_usage_error(self, rich_state):
        r = _run(["--bogus"], rich_state)
        assert r.returncode == 2


class TestCliContains:
    def test_list_contains_yes(self, rich_state):
        # appeal_denied_gates 场景：list 含 value → yes
        r = _run(["--contains", "gate_data.commit_history", "b2"], rich_state)
        assert r.returncode == 0 and r.stdout == "yes\n"

    def test_list_contains_no(self, rich_state):
        r = _run(["--contains", "gate_data.commit_history", "zz"], rich_state)
        assert r.returncode == 0 and r.stdout == "no\n"

    def test_dict_key_yes(self, rich_state):
        # appeal_records.$gate 场景：dict 含 key → yes
        r = _run(["--contains", "appeal_records", "G1"], rich_state)
        assert r.returncode == 0 and r.stdout == "yes\n"

    def test_dict_key_no(self, rich_state):
        r = _run(["--contains", "appeal_records", "G9"], rich_state)
        assert r.returncode == 0 and r.stdout == "no\n"

    def test_path_missing_no(self, rich_state):
        # d.get('appeal_denied_gates',[]) 缺失 → no + exit 0（python 成功输出默认值，|| 不触发）
        r = _run(["--contains", "gate_data.appeal_denied_gates", "G1"], rich_state)
        assert r.returncode == 0 and r.stdout == "no\n"


class TestCliGt:
    def test_gt_yes(self, rich_state):
        r = _run(["--gt", "gate_data.edit_count", "3"], rich_state)
        assert r.returncode == 0 and r.stdout == "yes\n"

    def test_gt_no(self, rich_state):
        r = _run(["--gt", "gate_data.edit_count", "5"], rich_state)
        assert r.returncode == 0 and r.stdout == "no\n"

    def test_gt_non_numeric_no(self, rich_state):
        r = _run(["--gt", "gate_data.l4_review", "0"], rich_state)
        assert r.returncode == 0 and r.stdout == "no\n"

    def test_gt_missing_no(self, rich_state):
        r = _run(["--gt", "gate_data.no_count", "0"], rich_state)
        assert r.returncode == 0 and r.stdout == "no\n"


class TestCliTail:
    def test_tail_list(self, rich_state):
        # 对齐 json.dumps(list[-N:]) 紧凑格式（含空格分隔）
        r = _run(["--tail", "gate_data.commit_history", "2"], rich_state)
        assert r.returncode == 0 and json.loads(r.stdout) == ["b2", "c3"]
        assert "," in r.stdout and "\n  " not in r.stdout  # 紧凑非 indent

    def test_tail_missing_returns_empty_list(self, rich_state):
        r = _run(["--tail", "gate_data.no_log", "3"], rich_state)
        assert r.returncode == 0 and r.stdout == "[]\n"

    def test_tail_state_missing_empty_stdout(self, tmp_path):
        # state 文件缺失 → print("") 输出 "\n"，bash $(...) 捕获剥尾部换行 = 空（对齐旧 `2>/dev/null || echo '[]'` 失败路径）
        env = dict(os.environ)
        env["STATE_FILE"] = str(tmp_path / "missing.json")
        r = subprocess.run(
            [sys.executable, SCRIPT, "--tail", "gate_data.key_rotation_log", "3"],
            capture_output=True, text=True, encoding="utf-8", env=env,
        )
        assert r.returncode == 1 and r.stdout.strip() == ""

    def test_tail_indent_matches_legacy_dumps(self, rich_state):
        """B9c：`--tail ... --indent 2` 对齐旧 `json.dumps(recent, indent=2)`（cmd_reflect）。"""
        r = _run(["--tail", "gate_data.commit_history", "2", "--indent", "2"], rich_state)
        assert r.returncode == 0
        assert r.stdout == json.dumps(["b2", "c3"], indent=2) + "\n"

    def test_tail_indent_keeps_more_than_n_semantics(self, tmp_path):
        """`rej[-N:] if len>N else rej` ⟹ 不足 N 条时原样输出整表（与 val[-N:] 等价）。"""
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": {"rejected_edits": [1, 2]}}), encoding="utf-8")
        r = _run(["--tail", "gate_data.rejected_edits", "5", "--indent", "2"], str(sf))
        assert r.stdout == json.dumps([1, 2], indent=2) + "\n"

    def test_tail_indent_non_list_nonzero(self, tmp_path):
        """旧式对非 list 做 `rej[-N:]` 会 TypeError ⟹ rc≠0（禁静默输出 items）。"""
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": {"rejected_edits": {"a": 1}}}), encoding="utf-8")
        r = _run(["--tail", "gate_data.rejected_edits", "5", "--indent", "2"], str(sf))
        assert r.returncode != 0 and r.stdout.strip() == ""
