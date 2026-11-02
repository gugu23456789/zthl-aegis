#!/usr/bin/env python3
"""
H1 性能落刀回归臂 —— `gk_audit_depth.py` 的「读一次 + 倒排索引 + git 批量化/并行」。

背景（finding `ECC-A0EFC250C698`）：`audit --all` 的 depth 域实测 **272s(WSL)/278s(Windows)**
> 每域 `_AUDIT_TIMEOUT=120s` ⟹ `depth.json` 空 ⟹ `failed_domains=['depth']`。
拆解：`check_python_module_deadcode` 246.0s（88.9%，O(N²) 读 + O(N²·F) 正则）
+ `enrich_with_git_intro` 30.6s（11%，38 次 `git log` 进程启动）。

本文件三条臂：
  1. **等价性**（核心安全网）：新实现 vs **原实现逐字复刻** 在同一夹具上 `depth_checks` 全等。
     夹具专挑易分歧形态：`from x import a,b` / alias / `x.y()` / 点号模块名 / 语法错 /
     测试文件跳过 / CLI heredoc 消费 / 同文件自引用。
  2. **批量化**：文件级 `git log` **只 1 次**（不逐文件回退）；符号级 pickaxe 并行填 `intro_by_symbol`。
  3. **性能界**：真仓 `scripts/` 上 `check_python_module_deadcode` < 20s（原 246s）。
"""

import json
import re
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_depth as gad  # noqa: E402

_REAL_SCRIPTS = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
# 原实现逐字复刻（仅作等价性对照；不参与生产路径）
# --------------------------------------------------------------------------
def _naive_module_deadcode(scripts_dir: str, cli_text: str = "") -> dict:
    """`check_python_module_deadcode` 的 **O(N²) 原实现**（2026-10-01 前版本）逐字复刻。"""
    import ast as _ast
    checks = []
    sd = Path(scripts_dir)
    if not sd.exists():
        return {"depth_checks": checks}
    for path in sorted(sd.glob("*.py")):
        if path.name.startswith(gad._SKIP_MODULE):
            continue
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
            tree = _ast.parse(src)
        except SyntaxError:
            checks.append({"check": "python_parse_error", "file": path.name,
                           "match": False, "error": "syntax"})
            continue
        except Exception:
            continue
        # 未使用 import
        unused_imports = []
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for a in node.names:
                    nm = a.asname or a.name.split(".")[0]
                    if gad._ref_count(src, nm, node.lineno) <= 0:
                        unused_imports.append((nm, node.lineno))
            elif isinstance(node, _ast.ImportFrom):
                for a in node.names:
                    if a.name == "*":
                        continue
                    nm = a.asname or a.name
                    if gad._ref_count(src, nm, node.lineno) <= 0:
                        unused_imports.append((nm, node.lineno))
        if unused_imports:
            checks.append({"check": "python_unused_import", "file": path.name,
                           "unused": sorted(n for n, _ in unused_imports),
                           "unused_lines": dict(unused_imports), "match": False})
        else:
            checks.append({"check": "python_unused_import", "file": path.name,
                           "unused": [], "unused_lines": {}, "match": True})
        # 模块级未调用函数（原内层：逐文件重读 + 逐函数全文正则）
        all_scripts = {}
        for p in sorted(path.parent.glob("*.py")):
            if p.name != path.name:
                try:
                    all_scripts[p.name] = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    all_scripts[p.name] = ""
        unused_funcs = []
        for node in tree.body:
            if isinstance(node, _ast.FunctionDef) and node.name != "main":
                count = 0
                for i, line in enumerate(src.split("\n"), start=1):
                    if line.lstrip().startswith("def " + node.name):
                        continue
                    count += len(re.findall(r"\b" + re.escape(node.name) + r"\b", line))
                cross = False
                for other, text in all_scripts.items():
                    if re.search(r"\bfrom\s+" + re.escape(path.stem) + r"\s+import\b", text) and \
                       re.search(r"\b" + re.escape(node.name) + r"\b", text):
                        cross = True
                        break
                    if re.search(r"\b" + re.escape(path.stem) + r"\." + re.escape(node.name) + r"\b", text):
                        cross = True
                        break
                if not cross and cli_text:
                    if re.search(r"\bfrom\s+" + re.escape(path.stem) + r"\s+import\b", cli_text) and \
                       re.search(r"\b" + re.escape(node.name) + r"\b", cli_text):
                        cross = True
                    elif re.search(r"\b" + re.escape(path.stem) + r"\." + re.escape(node.name) + r"\b", cli_text):
                        cross = True
                if count <= 0 and not cross:
                    unused_funcs.append((node.name, node.lineno))
        if unused_funcs:
            checks.append({"check": "python_unused_function", "file": path.name,
                           "unused": sorted(n for n, _ in unused_funcs),
                           "unused_lines": dict(unused_funcs), "match": False})
        else:
            checks.append({"check": "python_unused_function", "file": path.name,
                           "unused": [], "unused_lines": {}, "match": True})
    return {"depth_checks": checks}


_FIXTURE = {
    # 目标模块：三个顶层函数，分别由 from-import / 点号 / 无人消费
    "a.py": ("def exported():\n    return 1\n\n"
             "def helper():\n    return 2\n\n"
             "def lonely():\n    return 3\n\n"
             "x = 1\n"),
    # ① from-import 消费 exported
    "b.py": "from a import exported\n",
    # ② 点号消费 helper
    "c.py": "import a\n\nv = a.helper()\n",
    # 含 `from a import` 但名字不匹配 ⟹ 不得据此判 exported/helper/lonely 被消费
    "d.py": "from a import something_else\n\nw = 1\n",
    # alias 形态
    "f.py": "from a import exported as ex\n\ny = ex\n",
    # 点号模块名：`from pkg.sub import` **不得**命中 stem='sub'
    "dotted.py": "from pkg.sub import thing\n",
    # 自用 import + 文件内调用（不应报 unused）
    "e.py": "import os\n\n\ndef uses_os():\n    return os.getcwd()\n\n\nuses_os()\n",
    # 语法错
    "syntax_bad.py": "def (:\n",
    # 测试文件应被跳过
    "test_skipme.py": "import os\n",
}

_CLI_TEXT = 'python3 -c "from a import lonely"\n'   # CLI heredoc 消费 lonely


@pytest.fixture
def fixture_dir(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name, text in _FIXTURE.items():
        (scripts / name).write_text(text, encoding="utf-8")
    return str(scripts)


def _norm(d: dict) -> str:
    return json.dumps(d.get("depth_checks"), sort_keys=True, ensure_ascii=False)


class TestEquivalence:
    """判据：新实现与**原实现**在同一夹具上逐条全等（防「加速改错语义」）。"""

    def test_等同于原实现_无cli(self, fixture_dir):
        new = gad.check_python_module_deadcode(fixture_dir)
        old = _naive_module_deadcode(fixture_dir)
        assert _norm(new) == _norm(old), "新实现与原实现结果不一致（语义漂移）"

    def test_等同于原实现_含cli_heredoc(self, fixture_dir):
        new = gad.check_python_module_deadcode(fixture_dir, cli_text=_CLI_TEXT)
        old = _naive_module_deadcode(fixture_dir, cli_text=_CLI_TEXT)
        assert _norm(new) == _norm(old), "cli_text 分支语义漂移"

    def test_夹具自身覆盖关键形态(self, fixture_dir):
        """夹具有效性自检：确认它真的产生 ①/②/未消费 三类，而非"全 match 的假等价"。"""
        r = gad.check_python_module_deadcode(fixture_dir, cli_text=_CLI_TEXT)
        funcs = {c["file"]: c for c in r["depth_checks"]
                 if c.get("check") == "python_unused_function"}
        # exported：① from-import 消费
        assert "exported" not in funcs["a.py"]["unused"]
        # helper：② 点号消费
        assert "helper" not in funcs["a.py"]["unused"]
        # lonely：仅 cli heredoc 消费（不带 cli_text 时应报 unused）
        r2 = gad.check_python_module_deadcode(fixture_dir)
        funcs2 = {c["file"]: c for c in r2["depth_checks"]
                  if c.get("check") == "python_unused_function"}
        assert "lonely" in funcs2["a.py"]["unused"]
        # syntax_bad 走 parse_error 分支
        assert any(c.get("check") == "python_parse_error" and c.get("file") == "syntax_bad.py"
                   for c in r["depth_checks"])
        # test_ 前缀文件被跳过
        assert not any(c.get("file") == "test_skipme.py" for c in r["depth_checks"])


class TestGitBatching:
    """判据：文件级**只 1 次** git 调用；符号级并行填 intro_by_symbol（原为逐项 spawn）。"""

    def _fake(self, monkeypatch, stdout):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            class R:
                returncode = 0
                stderr = ""
            R.stdout = stdout(cmd)
            return R()

        monkeypatch.setattr(gad.subprocess, "run", fake_run)
        return calls

    def test_文件级批量只spawn一次(self, monkeypatch):
        stdout = "a1b2c3d|2026-01-02|add files\n\nscripts/a.py\nscripts/b.py\n"
        calls = self._fake(monkeypatch, lambda cmd: stdout)
        checks = [{"check": "script_consumer", "script": "a.py", "consumers": [], "match": False},
                  {"check": "script_consumer", "script": "b.py", "consumers": [], "match": False}]
        gad.enrich_with_git_intro(".", checks)
        file_level = [c for c in calls if "--diff-filter=A" in c]
        assert len(file_level) == 1, f"文件级未批量化（{len(file_level)} 次）: {calls}"
        for c in checks:
            assert c["intro"]["commit"] == "a1b2c3d"

    def test_文件级批量解析空则回退逐文件(self, monkeypatch):
        """批量输出不可解析（桩/旧 git）⟹ 逐文件回退，行为与旧实现一致。"""
        calls = self._fake(monkeypatch, lambda cmd: "abc123|2026-06-23|batch8 migration batch\n")
        checks = [{"check": "script_consumer", "script": "a.py", "consumers": [], "match": False}]
        gad.enrich_with_git_intro(".", checks)
        file_level = [c for c in calls if "--diff-filter=A" in c]
        assert len(file_level) == 2, f"应批量 1 次 + 回退 1 次: {calls}"
        assert checks[0]["intro"]["commit"] == "abc123"

    def test_符号级并行填intro_by_symbol(self, monkeypatch):
        def stdout(cmd):
            if "-S" in cmd:
                return "sym001|2026-03-04|add sym\n"
            return "a1b2c3d|2026-01-02|add files\n\nscripts/a.py\n"

        calls = self._fake(monkeypatch, stdout)
        checks = [{"check": "python_unused_import", "file": "a.py", "unused": ["os", "sys"],
                   "unused_lines": {"os": 1, "sys": 2}, "match": False}]
        # 需要真实文件才有行文本
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "scripts").mkdir()
            (Path(td) / "scripts" / "a.py").write_text("import os\nimport sys\n", encoding="utf-8")
            gad.enrich_with_git_intro(td, checks)
        assert set(checks[0]["intro_by_symbol"]) == {"os", "sys"}
        assert checks[0]["intro_by_symbol"]["sys"]["commit"] == "sym001"
        assert len([c for c in calls if "-S" in c]) == 2

    def test_全match时零spawn(self, monkeypatch):
        calls = self._fake(monkeypatch, lambda cmd: "")
        checks = [{"check": "python_unused_import", "file": "a.py", "unused": [],
                   "unused_lines": {}, "match": True}]
        gad.enrich_with_git_intro(".", checks)
        assert calls == [], f"全 match 时不应发起 git 调用: {calls}"


class TestPerfBound:
    """判据：真仓 `scripts/` 上 < 20s（原 246s；全流程原 272s > 120s 预算）。

    `serial`（2026-10-28）：时间预算臂在 xdist 并行下必被抢资源 ⟹ 假红 + 2-5min 串行复核。
    现由 `_accept_cli.sh` 在**并行段之后**独占整机跑（此时 HEAD 级 git 溯源缓存已由前面的
    用例预热，口径 = 生产稳态延迟，而不是冷缓存的一次性成本）。
    """

    @pytest.mark.serial
    def test_module_deadcode_under_budget(self):
        import time
        t0 = time.monotonic()
        r = gad.check_python_module_deadcode(str(_REAL_SCRIPTS))
        dt = time.monotonic() - t0
        assert r["depth_checks"], "真实 scripts/ 不应为空（夹具/路径错）"
        assert dt < 20.0, f"check_python_module_deadcode 用时 {dt:.2f}s ≥ 20s（原 246s）"

    @pytest.mark.serial
    def test_run_all_under_depth_budget(self):
        """全 depth 域 < 60s（`_AUDIT_TIMEOUT` = 120s 的一半余量）。"""
        import time
        t0 = time.monotonic()
        r = gad.run_all(str(_REAL_SCRIPTS), str(_REAL_SCRIPTS.parent / "gatekeeper-cli.sh"))
        dt = time.monotonic() - t0
        assert r["summary"]["total"] > 0
        assert dt < 60.0, f"run_all 用时 {dt:.2f}s（原 272s）"
