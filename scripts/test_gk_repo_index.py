"""test_gk_repo_index.py — 仓库索引生成器（FILES.md / llms.txt）的机检臂。

守什么：
  ① 确定性：同输入两次 build 完全一致（否则 `--check` 无意义）；
  ② 描述来源：手工注 > md 首个 H1 > py 模块 docstring 首行；
  ③ 漂移门：`--check` 能抓出被手改的 FILES.md / llms.txt，缺失也判红；
  ④ 公开面过滤：`_is_excluded` 命中的路径不得进索引（防私仓路径泄漏）；
  ⑤ llms.txt 是**精选**（md + 手工注），不是全量（全量在 FILES.md）。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_repo_index as R  # noqa: E402


def _tree(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "a.py").write_text(
        '"""A 模块首行。\n\n细节。\n"""\n', encoding="utf-8")
    (tmp_path / "scripts" / "b.py").write_text('"""B 模块。"""\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("# 自述标题\n\n正文\n", encoding="utf-8")
    (tmp_path / "references").mkdir()
    (tmp_path / "references" / "x.md").write_text("# 参考 X\n", encoding="utf-8")
    (tmp_path / "references" / "repo-index-annotations.json").write_text(
        json.dumps({"files": {"README.md": "手工注的手册"}}), encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    monkeypatch.setattr(R, "_is_excluded", lambda rel: False)
    return tmp_path


def test_build_is_deterministic(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    a, b = R.build(root), R.build(root)
    assert a["files"] == b["files"]
    assert a[R.FILES_MD] == b[R.FILES_MD]
    assert a[R.LLMS_TXT] == b[R.LLMS_TXT]


def test_descriptions_priority(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    d = R.build(root)["descs"]
    assert d["README.md"] == "手工注的手册"                 # 手工注优先
    assert "参考 X" in d["references/x.md"]                  # md H1
    assert "A 模块首行" in d["scripts/a.py"]                 # py docstring 首行


def test_excluded_paths_absent(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    monkeypatch.setattr(R, "_is_excluded", lambda rel: rel.startswith("docs/"))
    (root / "docs").mkdir()
    (root / "docs" / "secret.md").write_text("# 私仓\n", encoding="utf-8")
    data = R.build(root)
    assert not [f for f in data["files"] if f.startswith("docs/")]
    assert "secret.md" not in data[R.FILES_MD]


def test_hidden_files_skipped(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    assert ".gitignore" not in R.build(root)["files"]


def test_runtime_state_files_not_indexed(tmp_path, monkeypatch):
    """2026-11-08（导出树实测）：运行期 state 不是公开面输入，不得进索引。

    导出树没有 `.git` ⟹ 走 `os.walk`；预检/生成器自己写出的 `.gatekeeper.state*` 若被计入，
    `--check` 会与刚写入的 FILES.md 立刻漂移（实测 860 → 861 ⟹ 导出树内 preflight 恒 FAIL）。
    私仓侧靠 `git ls-files` 天然排除（未跟踪）⟹ 两侧判据必须对齐。
    """
    root = _tree(tmp_path, monkeypatch)
    (root / ".gatekeeper.state").write_text("{}", encoding="utf-8")
    (root / ".gatekeeper.state.own_user").write_text("HP", encoding="utf-8")
    files = R.build(root)["files"]
    assert not [f for f in files if f.startswith(".gatekeeper.state")], files
    # 生成后即便 state 再被写出，`--check` 也必须保持收敛（不自污染）
    R.write(root)
    (root / ".gatekeeper.state.own_user").write_text("HP", encoding="utf-8")
    assert R.check(root)["ok"] is True


def test_write_then_check_ok(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    changed = R.write(root)
    assert set(changed) == {R.FILES_MD, R.LLMS_TXT}
    assert R.check(root)["ok"] is True


def test_check_detects_drift(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    R.write(root)
    (root / R.FILES_MD).write_text("手工改坏\n", encoding="utf-8")
    r = R.check(root)
    assert r["ok"] is False and any("FILES.md" in i for i in r["issues"])


def test_check_detects_missing(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    r = R.check(root)
    assert r["ok"] is False and len(r["issues"]) == 2


def test_llms_is_curated(tmp_path, monkeypatch):
    root = _tree(tmp_path, monkeypatch)
    data = R.build(root)
    llms = data[R.LLMS_TXT]
    assert "README.md" in llms and "references/x.md" in llms
    assert "scripts/b.py" not in llms, "未注脚本不应进精选索引（全量在 FILES.md）"
    assert "scripts/b.py" in data[R.FILES_MD]
