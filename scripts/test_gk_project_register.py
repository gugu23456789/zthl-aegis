"""
test_gk_project_register.py -- Tests for gk_project_register.py (域 5 入库门禁)
================================================================================
Covers: register / list / remove 三动作 + 输入合规检测（marker 白名单 / state 路径 /
机密目录黑名单 / 类型合法域 / 重复登记）+ 原子写（_checksum + audit_log）+ 注册表损坏容错。
"""
import hashlib
import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

import gk_project_register as gpr


def _seed_scopes(tmp_path, projects=None):
    """创建含 governed_projects 的 scopes 文件，返回路径。"""
    sp = tmp_path / ".gatekeeper.scopes.json"
    data = {"version": 2, "governed_projects": projects or [], "audit_log": []}
    sp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return str(sp)


def _state_file(tmp_path, name="proj/.gatekeeper.state"):
    """创建合法的 state 文件（父目录 + 文件），返回绝对路径。"""
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(p)


def _recompute_checksum(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    payload = json.dumps({k: v for k, v in d.items() if k != "_checksum"},
                         ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class TestRegister:
    def test_register_happy_path(self, tmp_path):
        sp = _seed_scopes(tmp_path)
        state = _state_file(tmp_path)
        out = gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="my-project", state=state, type="main",
            note="demo", read_repo=None, scopes=sp))
        assert out["ok"] is True
        d = json.loads(Path(sp).read_text(encoding="utf-8"))
        assert len(d["governed_projects"]) == 1
        e = d["governed_projects"][0]
        assert e["markers"] == ["my-project"]
        assert e["state_file"].endswith(".gatekeeper.state")
        assert "type" not in e  # main 为默认语义不落盘
        assert d["_checksum"] == _recompute_checksum(sp)
        assert d["audit_log"][-1]["action"] == "register"

    def test_register_with_read_repo_and_type(self, tmp_path):
        sp = _seed_scopes(tmp_path)
        state = _state_file(tmp_path)
        out = gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="proj2", state=state, type="worktree",
            note="", read_repo="proj2", scopes=sp))
        assert out["ok"] is True
        d = json.loads(Path(sp).read_text(encoding="utf-8"))
        e = d["governed_projects"][0]
        assert e["type"] == "worktree"
        assert e["read_repo"] == "proj2"

    def test_register_first_time_creates_scopes(self, tmp_path):
        sp = str(tmp_path / "fresh.json")
        state = _state_file(tmp_path)
        out = gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="fresh", state=state, type="main",
            note="", read_repo=None, scopes=sp))
        assert out["ok"] is True
        assert Path(sp).is_file()

    def test_register_preserves_existing_projects(self, tmp_path):
        sp = _seed_scopes(tmp_path, projects=[
            {"markers": ["old"], "state_file": "/tmp/old.gatekeeper.state"}])
        state = _state_file(tmp_path)
        out = gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="new", state=state, type="main",
            note="", read_repo=None, scopes=sp))
        assert out["ok"] is True
        d = json.loads(Path(sp).read_text(encoding="utf-8"))
        assert len(d["governed_projects"]) == 2


class TestInputValidation:
    def test_bad_marker_spaces(self, tmp_path):
        state = _state_file(tmp_path)
        err = gpr._validate_input("bad marker!", state, "main")
        assert "marker 不合规" in err

    def test_bad_marker_too_long(self, tmp_path):
        state = _state_file(tmp_path)
        err = gpr._validate_input("a" * 65, state, "main")
        assert "marker 不合规" in err

    def test_bad_type(self, tmp_path):
        state = _state_file(tmp_path)
        err = gpr._validate_input("ok", state, "hyper")
        assert "type 非法" in err

    def test_state_not_absolute(self, tmp_path):
        err = gpr._validate_input("ok", "relative/path.gatekeeper.state", "main")
        assert "绝对路径" in err

    def test_state_wrong_suffix(self, tmp_path):
        err = gpr._validate_input("ok", "/tmp/foo.state", "main")
        assert "结尾" in err

    def test_state_missing_file(self, tmp_path):
        missing = str(tmp_path / "nope.gatekeeper.state")
        err = gpr._validate_input("ok", missing, "main")
        assert "不存在" in err

    def test_state_in_secret_dir(self, tmp_path):
        state = _state_file(tmp_path, name=".keys/x.gatekeeper.state")
        err = gpr._validate_input("ok", state, "main")
        assert "机密目录" in err

    def test_duplicate_marker_rejected(self, tmp_path):
        sp = _seed_scopes(tmp_path, projects=[
            {"markers": ["dup"], "state_file": "/tmp/a.gatekeeper.state"}])
        state = _state_file(tmp_path)
        out = gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="dup", state=state, type="main",
            note="", read_repo=None, scopes=sp))
        assert out["ok"] is False
        assert "已登记" in out["error"]

    def test_duplicate_state_rejected(self, tmp_path):
        sp = _seed_scopes(tmp_path)
        state = _state_file(tmp_path)
        gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="one", state=state, type="main",
            note="", read_repo=None, scopes=sp))
        out = gpr._action_register(gpr.argparse.Namespace(
            action="register", marker="two", state=state, type="main",
            note="", read_repo=None, scopes=sp))
        assert out["ok"] is False
        assert "重复" in out["error"]


class TestListRemove:
    def test_list_empty(self, tmp_path):
        sp = _seed_scopes(tmp_path)
        out = gpr._action_list(gpr.argparse.Namespace(action="list", scopes=sp))
        assert out["ok"] is True and out["count"] == 0

    def test_seal_upgrades_manual_registry(self, tmp_path):
        """存量手动 scopes（无 _checksum/audit_log）→ seal 补校验+审计（升级路径）。"""
        sp = _seed_scopes(tmp_path, projects=[
            {"markers": ["old"], "state_file": "/tmp/old.gatekeeper.state"}])
        out = gpr._action_seal(gpr.argparse.Namespace(action="seal", scopes=sp))
        assert out["ok"] is True
        d = json.loads(Path(sp).read_text(encoding="utf-8"))
        assert d["_checksum"] == _recompute_checksum(sp)
        assert d["audit_log"][-1]["action"] == "seal"
        assert len(d["governed_projects"]) == 1  # 不动存量条目

    def test_remove(self, tmp_path):
        sp = _seed_scopes(tmp_path, projects=[
            {"markers": ["gone"], "state_file": "/tmp/g.gatekeeper.state"}])
        out = gpr._action_remove(gpr.argparse.Namespace(action="remove", marker="gone", scopes=sp))
        assert out["ok"] is True
        d = json.loads(Path(sp).read_text(encoding="utf-8"))
        assert len(d["governed_projects"]) == 0
        assert d["audit_log"][-1]["action"] == "remove"

    def test_remove_unregistered(self, tmp_path):
        sp = _seed_scopes(tmp_path)
        out = gpr._action_remove(gpr.argparse.Namespace(action="remove", marker="ghost", scopes=sp))
        assert out["ok"] is False
        assert "未登记" in out["error"]

    def test_corrupted_scopes(self, tmp_path):
        sp = tmp_path / "bad.json"
        sp.write_text("{not json", encoding="utf-8")
        out = gpr._action_list(gpr.argparse.Namespace(action="list", scopes=str(sp)))
        assert out["ok"] is False
