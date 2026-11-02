"""
test_gk_moa_chain_t6.py -- T6 红先臂：下发点回环预检（apply-worktree --code-fix 接 _guard_precheck）
================================================================================
正本：finding `ECC-AC7004852D8C`（C 计划 §3 T6）。

缺口：`apply-worktree --code-fix --finding <fid>`（coder 派发入口，gatekeeper-cli.sh:8771）在族判定 /
建 worktree / 回 `next` 之前，**未**对 `<fid>` 跑处置前回环闸 `_guard_precheck`
（gk_finding.py:956；register/verify/close/reopen/amend-title/archive 已内建，唯独**下发点**缺失）。

本切片：① 只读 `finding precheck <fid>` 子命令（判据单一源 = `_guard_precheck`）；
② CLI `--code-fix` 分支**最前**（族判定之前）接线：命中 ⟹ fail-loud 拒派发；
③ 逃生舱 env `GK_FINDING_PRECHECK=0`。
"""
import json
import os
import subprocess

import pytest
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
CLI = SCRIPTS.parent / "gatekeeper-cli.sh"
PY = sys.executable
FID = "ECC-T6TEST0001"

CLEAN_TITLE = "T6 干净标题（锚真实）见 scripts/gk_finding.py:1"
DRIFT_TITLE = "T6 漂移标题（锚不存在）见 scripts/nonexistent_zzz_t6.py:1"


def _state(tmp_path, title):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": [{
        "id": FID, "title": title, "status": "open", "source": "review",
        "cover_layers": ["L2"], "root_key": "t6", "anchors": [], "facets": [],
    }]}}), encoding="utf-8")
    return str(st)


def _precheck(st, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run([PY, str(SCRIPTS / "gk_finding.py"), "precheck", st, FID],
                          capture_output=True, text=True, env=env)


def _codefix(st, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(["bash", str(CLI), "apply-worktree", "--code-fix",
                           "--finding", FID, "--state", st],
                          capture_output=True, text=True, env=env)


# ── ① `precheck` 子命令：无漂移 ⟹ rc0 + ok:true ─────────────────────────────
def test_precheck_clean_ok(tmp_path):
    r = _precheck(_state(tmp_path, CLEAN_TITLE))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["ok"] is True


# ── ② `precheck` 子命令：漂移 ⟹ rc1 + ECC_PRECHECK_DRIFT + 明细 ──────────────
def test_precheck_drift_fails(tmp_path):
    r = _precheck(_state(tmp_path, DRIFT_TITLE))
    assert r.returncode == 1, r.stdout + r.stderr
    d = json.loads(r.stdout)
    assert d["ok"] is False and "ECC_PRECHECK_DRIFT" in d["error"], d
    assert d["drift"], d


# ── ③ 逃生舱：env GK_FINDING_PRECHECK=0 ⟹ rc0（skip）──────────────────────
def test_precheck_escape_hatch(tmp_path):
    r = _precheck(_state(tmp_path, DRIFT_TITLE), {"GK_FINDING_PRECHECK": "0"})
    assert r.returncode == 0, r.stdout + r.stderr


# ── ④ 形态臂：CLI `--code-fix` 分支接线 ───────────────────────────────────
def test_cli_wires_precheck():
    s = CLI.read_text(encoding="utf-8")
    assert 'gk_finding.py" precheck' in s, "code-fix 分支未接 finding precheck"
    assert "ECC_PRECHECK_DRIFT" in s, "code-fix 分支未 fail-loud"


# ── ⑤ E2E：漂移 finding ⟹ 拒派发（error=ECC_PRECHECK_DRIFT）────────────────
@pytest.mark.skipif(os.name == "nt", reason="POSIX bash E2E")
def test_codefix_blocks_on_drift(tmp_path):
    r = _codefix(_state(tmp_path, DRIFT_TITLE))
    assert r.returncode != 0, r.stdout
    out = json.loads(r.stdout)
    assert out.get("error") == "ECC_PRECHECK_DRIFT", out


# ── ⑥ E2E 对照：无漂移 ⟹ 放行（错误非 precheck）────────────────────────────
@pytest.mark.skipif(os.name == "nt", reason="POSIX bash E2E")
def test_codefix_passes_clean(tmp_path):
    r = _codefix(_state(tmp_path, CLEAN_TITLE))
    out = json.loads(r.stdout)          # 必须可解析（CLI 环境异常会在此暴露）
    assert out.get("error") != "ECC_PRECHECK_DRIFT", (r.returncode, out)
