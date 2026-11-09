#!/usr/bin/env python3
"""红先测试：XENV-FORM 亚型 B —— 归一产物被喂给 FS / flavour 谓词（G-6 与 step3 就近查找）

族规则①（计划 §2 / 族契约 `ECC-1FC673558891`）：`_win_to_wsl` 产物**只可用于比较键**；
凡 FS 操作（exists / is_dir / is_file / read_text / stat / resolve）与 **flavour 判据**
（`is_absolute`）必须吃**宿主原生形态** —— 落刀后由单点 `_host_form` 承担。

两站点：
  · **G-6** `_scan_script_content`（`ECC-658E1E62B86D`）：`p = Path(_win_to_wsl(script_path))`
    之后 `p.is_absolute()` / `p.exists()` / `p.is_file()` / `p.read_text()`。Windows 宿主下
    `/mnt/c/…` 被读成 `C:\\mnt\\c\\…` ⟹ 恒不存在 ⟹ **Gate R0.3（脚本内容级危险命令扫描）
    整条静默失效**（fail-open）。
  · **step3 就近查找**（`ECC-B21BEDC08CE7`）：`p = Path(cwd_wsl)` ⟹ Windows 宿主下走查
    `C:\\mnt\\c\\…` ⟹ 恒不命中 ⟹ 静默回落技能仓默认门卫（**施加错误的 state**）。

⚠ 宿主形态臂必须走 **Windows python 子进程**（病灶只在 nt flavour 可达）；posix 面在进程内测。
红先纪律：实现前本文件必须**全红** —— G-6 臂返回 `None`（漏检）、step3 臂回落默认（漏认领）、
`_host_form` 契约臂 AttributeError（单点未建）。
"""
import json
import subprocess
import sys
import uuid
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import pre_tool_hook as h  # noqa: E402

WIN_PY = "<home>/AppData/Local/Programs/Python/Python311/python.exe"

# ═══════════════ Windows 宿主子进程探针 ═══════════════
# 每条臂**单独一次**子进程；超时 = RED 证据，不是 flaky。
_CHILD = r'''
import json, shutil, sys, tempfile
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import pre_tool_hook as h

arm = sys.argv[2]
base = Path(tempfile.mkdtemp(prefix="gk_fsform_"))
out = {"arm": arm, "flavour": type(Path("/")).__name__}
default = base / "default.state"
default.write_text('{"stage": "STAGE_2"}', encoding="utf-8")
h.STATE_FILE = default
h.SCOPES_FILE = base / ".gatekeeper.scopes.json"
h.SKILL_DIR = base / "other-skill"
h.GOVERNED_SCOPES = {}

# 夹具脚本：内容级扫描的正臂载体。用 **$0 递归**（非破坏性标记）而非危险命令字面量 ——
# 计划纪律「写 shell 测试夹具时避免字面量被自身防线拦截」，且本夹具永不被执行。
fx = base / "g6_fixture.sh"
fx.write_text('#!/bin/bash\nbash "$0"\n', encoding="utf-8")
fx_win = str(fx).replace("\\", "/")

if arm == "scan_native":
    r = h._scan_script_content("bash " + fx_win)
    out["hit"] = r is not None
    out["reason"] = (r[0] if r else "")
    out["fixture"] = str(fx)
elif arm == "scan_native_missing":
    r = h._scan_script_content("bash " + str(base / "nope_missing.sh").replace("\\", "/"))
    out["hit"] = r is not None
elif arm == "host_form_abs":
    out["host_form_of_wsl"] = h._host_form("<home>/x.sh")
    out["host_form_of_win"] = h._host_form("<home>\\x.sh")
    out["abs_on_host_form_wsl_input"] = bool(Path(out["host_form_of_wsl"]).is_absolute())
    out["abs_on_host_form_win_input"] = bool(Path(out["host_form_of_win"]).is_absolute())
    out["abs_on_raw_wsl_input"] = bool(Path("<home>/x.sh").is_absolute())
elif arm == "walkup_native":
    proj = base / "gk_fsform_reg_proj" / "src"
    proj.mkdir(parents=True)
    nearest = base / "gk_fsform_reg_proj" / ".gatekeeper.state"
    nearest.write_text('{"stage": "STAGE_0"}', encoding="utf-8")
    h.GOVERNED_SCOPES = {"gk_fsform_reg_proj": str(base / "missing.state")}
    # cwd 故意给**最坏情形**：WSL 形态 + Windows 宿主
    cwd_wsl = "/mnt/c" + str(proj)[2:].replace("\\", "/")
    r = h._resolve_state_by_cwd(cwd_wsl)
    out["cwd_given"] = cwd_wsl
    out["resolved"] = str(r or "")
    out["expect_nearest"] = str(nearest)
    out["expect_default"] = str(default)

print(json.dumps(out, ensure_ascii=True))
shutil.rmtree(base, ignore_errors=True)
'''


def _win_form(p) -> str:
    """WSL 路径 → Windows 形态（**必须**：Windows python 把 `/tmp/x` 读成 `C:\\tmp\\x`）。"""
    s = str(p).replace("\\", "/")
    if s.startswith("/mnt/") and len(s) > 6 and s[6] == "/":
        return s[5].upper() + ":" + s[6:]
    return s


def _run_arm(arm: str, timeout: int = 60) -> dict:
    assert Path(WIN_PY).exists(), f"Windows python 不在位，宿主形态臂不可测：{WIN_PY}"
    tmp_win = Path("<home>/AppData/Local/Temp")
    assert tmp_win.is_dir(), f"Windows 临时目录不可见（无法给宿主 python 递脚本）：{tmp_win}"
    script = tmp_win / f"gk_fsform_child_{arm}_{uuid.uuid4().hex[:6]}.py"
    script.write_text(_CHILD, encoding="utf-8")
    try:
        r = subprocess.run([WIN_PY, _win_form(script), _win_form(SCRIPT_DIR), arm],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"臂 {arm} 在 {timeout}s 内未返回（宿主形态挂死）")
    finally:
        script.unlink(missing_ok=True)
    assert r.returncode == 0, f"臂 {arm} 子进程失败 rc={r.returncode}: {r.stderr[-500:]}"
    return json.loads(r.stdout.strip().splitlines()[-1])


# ═══════════════ `_host_form` 契约（posix 面可判） ═══════════════

class TestHostFormContract:
    """FS/谓词侧**单形态**契约 —— 与 `_norm_forms`（比较键**三形态枚举**）分工不许互换。"""

    def test_posix_host_keeps_mnt_form(self):
        """posix 宿主上 `/mnt/c/…` 已是宿主原生形态 → 必须恒等（不得反转 WSL 侧）。"""
        assert h._host_form("<home>/x.sh") == "<home>/x.sh"

    def test_posix_host_converts_win_form(self):
        assert h._host_form("<home>\\x.sh") == "<home>/x.sh"
        assert h._host_form("<home>/x.sh") == "<home>/x.sh"

    def test_empty_and_relative_untouched(self):
        assert h._host_form("") == ""
        assert h._host_form("./rel.sh") == "./rel.sh"
        assert h._host_form("/tmp/x.sh") == "/tmp/x.sh"

    def test_host_form_is_single_string_not_enumeration(self):
        """防两 helper 互换：`_host_form` 单形态（str），`_norm_forms` 多形态（tuple ≥2）。"""
        assert isinstance(h._host_form("C:\\a"), str)
        assert isinstance(h._norm_forms("C:\\a"), tuple)
        assert len(h._norm_forms("C:\\a")) >= 2
        assert "/mnt/c/a" in h._norm_forms("C:\\a")


# ═══════════════ G-6 `_scan_script_content`（Windows 宿主子进程） ═══════════════

class TestScanScriptContentNativeHost:
    def test_native_host_reads_script_and_blocks(self):
        """正臂（G-6 主判据）：脚本以**宿主原生形态**存在 ⟹ 必须真读到内容并 BLOCK。"""
        r = _run_arm("scan_native")
        assert r["hit"] is True, (
            "脚本内容级扫描在 Windows 宿主下漏检（p=Path(_win_to_wsl(...)) ⟹ C:\\mnt\\c\\… 不存在）："
            + json.dumps(r, ensure_ascii=False))
        assert "g6_fixture.sh" in r["reason"], f"BLOCK 文案应指明脚本路径：{r}"

    def test_native_host_missing_script_still_none(self):
        """负臂：脚本不存在时仍返回 None（不得因改形态而误报）。"""
        r = _run_arm("scan_native_missing")
        assert r["hit"] is False, f"不存在的脚本不得产生 BLOCK：{r}"


# ═══════════════ step3 就近查找（Windows 宿主子进程） ═══════════════

class TestWalkUpNativeHost:
    def test_native_host_claims_nearest_state(self):
        """G-7′ 主判据：Windows 宿主 + WSL 形态 cwd ⟹ 走查必须命中真实就近 state。"""
        r = _run_arm("walkup_native")
        assert r["resolved"].replace("\\", "/") == r["expect_nearest"].replace("\\", "/"), (
            "就近查找在宿主形态下恒不命中、静默回落默认门卫（施加错误的 state）："
            + json.dumps(r, ensure_ascii=False))

    def test_native_host_form_absolute(self):
        """flavour 判据契约：归一产物问 `is_absolute()` 是错的，宿主原生形态才对。"""
        r = _run_arm("host_form_abs")
        assert r["abs_on_host_form_wsl_input"] is True, f"宿主原生形态应判绝对：{r}"
        assert r["abs_on_host_form_win_input"] is True, f"宿主原生形态应判绝对：{r}"
        assert r["abs_on_raw_wsl_input"] is False, f"（记录现象）归一产物问 is_absolute 为假：{r}"


# ═══════════════ posix 非回归 ═══════════════

class TestPosixNonRegression:
    def test_scan_script_content_still_blocks_posix(self, tmp_path):
        """非回归：WSL 侧（唯一生产态）脚本内容扫描不得因本次改动失效。"""
        fx = tmp_path / "posix_fixture.sh"
        fx.write_text('#!/bin/bash\nbash "$0"\n', encoding="utf-8")
        r = h._scan_script_content("bash " + str(fx))
        assert r is not None, "posix 侧脚本内容扫描失效"
        assert "posix_fixture.sh" in r[0]

    def test_scan_script_content_missing_still_none(self, tmp_path):
        assert h._scan_script_content("bash " + str(tmp_path / "nope.sh")) is None

    def test_scan_relative_script_resolves_against_cwd(self, tmp_path, monkeypatch):
        """非回归：相对脚本路径仍按宿主原生 cwd 拼（原语义不动）。"""
        fx = tmp_path / "rel_fixture.sh"
        fx.write_text('#!/bin/bash\nbash "$0"\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        r = h._scan_script_content("bash ./rel_fixture.sh")
        assert r is not None, "相对路径形态的内容扫描失效"
        assert "rel_fixture.sh" in r[0]

    def test_walkup_still_claims_nearest_posix(self, tmp_path, monkeypatch):
        """非回归：posix 侧就近认领（WSL CLI 真实工作态）不得被 `_host_form` 反转。"""
        proj = tmp_path / "reg2" / "src"
        proj.mkdir(parents=True)
        nearest = tmp_path / "reg2" / ".gatekeeper.state"
        nearest.write_text('{"stage": "STAGE_0"}', encoding="utf-8")
        default = tmp_path / "d.state"
        default.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(h, "SKILL_DIR", tmp_path / "other-skill")
        monkeypatch.setattr(h, "STATE_FILE", default)
        monkeypatch.setattr(h, "SCOPES_FILE", tmp_path / "scopes.json")
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {"reg2": str(tmp_path / "missing.state")})
        assert h._resolve_state_by_cwd(str(proj)) == nearest
