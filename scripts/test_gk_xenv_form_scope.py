#!/usr/bin/env python3
"""红先测试：XENV-FORM 族（宿主形态不对称）—— ②a / ②b / ③ / ④ + 99056BFDBC47

族病（2026-09-20 实测 A/B 六臂 + 本文件复核）：`_win_to_wsl` 只作用**单侧**
（左操作数过、右操作数不过）⟹ Windows 宿主形态下比较恒假 ⟹ `_in_governed_scope`
判「范围外」⟹ `main()` 早退 ⟹ Gate 1/2/3/4/8 **整链不执行**（fail-open）。

| 站点 | 符号 | 病 |
|:--|:--|:--|
| ②a | `_in_governed_scope` | `cwd_wsl` 过 `_win_to_wsl`，`skill_wsl` 只 `replace("\\\\","/")` |
| ②b | `_resolve_state_by_cwd` step2 | 同形孪生（决定「落到哪个 state」） |
| ③ | `_resolve_state_by_cwd` step3 | 哨兵 `while str(p) not in ("/","",".")` 是 POSIX 专属；Windows 根锚 `str(Path("C:/")) == "C:\\\\"` ⟹ **自指死循环**（仓内 `_state_walk_boundary` docstring 自证同类曾在根锚死循环、卡死全量 pytest） |
| ④ | `_resolve_state_by_target_path` 首判 | 同形（F5 目标通道在 Windows 宿主下不认领技能仓） |
| 99056BFDBC47 | ②a/②b/④ 三处落点 | 缺目录边界：`/…/spz-gatekeeper-r-sequence-x` 被误判为仓内 |

**判据形态（按质询 G1/G3 硬约束）**：
  · **独立比较键 + 双侧同步归一** —— 禁只归一单侧；复用 `_resolve_existing` 的
    三形态枚举范式（原样 + `_win_to_wsl` + `_wsl_to_win`），**不新建第二套归一 helper**。
  · **不引入 `lower()`** —— 全局 lower 会同时破 (a) `GOVERNED_SCOPES` 大写 marker
    子串面、(b) 大小写敏感 FS 上 `Path(t)` 走查。大写盘符形态（`/mnt/C/…`）改由
    三形态枚举里的 `_wsl_to_win` 形态自然覆盖（`→ C:/…`，与技能目录同形态）。
  · ③ 只替换**循环终止判据**为既有 `_state_walk_boundary`；尾部 `return STATE_FILE`
    **保持不变**（fail-closed 默认门卫，非 `_resolve_state_by_target_path` 的 `None` 语义）。

⚠ 环境说明（如实声明，不当借口）：②b/③/④ 的**病灶只在 Windows 宿主可达**
（`Path("/mnt/c/x").parent` 在 Windows flavour 走 `\\mnt\\c\\x`，终态 `\\` 不在 POSIX
哨兵集合内；WSL flavour 走 `/` 会自然退出）⟹ 这三条必须用 **Windows python 子进程**
测；纯谓词面（②a / 99056 / 归一一致）在 WSL python 内测。

红先纪律：实现前本文件必须全红（②a/99056 断言失败；②b/③/④ 子进程超时或结果不符）。
"""
import json
import subprocess
import sys
import uuid
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import pre_tool_hook as h  # noqa: E402

SKILL_WIN = "<home>\\.trae\\skills\\spz-gatekeeper-r-sequence"
SKILL_WSL = "<home>/.trae/skills/spz-gatekeeper-r-sequence"
WIN_PY = "<home>/AppData/Local/Programs/Python/Python311/python.exe"

# ═══════════════ Windows 宿主子进程探针 ═══════════════
# 每条臂**单独一次**子进程（任一条死循环都不得连带其它臂）；超时 = RED 证据，不是 flaky。
def _child_script(arm: str) -> str:
    """子进程源码：每臂独立、自带 tempdir、只输出一行 JSON（ASCII 保证）。"""
    return r'''
import json, shutil, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import pre_tool_hook as h

arm = sys.argv[2]
base = Path(tempfile.mkdtemp(prefix="gk_xenv_"))
state = base / ".gatekeeper.state"
state.write_text('{"stage": "STAGE_2", "r_phase": "R1"}', encoding="utf-8")
wsl_base = "/mnt/c" + str(base)[2:].replace("\\", "/")
out = {"arm": arm, "wsl_base": wsl_base}

h.STATE_FILE = state
h.SCOPES_FILE = base / ".gatekeeper.scopes.json"
h.GOVERNED_SCOPES = {}

if arm == "step2":          # ②b
    h.SKILL_DIR = base                              # SKILL_DIR = Windows 形态（真实宿主形态）
    out["resolved"] = str(h._resolve_state_by_cwd(wsl_base + "/scripts") or "")
elif arm == "target":       # ④
    h.SKILL_DIR = base
    out["resolved"] = str(h._resolve_state_by_target_path(wsl_base + "/scripts/x.py") or "")
elif arm == "target_out":   # ④ 负臂：范围外目标
    h.SKILL_DIR = base / "other-skill"
    mirror = base / "mirror"
    mirror.mkdir()
    (mirror / ".gatekeeper.state").write_text("{}", encoding="utf-8")
    out["resolved"] = str(h._resolve_state_by_target_path(str(mirror / "x.py")) or "")
elif arm == "walkup":       # ③ cwd 命中已登记 marker 但该项目 state 缺失
    h.SKILL_DIR = base / "other-skill"
    proj = base / "gk_xenv_registered_proj" / "src"
    proj.mkdir(parents=True)
    h.GOVERNED_SCOPES = {"gk_xenv_registered_proj": str(base / "missing.state")}
    t0 = time.time()
    r = h._resolve_state_by_cwd(wsl_base + "/gk_xenv_registered_proj/src")
    out["elapsed"] = round(time.time() - t0, 2)
    out["resolved"] = str(r or "")
elif arm == "walkup_find":  # ③ + G-7′ 正臂（宿主形态）：宿主形态下走查**可达真实目录**
    # ⟹ 除「不挂死」外还须**认领就近 state**。G-7′（ECC-B21BEDC08CE7）修前此处恒落
    # 默认门卫 —— 原断言锁的正是该缺陷面，随本次落刀一并更正（见 test_walkup_host_form_no_hang_either）。
    h.SKILL_DIR = base / "other-skill"
    proj = base / "gk_xenv_registered_proj" / "src"
    proj.mkdir(parents=True)
    nearest = base / "gk_xenv_registered_proj" / ".gatekeeper.state"
    nearest.write_text("{}", encoding="utf-8")
    h.GOVERNED_SCOPES = {"gk_xenv_registered_proj": str(base / "missing.state")}
    t0 = time.time()
    r = h._resolve_state_by_cwd(wsl_base + "/gk_xenv_registered_proj/src")
    out["elapsed"] = round(time.time() - t0, 2)
    out["resolved"] = str(r or "")
    out["expect"] = str(nearest)
    out["default"] = str(state)

print(json.dumps(out, ensure_ascii=True))
shutil.rmtree(base, ignore_errors=True)
'''


def _win_form(p) -> str:
    """WSL 路径 → Windows 形态（**必须**：Windows python 把 `/tmp/x` 读成 `C:\\tmp\\x`）。"""
    s = str(p).replace("\\", "/")
    if s.startswith("/mnt/") and len(s) > 6 and s[6] == "/":
        return s[5].upper() + ":" + s[6:]
    return s


def _run_arm(arm: str, timeout: int = 25) -> dict:
    """Windows python 跑单臂；超时 → 抛 AssertionError（= ③ 死循环的 RED 证据）。"""
    assert Path(WIN_PY).exists(), f"Windows python 不在位，宿主形态臂不可测：{WIN_PY}"
    tmp_win = Path("<home>/AppData/Local/Temp")
    assert tmp_win.is_dir(), f"Windows 临时目录不可见（无法给宿主 python 递脚本）：{tmp_win}"
    script = tmp_win / f"gk_xenv_child_{arm}_{uuid.uuid4().hex[:6]}.py"
    script.write_text(_child_script(arm), encoding="utf-8")
    try:
        r = subprocess.run([WIN_PY, _win_form(script), _win_form(SCRIPT_DIR), arm],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AssertionError(
            f"臂 {arm} 在 {timeout}s 内未返回 —— 宿主形态下 walk-up 未终止（③ 自指死循环）")
    finally:
        script.unlink(missing_ok=True)
    assert r.returncode == 0, f"臂 {arm} 子进程失败 rc={r.returncode}: {r.stderr[-400:]}"
    return json.loads(r.stdout.strip().splitlines()[-1])


# ═══════════════ ②a / 99056BFDBC47：纯谓词面（WSL python 可判） ═══════════════

class TestInGovernedScope:
    def test_native_host_form_in_scope(self, monkeypatch):
        """Trae 会话真实形态：SKILL_DIR 为 Windows 形态、cwd 为 /mnt 形态 → 必须判范围内。"""
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WIN))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {})
        assert h._in_governed_scope(SKILL_WSL + "/scripts") is True

    def test_wsl_side_not_reversed(self, monkeypatch):
        """非回归：SKILL_DIR 为 /mnt 形态（WSL CLI 侧）时，原工作态**不得反转**。"""
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WSL))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {})
        assert h._in_governed_scope(SKILL_WSL + "/scripts") is True
        assert h._in_governed_scope("<home>/.trae/skills/spz-gatekeeper-r-sequence/scripts") is True

    def test_uppercase_drive_form_in_scope(self, monkeypatch):
        """99056 的大写盘符形态（`/mnt/C/…`）：三形态枚举下应与小写同判（**不靠 lower**）。"""
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WSL))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {})
        assert h._in_governed_scope("/mnt/C/Users/HP/.trae/skills/spz-gatekeeper-r-sequence/scripts") is True

    def test_sibling_prefix_rejected(self, monkeypatch):
        """99056 的目录边界面：前缀同形而不同目录 → 不得误判仓内（缺 rstrip+"/" 的现场）。"""
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WSL))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {})
        assert h._in_governed_scope(SKILL_WSL + "-x/scripts") is False

    def test_exact_skill_dir_still_in_scope(self, monkeypatch):
        """边界口径不得把「正好等于技能目录」判出去。"""
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WSL))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {})
        assert h._in_governed_scope(SKILL_WSL) is True

    def test_marker_face_semantics_unchanged(self, monkeypatch):
        """回归锁：marker 子串面大小写敏感语义**不变**（禁止 lower 的战果面）。"""
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WSL))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {"Mooncake-0.3.13.post1": "/mnt/c/x/s"})
        assert h._in_governed_scope("<home>/Downloads/Mooncake-0.3.13.post1/a") is True
        assert h._in_governed_scope("<home>/Downloads/mooncake-0.3.13.post1/a") is False

    def test_out_of_scope_still_allowed(self, monkeypatch):
        monkeypatch.setattr(h, "SKILL_DIR", Path(SKILL_WSL))
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {})
        assert h._in_governed_scope("/tmp/x") is False


class TestNormFormsContract:
    def test_both_host_forms_share_a_common_key(self):
        """双侧同步归一的**契约**：同一位置的 Windows 形态与 WSL 形态必须产出交集键。"""
        a = set(h._norm_forms("<home>/x"))
        b = set(h._norm_forms("<home>/x"))
        assert a & b, f"两侧无共同比较键 ⟹ 单侧归一病灶：{sorted(a)} vs {sorted(b)}"
        assert "<home>/x" in a and "<home>/x" in b

    def test_trailing_slash_and_backslash_normalised(self):
        assert h._norm_forms("/mnt/c/a/") == h._norm_forms("/mnt/c/a")
        assert set(h._norm_forms("C:\\a\\b")) & set(h._norm_forms("/mnt/c/a/b"))

    def test_empty_is_empty(self):
        assert h._norm_forms("") == ()


# ═══════════════ ②b / ④：目标/归属通道（Windows 宿主子进程） ═══════════════

class TestNativeHostResolution:
    def test_step2_claims_skill_state_in_native_form(self):
        r = _run_arm("step2")
        assert r["resolved"].endswith(".gatekeeper.state"), f"②b 未认领技能 state：{r}"

    def test_target_path_claims_skill_state_in_native_form(self):
        r = _run_arm("target")
        assert r["resolved"].endswith(".gatekeeper.state"), f"④ 未认领技能 state：{r}"

    def test_target_path_out_of_scope_returns_none(self):
        r = _run_arm("target_out")
        assert r["resolved"] == "", f"范围外目标不得被拉进治理：{r}"


# ═══════════════ ③：walk-up 终止性（Windows 宿主子进程，超时 = RED） ═══════════════

class TestWalkUpTermination:
    def test_walkup_terminates_and_falls_back_fail_closed(self):
        """③ 主判据：宿主形态下 cwd 命中已登记 marker 但该项目 state 缺失 → 必须**终止**，
        且尾部保留 fail-closed 默认门卫（`return STATE_FILE`，非 None）。"""
        r = _run_arm("walkup")
        assert r["elapsed"] < 10, f"walk-up 耗时异常：{r}"
        assert r["resolved"].endswith(".gatekeeper.state"), f"尾部必须保留 fail-closed 默认门卫：{r}"

    def test_walkup_host_form_no_hang_either(self):
        """③ + G-7′ 副臂：宿主形态下走查既不挂死、也要**认领就近 state**（G-7′ 修后语义）。
        修前本臂断言的是「静默落默认门卫」—— 那正是 `ECC-B21BEDC08CE7` 的缺陷面，
        故随落刀一并更正（原锁缺陷面 = 反被缺陷固化，记入计划 §11）。"""
        r = _run_arm("walkup_find")
        assert r["elapsed"] < 10, f"walk-up 耗时异常：{r}"
        assert r["resolved"].replace("\\", "/") == r["expect"].replace("\\", "/"), \
            f"宿主形态下必须认领就近 state（不得静默回落默认门卫）：{r}"
        assert r["resolved"].replace("\\", "/") != r["default"].replace("\\", "/"), \
            f"不得回落默认门卫：{r}"

    def test_walkup_still_claims_nearest_state_posix(self, tmp_path, monkeypatch):
        """③ 非回归（posix 形态 = WSL CLI 侧真实工作态）：换终止判据**不得漏认**沿途就近 state。"""
        proj = tmp_path / "reg_proj" / "src"
        proj.mkdir(parents=True)
        nearest = tmp_path / "reg_proj" / ".gatekeeper.state"
        nearest.write_text("{}", encoding="utf-8")
        default = tmp_path / "default.state"
        default.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(h, "SKILL_DIR", tmp_path / "other-skill")
        monkeypatch.setattr(h, "STATE_FILE", default)
        monkeypatch.setattr(h, "SCOPES_FILE", tmp_path / "scopes.json")
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {"reg_proj": str(tmp_path / "missing.state")})
        assert h._resolve_state_by_cwd(str(proj)) == nearest

    def test_walkup_default_untouched(self, tmp_path, monkeypatch):
        """③ 非回归：全不中仍回落默认门卫（原语义不动）。"""
        default = tmp_path / "default.state"
        default.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(h, "SKILL_DIR", tmp_path / "other-skill")
        monkeypatch.setattr(h, "STATE_FILE", default)
        monkeypatch.setattr(h, "SCOPES_FILE", tmp_path / "scopes.json")
        monkeypatch.setattr(h, "GOVERNED_SCOPES", {"reg_proj": str(tmp_path / "missing.state")})
        assert h._resolve_state_by_cwd(str(tmp_path / "reg_proj" / "src")) == default
