#!/usr/bin/env python3
"""`ECC-74B7327230D8` 红先臂：subagent evidence 形态归一（盘符路径被当分隔符）。

缺陷（`gatekeeper-cli.sh` 落库块原式 `e.split(':')[0]/[1]`）：字符串型 evidence 若为 Windows
盘符路径（`C:/Users/…/x.py:13 —— desc`），**盘符冒号被当分隔符** ⟹ `file='C'`、`lines` 塞入
全路径；渲染侧 `file + ':' + lines` 又拼回原样 ⟹ HTML/报告看不出症状，但 `file` 已不可单独
消费（按文件聚合/链接失效），F-REV-97 的锚检也因复合 `file:lines` 而放过。

修法 = `gk_subagent_report.normalize_evidence()`（按**首个「冒号 + 数字」**切）。

⚠ 归一下沉到**已跟踪**文件 `gk_subagent_report.py`（而**非**新建模块）—— red-first 沙箱会把
**未跟踪**的新脚本软链回工作树（`_redfirst_cli.sh` 覆盖层）⟹ 新模块在 HEAD 沙箱里照样存在
⟹ 行为臂**假绿**（`test_gk_active_surface.py` 头部同款教训）。HEAD 上该函数不存在
⟹ `AttributeError` ⟹ 下列前三臂必红；第四臂（静态）在 HEAD 上亦必红（CLI 仍有裸 split）。
"""
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
CLI = SD / "gatekeeper-cli.sh"
sys.path.insert(0, str(SD / "scripts"))


def _norm(ev):
    import gk_subagent_report
    return gk_subagent_report.normalize_evidence(ev)


def test_normalize_evidence_drive_path_not_split():
    """红先：Windows 盘符路径 ⟹ `file` 须保**完整路径**（原式得 `'C'`）。"""
    out = _norm(["<home>/.trae/x.py:13 —— desc"])
    assert out[0]["file"] == "<home>/.trae/x.py", out
    assert out[0]["lines"] == "13 —— desc", out
    assert out[0]["status"] == "confirmed", out


def test_normalize_evidence_plain_and_missing_line():
    """红先：普通 `p:13` / 无行号 `p` / 多行号 `p:1,2` 均正确（判据面不退化）。"""
    out = _norm(["a.py:1", "b.py", "c.py:1,2"])
    assert [(r["file"], r["lines"]) for r in out] == [
        ("a.py", "1"), ("b.py", ""), ("c.py", "1,2")], out


def test_normalize_evidence_mixed_forms_preserved():
    """红先：混合形态（dict + str）**不吞不抛** —— 原式在 dict 上 `AttributeError`，被落库块的
    `2>/dev/null || true` 静默吞掉 ⟹ 整条 history 不写（异形同源静默族）。"""
    d = {"file": "x", "lines": "1", "status": "confirmed"}
    out = _norm([d, "a.py:2"])
    assert out[0] == d, out
    assert out[1] == {"file": "a.py", "lines": "2", "status": "confirmed"}, out


def test_evidence_normalizer_cli_wired():
    """静态红先：CLI 落库块不再用裸 `e.split(':')`，改调 `normalize_evidence`。

    并钉住 import **与该调用同载荷** —— 首版把 import 误落进通用 `_state_write()` helper 载荷
    （grep 得到「函数名在源码里」即误判接线成功），而落库块载荷未 import ⟹ 运行期 `NameError`
    被该块尾的 `2>/dev/null || true` 静默吞掉（history 整条不写）= 静默族复发。故判据升为
    「import 恰一处 ∧ 落在落库块载荷内（HK_HMAC 锚之后、调用之前）」。
    """
    src = CLI.read_text(encoding="utf-8")
    assert "normalize_evidence" in src, "落库块未接线 normalize_evidence（归一下沉未生效）"
    assert "e.split(':')[0]" not in src, "落库块仍有裸 `e.split(':')[0]` ⟹ 盘符仍被误切"
    _imp = "from gk_subagent_report import normalize_evidence"
    assert src.count(_imp) == 1, f"归一 helper 的 import 必须**恰一处**（实得 {src.count(_imp)}）"
    _call = src.index("evidence=normalize_evidence(")
    _anchor = src.index('GK_HMAC_VALID="$hmac_valid" python3 -c')
    assert _anchor < src.index(_imp) < _call, (
        "import 未与落库块调用**同载荷**（误落它处 ⟹ 运行期 NameError 被 2>/dev/null 静默吞）")
