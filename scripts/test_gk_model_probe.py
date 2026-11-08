#!/usr/bin/env python3
"""模型版本探针 **红先臂**（`ECC-75F6A2BB7F2B`）。

缺陷（W2A §6.1 / §6.3(3) F1b）：判 stride / 相位周期 `S` 等**版本相关量**时**禁据 alias 推断**
—— 模型名可**沿用同一 alias 仅换后端**。本仓既无版本探针（`S` 吊在未证的 alias 字符串上），
也无 CLI 入口 ⟹ 6 臂的模型版本/`S` 不可实测。

修法 = 新 `scripts/gk_model_probe.py`（元数据层 `model` / `system_fingerprint` + 行为层变 `L`
测周期）+ CLI 命令 `model-probe`；`resolved=false` **fail-loud**（下游不得静默假设 `S=2`）。

落刀前必红：模块缺席（ImportError）+ CLI 未注册（断言失败）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def test_model_probe_module_symbols_present():
    """源码形态：模块 + 纯函数坐标（`resolve` / `normalize_meta` / `CANDIDATE_STRIDES`）。"""
    import gk_model_probe as m

    for sym in ("resolve", "normalize_meta", "CANDIDATE_STRIDES"):
        assert hasattr(m, sym), "gk_model_probe 缺符号 %s" % sym


def test_normalize_meta_both_shapes():
    import gk_model_probe as m

    a = m.normalize_meta({"data": [{"id": "deepseek-flash"}, {"id": "deepseek-v4-pro"}]})
    assert a["model_ids"] == ["deepseek-flash", "deepseek-v4-pro"]
    assert a["fingerprint"] is None
    b = m.normalize_meta({"model": "deepseek-flash", "system_fingerprint": "fp_x"})
    assert b["model_id"] == "deepseek-flash" and b["fingerprint"] == "fp_x"


def test_model_probe_resolve_from_fingerprint_table():
    """元数据层：`system_fingerprint` 命中已知表 ⟹ 定 `S`。"""
    import gk_model_probe as m

    out = m.resolve(meta={"model": "deepseek-flash", "system_fingerprint": "fp_v41"},
                    known_strides={"fp_v41": 2})
    assert out["resolved"] is True and out["stride"] == 2
    assert out["source"] == "fingerprint-table"


def test_model_probe_resolve_from_behavioral_series():
    """行为层回退：给观测序列直接测周期（不依赖 alias）。"""
    import gk_model_probe as m

    series = [0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3]
    out = m.resolve(meta={"model": "deepseek-flash"}, series=series)
    assert out["resolved"] is True and out["stride"] == 4
    assert out["source"] == "behavioral"


def test_model_probe_fail_loud_when_unresolvable():
    """负臂：alias / 未知 fingerprint / 无行为序列 ⟹ 不得编造 `S`（禁据 alias 判版本）。"""
    import gk_model_probe as m

    out = m.resolve(meta={"model": "deepseek-flash", "system_fingerprint": "fp_unknown"})
    assert out["resolved"] is False and out["stride"] is None
    assert out["fingerprint"] == "fp_unknown"
    out2 = m.resolve(meta={"model": "deepseek-v4-pro"})
    assert out2["resolved"] is False and out2["stride"] is None


def test_model_probe_cli_registered():
    """CLI 入口：`model-probe` 须注册（否则「禁裸跑 gk_*.py」下无人能调）。"""
    src = CLI.read_text(encoding="utf-8")
    assert "_CMD_REG[model-probe]=" in src, "未注册 CLI 命令 model-probe"
    assert "cmd_model_probe() {" in src, "缺 cmd_model_probe 实现"


def test_model_probe_has_no_private_paper_source():
    """公开面：候选 stride 只作为**候选**，不得引用私有论文仓路径或跨仓副本。"""
    src = (Path(__file__).resolve().parent / "gk_model_probe.py").read_text(encoding="utf-8")
    assert "CANDIDATE_STRIDES" in src
    assert "papers/" not in src, "公开模块不得含私有论文仓路径"
    assert "repro/phase_probe.py" not in src, "公开模块不得把论文仓记录副本当源"
