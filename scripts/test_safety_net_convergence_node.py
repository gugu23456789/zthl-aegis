"""Infra-4 红先臂：安全网模版「收敛预判节点」（A8/RCA）。

主题（plan §12.2）：`references/sequence-node-safety-net-template.md` 新增**收敛预判节点** ——
进入**迭代审查循环前**，依 A8/RCA 算 `r̂`/`N*`；不收敛（`r̂ ≥ r_min 连续 K 轮`）⟹ **fail-loud 早停**。
判据单源 = `references/convergence-evaluator.md §5`（禁第二口径）。
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TPL = ROOT / "references" / "sequence-node-safety-net-template.md"


def test_template_has_convergence_precheck_node():
    txt = TPL.read_text(encoding="utf-8")
    assert "收敛预判节点" in txt, "模版缺「收敛预判节点」（Infra-4）"
    assert "convergence-evaluator.md" in txt, "模版未指向收敛评估器**正本**（判据单源）"
    assert "pre-check convergence --loop" in txt, "模版未给出收敛预判的**可执行命令**"
    assert ("转 M" in txt or "机制修复" in txt), "模版未写明 NO-CONVERGENCE 的后果（强制转机制修复）"


def test_template_verification_checklist_covers_convergence():
    txt = TPL.read_text(encoding="utf-8")
    seg = txt[txt.find("## 6."):]
    assert "收敛预判" in seg, "§6 验收清单未含收敛预判项（新增节点须逐条核对）"
