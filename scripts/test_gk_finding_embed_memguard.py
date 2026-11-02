"""红先臂：嵌入 producer 的内存防线（finding `ECC-666539027A62`）。

背景（2026-10-10）：全量 552 条一次过 ONNX ⟹ 注意力张量 **一次性要 4.6GB**
（batch × heads × T² × 4B）⟹ OOM ⟹ 拖崩宿主（Trae/Electron）。临时用「固定分批 32」
止血，但**单条超长文本**或**批内条数过大**仍会炸。本 finding 补三道硬防线：

  ① **自适应批** `plan_batches`：每批同时受 `max_count` 与 `max_chars` 约束（保序/无重复/全覆盖）；
  ② **预检门** `preflight_batches`：按估计峰值（`estimate_peak_bytes`）**降批**直到 ≤ cap；
     降到 `max_count=1` 仍超 ⟹ **fail-loud**（拒绝而非 OOM）；
  ③ **内存上限**：Node 子进程 `--max-old-space-size`（`GK_EMBED_NODE_MAX_MB`）+ 桥侧 `truncation/max_length`。

**红先对照**：HEAD（`481d02a`）的 `gk_finding_embed` **无** `plan_batches`/`estimate_peak_bytes`/
`preflight_batches` ⟹ 三个臂全部 AttributeError ⟹ 红。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_plan_batches_respects_count_and_chars():
    """正臂：`plan_batches` 必须同时守 max_count 与 max_chars，且保序/无重复/全覆盖。"""
    import gk_finding_embed as ge
    texts = ["x" * 100] * 10
    batches = ge.plan_batches(texts, max_count=3, max_chars=250)
    flat = [i for b in batches for i in b]
    assert sorted(flat) == list(range(10)), "须全覆盖且无重复"
    for b in batches:
        assert len(b) <= 3, "批内条数须 <= max_count"
        if len(b) > 1:                      # 单条独占批允许超 max_chars（不丢料）
            assert sum(len(texts[i]) for i in b) <= 250, "多元素批须守 max_chars"


def test_preflight_gate_bounds_peak():
    """正臂：预检门须把估计峰值降到 cap 之下（自动降批），且不丢任何下标。"""
    import gk_finding_embed as ge
    texts = ["y" * 50] * 200
    batches, est = ge.preflight_batches(texts, max_count=64, max_chars=10 ** 9, cap=300 * 10 ** 6)
    assert est <= 300 * 10 ** 6, "估计峰值须 <= cap"
    assert sorted(i for b in batches for i in b) == list(range(200)), "不得丢下标"
    assert len(batches) >= 2, "须因降批而分成多批"


def test_preflight_refuses_oversize_single():
    """正臂（fail-loud）：降到 max_count=1 仍超 cap ⟹ 必须 raise，不得静默放行。"""
    import gk_finding_embed as ge
    texts = ["z" * 10] * 4
    raised = False
    try:
        ge.preflight_batches(texts, max_count=64, max_chars=10 ** 9, cap=1)
    except RuntimeError:
        raised = True
    assert raised, "超上限须 fail-loud（RuntimeError）"
