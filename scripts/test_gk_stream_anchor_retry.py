#!/usr/bin/env python3
"""红先臂：evidence-锚/必需字段**重试流中断**的可观测性与账实一致（`ECC-9792B39A6B0C`）。

病象（2026-10-10 实测）：`_run_once` 内 `Runner.run_streamed().stream_events()` 抛
`process() takes no keyword arguments`，被 `except Exception as _se` 吞掉后**只记 `str(e)`**
（无 traceback）⟹ 真身不可定位；且 F-REV-81 / F-REV-97 两处重试即使流中断（或整轮异常）
仍写 `retried=True` ⟹ **账实歧义**（「发起过重试」与「重试真跑通」混为一谈）。

判据（**HEAD 必红**）：HEAD 版 `subagent_runner.py` 无 `_stream_ok`/`_sok0`/
`stream_broken`/`retry_failed` 与 traceback 落盘 ⟹ 断言失败；修后绿。
判据面 = **已跟踪** `scripts/subagent_runner.py` 源码切片（禁第二事实源；不新建模块）。
"""
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _src() -> str:
    return (_HERE / "subagent_runner.py").read_text(encoding="utf-8")


def test_arm1_run_once_returns_stream_ok_tuple():
    """臂1（主判据 · 契约）：`_run_once` 回报流是否完好（返回 **4 元组**，末位 `_stream_ok`），
    上层据以解包 `_sok0`。HEAD 恒 3 元组 ⟹ 红。"""
    src = _src()
    assert "_stream_ok = True" in src, "run_once 未初始化 _stream_ok"
    assert "_stream_ok = False" in src, "流中断未置 _stream_ok=False"
    assert "return _res, _txt, _extract_llm_json(_txt), _stream_ok" in src, \
        "run_once 未返回 4 元组（stream_ok 未回报）"
    assert ", llm_data, _sok0 = await _run_once(_run_input)" in src, \
        "首调未解包 _sok0（流态未上浮）"


def test_arm2_stream_except_drops_traceback():
    """臂2（可定位性）：流消费 except 分支须落**完整 traceback**（原只记 `str(e)` ⟹ 真身不可定位）。"""
    src = _src()
    assert "import traceback as _tb" in src, "except 分支未 import traceback"
    assert "_tb.format_exc()" in src, "except 分支未落 traceback（仅 str(e) 不可定位真身）"


def test_arm3_first_stream_broken_flagged():
    """臂3（账实一致 · 首轮）：首轮流中断须置 `verification["stream_broken"]=True`。"""
    src = _src()
    assert "if not _sok0:" in src, "未据 _sok0 判首轮流态"
    assert 'verification["stream_broken"] = True' in src, \
        "首轮流中断未标记 stream_broken（账实歧义：聚合可用却不记首轮流残缺）"


def test_arm4_frev81_retry_failed_flagged():
    """臂4（账实一致 · F-REV-81）：重试流中断/异常须置 `verification["retry_failed"]=True`，
    且重试结果须**切片为 3 元组**再喂 `_pick_retry_result`（契约守恒）。"""
    src = _src()
    assert "_retry_broke = not _r[3]" in src, "F-REV-81 未捕获重试流态"
    assert "_new = _r[:3]" in src, "F-REV-81 重试结果未切片为 3 元组（契约破裂）"
    assert 'verification["retry_failed"] = True' in src, \
        "F-REV-81 重试白跑仍记 retried=True（账实歧义）"


def test_arm5_frev97_retry_failed_flagged():
    """臂5（账实一致 · F-REV-97）：同形 —— 重试流中断/异常须置
    `evidence_anchor["retry_failed"]=True`，结果切片为 3 元组。"""
    src = _src()
    assert "_retry_broke2 = not _r2[3]" in src, "F-REV-97 未捕获重试流态"
    assert "_new = _r2[:3]" in src, "F-REV-97 重试结果未切片为 3 元组（契约破裂）"
    assert 'evidence_anchor["retry_failed"] = True' in src, \
        "F-REV-97 重试白跑仍记 retried=True（账实歧义）"


def test_guard6_retry_pick_contract_is_3tuple():
    """守卫臂（**非红**：HEAD 即绿，不入选红先集）：`_pick_retry_result` 契约仍按
    3 元组解包（`_r, _t, _d = new`）—— 防为接 4 元组而把 helper 也改成 4 元组（第二处漂移）。"""
    src = _src()
    assert "_r, _t, _d = new" in src, "_pick_retry_result 契约被改（应恒按 3 元组解包）"
