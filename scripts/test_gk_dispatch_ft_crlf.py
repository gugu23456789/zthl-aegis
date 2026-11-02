# -*- coding: utf-8 -*-
"""红先臂（2026-11-01 二轮返工）：BARE 守卫 full_task 匹配须比较侧 CRLF 归一。

病灶演进（两轮实锤）：
  一轮误判：以为只是 bash `$()` 捕获 Windows print 留尾 \r ⟹ 在 _aft 加了
  `tr -d '\r'`（941f2e84）。二轮决定性实证推翻：存量 full_task **内含 18 处 \r\n**
  （CRLF 在组装入 state 时已烙进存储数据），于是
    - after_bash（留尾 \r）vs stored：不等（尾 \r + 内部 \r\n）；
    - after_tr（剥全部 \r）vs stored：也不等（内部 \r\n 被改成 \n，内容变了）。
  ⟹ bash 侧怎么剥都不可能同时对「存量含 CRLF」与「存量干净」两种数据都对。

正解（本臂锁定）：比较侧归一 —— `task_in_pipeline` 把两侧 `\r\n`/`\r` 归一为 `\n`
后再精确比。对存量脏数据（内含 CRLF）与传入侧干净数据（bash 已 tr）都 MATCH；
对真正不同的 task 仍不等（不放水，fail-closed 语义不变）。

臂1（行为级，红→绿）：state 里 full_task 内含 \r\n，传入 \n 版本须命中 True。
臂2（行为级，防放水）：真正不同的 task 仍须 False。
臂3（源码级）：task_in_pipeline 函数体须含归一调用（防止将来被"简化"删掉）。
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gk_task_gate import task_in_pipeline  # noqa: E402

_STORED = "【preflight 证据摘要】第一行。\r\n第二行，含 SOURCES: URL 列表。"
_CLEAN = "【preflight 证据摘要】第一行。\n第二行，含 SOURCES: URL 列表。"


def _mk_state(tmp: Path) -> str:
    sf = tmp / "state.json"
    sf.write_text(
        json.dumps(
            {"gate_data": {"task_pipeline": [{"full_task": _STORED}]}},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return str(sf)


def test_task_in_pipeline_normalizes_crlf():
    """臂1（红→绿）：存量含 \r\n 的 full_task 与 \n 版本传入须 MATCH。"""
    with tempfile.TemporaryDirectory() as td:
        sf = _mk_state(Path(td))
        assert task_in_pipeline(sf, _CLEAN) is True, (
            "存量 full_task 内含 \\r\\n 时，传入 \\n 版本未命中 ⟹ 裁决派发 "
            "BARE_PLAN_REFINEMENT 必挂（2026-11-01 二轮实锤：bash 侧无论剥不剥 "
            "\\r 都救不了，须 task_in_pipeline 比较侧归一 CRLF）。"
        )


def test_task_in_pipeline_still_rejects_different():
    """臂2（防放水）：真正不同的 task 仍须 False（fail-closed 不变）。"""
    with tempfile.TemporaryDirectory() as td:
        sf = _mk_state(Path(td))
        assert task_in_pipeline(sf, "完全不同的任务串") is False
        # 前缀相同但尾部不同也不许命中
        assert task_in_pipeline(sf, _CLEAN + "。") is False


def test_task_in_pipeline_source_has_normalization():
    """臂3（源码级）：函数体须显式归一 CRLF（防回归成裸 ==）。"""
    src = (Path(__file__).resolve().parent / "gk_task_gate.py").read_text(
        encoding="utf-8"
    )
    i = src.find("def task_in_pipeline")
    assert i >= 0, "task_in_pipeline 缺失"
    body = src[i: src.find("\ndef ", i + 1)]
    assert "\\r" in body, (
        "task_in_pipeline 函数体内无 \\r 归一处理 ⟹ 回归为裸精确匹配，"
        "存量含 CRLF 的 full_task 将恒不命中（BARE 复燃）。"
    )
