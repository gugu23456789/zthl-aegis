#!/usr/bin/env python3
"""红先臂：MoA `--serve` 页注入锚（`ECC-9FF31C13260D`）+ `--md` 非静默面（`ECC-4A6DA8F310F5`）。

病象（2026-10-10 用户实测「图没了 + 输出全是乱码」）：`render_serve_html` 用
`html.replace("</body>", widget + "</body>", 1)` 锚**首个** `</body>`；而裁定页把「下载
HTML」构造器整页源码嵌进 JS 字符串，其中已含一个 `</body>` ⟹ 注入的 `<script>` 落在
ECharts 块内部 → 图表不渲染 + 压缩 JS 被当正文显示（仅 `--serve` 变体受影响）。

判据面 = **已跟踪** `scripts/gk_moa_aggregate.py`（禁第二事实源；不新建模块）。
red-first 沙箱按 `git archive HEAD scripts` 取**未修**版 ⟹ 本文件对 HEAD 必红
（arm1/arm2/arm3 + arm_b1）；`arm_b2` 为**非红**回归守卫（HEAD 即绿），不入选红先集。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_moa_aggregate as M  # noqa: E402


# ── finding A：serve 注入锚 ────────────────────────────────────────────────
def test_arm1_injects_before_document_body():
    """臂1（主判据）：注入须落**文档级**（最后一个）`</body>` 前，不得动其前内容。

    HEAD：`replace(..., 1)` 命中 JS 字符串内首个 `</body>` ⟹ `out[:i]` 被改写、JS 串被劈开。
    """
    html = '<html><body><script>var dl="A</body>B";</script><p>hi</p></body></html>'
    i = html.rfind("</body>")
    out = M.render_serve_html(html)
    assert out[:i] == html[:i], "文档级 </body> 之前的内容不得被改动（HEAD 命中字符串内 </body>）"
    assert out.endswith(html[i:]), "文档级 </body> 及其后缀须原样保留"
    injected = out[i:len(out) - len(html[i:])]
    assert 'id="gk-serve-card"' in injected, "提交卡片须恰注入在文档级 </body> 之前"


def test_arm2_appends_without_body():
    """臂2：无 `</body>` 的片段 ⟹ 追加（禁区不静默丢弃）。HEAD 的 replace 无匹配 ⟹ 卡片全无。"""
    html = '<div id="app">hi</div>'
    out = M.render_serve_html(html)
    assert out.startswith(html), "原内容须是前缀"
    assert 'id="gk-serve-card"' in out[len(html):], "无 body 时卡片须被追加（HEAD 静默返回原文）"


def test_arm3_js_string_body_not_split():
    """臂3：JS 字符串内的 `</body>` 不得被当作锚劈开（HEAD 直接把它拦腰截断 = 乱码根因）。"""
    html = '<body><script>var t="</body>";</script><p>x</p></body>'
    out = M.render_serve_html(html)
    assert 'var t="</body>";' in out, "JS 字符串必须保持完整（HEAD 在此处插入 = 劈开脚本）"
    assert out.index('id="gk-serve-card"') > out.index('var t="</body>";'), \
        "卡片须在 JS 串之后（文档级 </body> 前），不得嵌进脚本"


# ── finding B：--md 非静默面 ─────────────────────────────────────────────
def test_arm_b1_md_surfaces_error():
    """臂 b1（主判据）：`--md` 须渲染 `error`/`hint`（未知批号/task 零命中的非静默缺口）。

    HEAD：`render_md` 只渲 references，error/hint 被吞 ⟹ 仅 rc=1 可见 = 半静默。
    """
    agg = {"error": "no_entry_matches_batch",
           "hint": "该批号在 subagent_history 中无匹配…可用 batch_id：deadbeef0001",
           "trace": {}, "references": []}
    text = M.render_md(agg)
    assert "no_entry_matches_batch" in text, "md 面须显示 error（HEAD 吞掉错误）"
    assert "batch_id" in text, "md 面须显示 hint 的可操作指引"


def test_arm_b2_md_clean_when_no_error():
    """守卫臂（**非红**：HEAD 即绿，不入选红先集）：无 error 时不得凭空渲染错误块。"""
    text = M.render_md({"trace": {}, "references": []})
    assert "聚合错误" not in text, "无 error 时不得渲染错误块（防过度修复）"
