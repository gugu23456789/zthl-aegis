#!/usr/bin/env python3
"""L2 受限审查模型链红先测试（2026-10-31）。

病象：`--subagent --crossrev` 的派发行原样传 `--api-model ${API_MODEL}`
⟹ 模型恒 = `DS_MODEL_CRITIC`（v4-flash 族），外部无覆盖位。
修法（本测试守护）：派发行统一走 `_subagent_model_chain`
= `GK_SUBAGENT_API_MODEL` → 当前 provider 的 `API_MODEL` → `deepseek-flash`
（与 `gk_paper_review` / `gk_pc_sim` 调 subagent_runner 的链同源）。

只做**静态读取** CLI（零 API、零 state 写入）。
"""
import re
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _txt() -> str:
    return CLI.read_text(encoding="utf-8", errors="replace")


def test_dispatch_rows_use_model_chain():
    txt = _txt()
    assert "_subagent_model_chain() {" in txt, "缺模型链单源函数"
    # 主派发 / DS 重试 / MiMo 降级 三行必须同源
    assert txt.count('--api-model "$(_subagent_model_chain)"') == 3, \
        "subagent 三处派发行未全部接入模型链"
    assert '--api-model "${API_MODEL}"' not in txt, \
        "仍有裸 API_MODEL 硬编码（L2 受限审查会退回 v4-flash 固定车道）"


def test_chain_env_first_and_mimo_isolated():
    m = re.search(r"_subagent_model_chain\(\) \{.*?\n\}", _txt(), re.S)
    assert m, "找不到 _subagent_model_chain 函数体"
    body = m.group(0)
    assert "GK_SUBAGENT_API_MODEL" in body, "模型链必须优先读 GK_SUBAGENT_API_MODEL"
    assert '"$PROVIDER" = "deepseek"' in body, \
        "env 覆盖必须限定 deepseek 车道（MiMo 端不存在 DS 模型名）"
    assert "deepseek-flash" in body, "缺省兜底须与 subagent_runner 默认一致"
