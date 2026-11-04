"""
gatekeeper subagent prototype — openai-agents SDK v0.18.3
验证: tool约束 + output_guardrail + 预算限制
"""
import asyncio, os, sys, subprocess

__test__ = False  # API 原型验证脚本（需真实 key+网络+预算），非 CI 单元测试（2026-08-15：
                  # pytest 收集时无 key 顶层 exit(1) / 有 key 跑真实 API 致 MaxTurnsExceeded。
                  # 2026-08-20: 补 __main__ 保护——pytest import 时不执行 main，仅直跑脚本时调用）

from openai import AsyncOpenAI
from agents import (
    Agent, Runner, ModelSettings, function_tool,
    OpenAIChatCompletionsModel, GuardrailFunctionOutput,
    output_guardrail, set_tracing_disabled,
)
set_tracing_disabled(True)

DEEPSEEK_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
if not DEEPSEEK_KEY:
    try:
        result = subprocess.run(
            ["powershell.exe", "-Command", "[Environment]::GetEnvironmentVariable('DEEPSEEK_API_KEY','User')"],
            capture_output=True, text=True
        )
        DEEPSEEK_KEY = result.stdout.strip()
    except Exception: pass
if not DEEPSEEK_KEY:
    print('{"error":"DEEPSEEK_API_KEY not set"}'); sys.exit(1)

_ds = AsyncOpenAI(api_key=DEEPSEEK_KEY, base_url="https://api.deepseek.com/v1")
DS = OpenAIChatCompletionsModel(model="deepseek-chat", openai_client=_ds)

# ── 受限工具: 只能搜 gatekeeper ──
@function_tool
def search_gk(pattern: str, repo: str = "skill") -> str:
    """Search gatekeeper repos. repo=gatekeeper|skill"""
    r = subprocess.run(
        ["bash", "<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh",
         "search", pattern, "--repo", repo],
        capture_output=True, text=True, timeout=30
    )
    return r.stdout[:1000]

@output_guardrail
async def require_output(ctx, agent, output) -> GuardrailFunctionOutput:
    if not output or len(output.strip()) < 10:
        return GuardrailFunctionOutput(output_info="empty_or_short", tripwire_triggered=True)
    return GuardrailFunctionOutput(output_info="ok", tripwire_triggered=False)

subagent = Agent(
    name="gk-reviewer",
    instructions="用 search_gk 搜索，然后回答。简短。",
    model=DS, tools=[search_gk],
    output_guardrails=[require_output],
    model_settings=ModelSettings(temperature=0.0, max_tokens=200),
)

async def main():
    r = await Runner.run(subagent, "search 'edit_budget' in gatekeeper skill and summarize")
    print("=== PASS ===")
    print(r.final_output[:500])

if __name__ == "__main__":
    asyncio.run(main())
