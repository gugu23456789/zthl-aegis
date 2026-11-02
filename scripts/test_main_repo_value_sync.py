"""主仓路径**单源**判据（2026-10-31 开源前置；替代原「三处字面量逐字一致」）。

原判据（C1b/C4）要求 `gatekeeper-cli.sh` / `gk_route_center.py` / `subagent_runner.py`
三处**字面量副本**逐字一致 —— 那是「物理迁移不漏改」的锚，但也是 OSS 可移植性的阻断：
新用户 clone 后主仓指向别人的机器。

现判据：
  1. 三处**均不含**个人主仓字面量（`<workspace>`）；
  2. 三处**均引用**单源 `gk_main_repo`（bash 经 `gk_main_repo.sh`）；
  3. 单源解析优先级 = GK_MAIN_REPO → state.target_repo → META → git（见 test_gk_main_repo.py）。
"""
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
CLI_PATH = SKILL_DIR / "gatekeeper-cli.sh"
ROUTE_CENTER = SKILL_DIR / "scripts" / "gk_route_center.py"
RUNNER = SKILL_DIR / "scripts" / "subagent_runner.py"
SINGLE_SOURCE = SKILL_DIR / "scripts" / "gk_main_repo.py"

# 拼接写法（2026-11-02 CI 修复）：OSS scrub 会把整串字面量替换成 `<workspace>`，
#   与 gatekeeper-cli.sh 注释里的占位符撞车 ⟹ 公开包恒红。拆成两段后 scrub 不命中，
#   判据（三处均不含个人主仓字面量）不变。
_LEGACY_LITERAL = "HunYuan3D" + "_test_cases"


def test_no_hardcoded_main_repo_in_three_copies():
    for p in (CLI_PATH, ROUTE_CENTER, RUNNER):
        src = p.read_text(encoding="utf-8")
        assert _LEGACY_LITERAL not in src, f"{p.name} 仍含个人主仓字面量（OSS 不可移植）"


def test_all_three_delegate_to_single_source():
    assert SINGLE_SOURCE.exists(), "单源 gk_main_repo.py 缺失"
    assert "gk_main_repo.sh" in CLI_PATH.read_text(encoding="utf-8"), \
        "gatekeeper-cli.sh 未 source 单源薄壳"
    assert "gk_main_repo" in ROUTE_CENTER.read_text(encoding="utf-8"), \
        "gk_route_center.py 未引用单源"
    assert "gk_main_repo" in RUNNER.read_text(encoding="utf-8"), \
        "subagent_runner.py 未引用单源"
