"""
conftest.py -- Pytest configuration for gatekeeper scripts
=================================================
Shared fixtures and utilities for gk_*.py tests.
"""

import json
import os
import signal
import subprocess

import pytest


# ── 子进程 stdin 缺省隔离（2026-11-08，长尾/蓝屏根因止血）──────────────────────
# 病象：xdist worker 继承父进程 stdin 管道（已打开、对端永不写入）⟹ 用例派生的
#   bash.exe / openssl / wsl.exe 子进程 readline 无界阻塞 ⟹ 全量在 95%+ 处「永不结束」
#   （源码定案：scripts/test_subagent_runner_stdin.py 顶部注释 + 408-research 报告）。
# 处置：未**显式**指定 stdin 的 Popen 一律 DEVNULL（显式 stdin= 的调用完全不动，
#   例如 run(input=...) 传的是 PIPE）。父链上再无「悬空读端」⟹ 卡死面消失。
_ORIG_POPEN_INIT = subprocess.Popen.__init__


def _popen_default_stdin(self, *args, **kwargs):
    # Popen(args, bufsize, executable, stdin, stdout, stderr, ...)：args 达到 4 个 ⟹
    #   stdin 已由位置参数给出，此时不得再塞 kwargs（会 TypeError 重复传参）。
    if len(args) < 4 and "stdin" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    return _ORIG_POPEN_INIT(self, *args, **kwargs)


subprocess.Popen.__init__ = _popen_default_stdin


# ── 单测看门狗（2026-11-03，全量取证引出）─────────────────────────────────────
# 背景：全量在 99% 处被 WSL 9p 的 D 态 RPC 挂起 >16min（`wchan=p9_client_rpc`），
#   xdist 其余 worker 空等。无 pytest-timeout 插件（按规则不装包）⟹ 用 SIGALRM 兜住
#   **Python 层**挂起/长睡；D 态内核等待无法被信号打断，仍需外部 stall 看门狗或迁 ext4。
# 默认 **0 = 关闭**（opt-in）：SIGALRM 若在子进程等待/teardown 中触发，可能让 xdist worker
# 非正常退出并把 controller 挂住（2026-11-03 ext4 A/B 实测过一次「无 worker、controller
# 卡在 futex」）。排障时显式开：`GK_TEST_TIMEOUT=180 pytest ...`；常驻兜底用**外部** stall
# 看门狗（日志 N 秒无增长就抓 wchan 并 kill），它不依赖测试内部状态。
_TEST_TIMEOUT_S = float(os.environ.get("GK_TEST_TIMEOUT", "0") or "0")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    if _TEST_TIMEOUT_S <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _alarm(signum, frame):
        raise TimeoutError("GK_TEST_TIMEOUT: %s 超过 %.0fs（可调 GK_TEST_TIMEOUT）"
                           % (item.nodeid, _TEST_TIMEOUT_S))

    try:
        _old = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, _TEST_TIMEOUT_S)
    except (ValueError, OSError):          # 非主线程 / 不支持 ⟹ 不阻断
        yield
        return
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, _old)


def pytest_configure(config):
    """注册 `serial` 标记（2026-10-28，性能臂专用）。

    为什么需要：性能/时间预算臂（如 `test_gk_audit_depth_index.TestPerfBound`）在 xdist
    并行下被其它 worker 抢 CPU/I/O ⟹ 实测必然击穿预算 ⟹ 假红 ⟹ `_accept_cli.sh` 把假红
    丢进**串行复核**再跑一遍（实测单臂 ≈2-5min，是收口时间的主要成分）。
    语义：标 `serial` 的臂由 `_accept_cli.sh` **排除出并行段**，在并行段之后**独占整机**
    串行跑一次（覆盖率不变，判定环境变干净）。裸 `pytest` 不做筛选时它们照常运行。
    """
    config.addinivalue_line(
        "markers",
        "serial: 时间/资源敏感，禁止在 xdist 并行段运行（由 _accept_cli.sh 串行段执行）")


@pytest.fixture
def tmp_state(tmp_path):
    """Create a temporary state file for testing."""
    state_file = tmp_path / "test_state.json"
    initial_state = {
        "r_phase": "ECO-RESEARCH",
        "stage": "STAGE_0",
        "branch": "test",
        "gate_data": {},
        "monitor_scores": {},
        "history": []
    }
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(initial_state, f, indent=2)
    return str(state_file)


@pytest.fixture
def tmp_state_with_checksum(tmp_path):
    """Create a temporary state file with valid checksum."""
    import hashlib
    state_file = tmp_path / "test_state.json"
    gate_data = {"test": "value"}
    gate_dump = json.dumps(gate_data, sort_keys=True, ensure_ascii=True)
    checksum = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
    
    initial_state = {
        "r_phase": "ECO-RESEARCH",
        "stage": "STAGE_0",
        "branch": "test",
        "gate_data": gate_data,
        "monitor_scores": {},
        "history": [],
        "_checksum": checksum
    }
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(initial_state, f, indent=2)
    return str(state_file)


@pytest.fixture
def tmp_state_tampered(tmp_path):
    """Create a temporary state file with tampered checksum."""
    state_file = tmp_path / "test_state.json"
    initial_state = {
        "r_phase": "ECO-RESEARCH",
        "stage": "STAGE_0",
        "branch": "test",
        "gate_data": {"test": "value"},
        "monitor_scores": {},
        "history": [],
        "_checksum": "0000000000000000"  # Wrong checksum
    }
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(initial_state, f, indent=2)
    return str(state_file)


# 2026-09-19（ECC-68F951431000）：本仓 `scripts/_*_test.py` 是**独立运行的红队检查脚本**，不是 pytest
# 套件 —— `.gitignore:26` 已用同一模式把它们排除出版本控制，**但 pytest 不读 .gitignore** ⟹ 收集期仍会
# import 它们；而 `_r8_test.py` 顶层是 `if FAIL: sys.exit(1)` ⟹ `INTERNALERROR: SystemExit`、
# 整个会话 "no tests ran"（所有测试都不跑）。
# ⚠ 文件内那句 `__test__ = False` **挡不住**：它在 import **完成后**才被 pytest 读取，而模块体在
#   收集期就已执行完毕。唯一可靠的排除面 = 收集器配置 ⟹ 本 glob（与 .gitignore 同口径，单一来源）。
# 效果：裸跑 `pytest` 不再需要外部 `--ignore`/`--ignore-glob`（计划文档里的那条调用纪律随之成为冗余）。
collect_ignore_glob = ["_*_test.py"]


# ── 跨用例模块级全局隔离（`ECC-2C6363430A3B` **根因层**，2026-09-24）───────────────────
# 现象（定案见 docs/plans/2026-09-22-coding-agent-slice-design.md §R25.8b）：`-n auto` 的
#   **默认 `--dist load` 按用例分配 worker** ⟹ 不同测试文件的用例在同一 worker 进程内交错
#   执行；而 `subagent_runner._bootstrap()` 一条 `global` 语句写十个模块级全局
#   （`_CFG, STDIN_API_KEY, client, model, tools, tool_names, instructions, agent, …`），
#   用例 teardown 普遍只 `monkeypatch.setattr(sr, "_CFG", None)` ⟹ `sr.client`/`sr.tool_names`
#   等**残值跨用例存活**，污染同 worker 的后续**文件**（`test_subagent_gitnexus_contract.py:296`
#   已记录该残留）。后果 = 「并行失败 / 串行通过」的假阳性被误报为真回归，反噬一键验收可信度。
# 处置分层（三层，不互相替代）：
#   **根因层** = 本夹具 —— 自动快照/还原目标模块的全部全局名 ⟹ 与 worker 分块方式**解耦**
#                （默认 dist 也稳定；红先臂 = test_subagent_runner_extract.py::
#                 test_module_global_isolation_fixture_exists_and_restores）
#   **确定层** = 运行器加 `--dist loadfile`（同文件用例恒同 worker，分配可复现）
#   **检测层** = `_accept_cli.sh` 对 NEW 集合的串行复核（独立哨兵，兜未来新泄漏）
# 新增**有状态模块**（bootstrap 式写全局）时把模块名加进本表即可，无需逐用例写纪律。
_ISOLATE_MODULES = ("subagent_runner",)
_MISSING = object()


@pytest.fixture(autouse=True)
def _isolate_module_globals():
    """用例前后快照/还原 `_ISOLATE_MODULES` 的**全部**模块级名称（浅拷贝，微秒级）。

    还原语义：用例期**新增**的名字（bootstrap 产物）删掉；**改过值**的名字复原；
    未动的名字原值写回（幂等无副作用）。`monkeypatch` 的自动回滚与本夹具并存无害。
    """
    import sys
    mods = [m for m in (sys.modules.get(n) for n in _ISOLATE_MODULES) if m is not None]
    before = [dict(vars(m)) for m in mods]
    yield
    for m, snap in zip(mods, before):
        cur = vars(m)
        for k in [k for k in cur if k not in snap]:
            del cur[k]
        for k, v in snap.items():
            if cur.get(k, _MISSING) is not v:
                cur[k] = v


# ── write-claims 台账隔离（**只对卫星/生产者侧测试文件**）（`ECC-078AAECF33FB`，2026-10-06）──────
# 卫星生产者接线后：`gk_satellite.append` 会经 `claim_anchor(repo=None)` 写 **write-claims 台账**。
#   台账默认落点 = 脚本所在仓的**主 worktree**（`gk_write_claims._default_repo` 取 `git worktree list`
#   首项）⟹ 测试内调 `append` 会**写脏生产台账**（真实 `.gatekeeper.write-claims.jsonl`，且后续
#   `reconcile` 会把 tmp 片当 zombie / unregistered 噪声）。
#   **作用域刻意收窄**：只对**会调 `append` 的测试文件**把 `GK_WRITE_CLAIMS_PATH` 钉到本用例 `tmp_path`。
#   为何不用全局（两版都被证伪）：
#     · 全局 `GK_WRITE_CLAIMS_PATH` ⟹ `test_gk_write_claims.test_arm7_append_is_best_effort`
#       （用**显式坏 repo** 造写失败）被架空（env 覆盖胜出 ⟹ 写成功 ⟹ 臂红）；
#     · 全局 patch `_default_repo` ⟹ `test_gk_write_claims_reclaim_guard.test_arm5_default_repo_single_source_via_git`
#       （**正**测默认落点走 `git worktree list`）被架空（臂红）。
#   两者都是对「默认落点机制本身」的合法臂 ⟹ 全局夹具必与之冲突。故只圈**生产者侧**文件。
_CLAIMS_ISOLATED_TEST_FILES = (
    "test_gk_satellite.py",
    "test_gk_satellite_p1p2.py",
    "test_gk_satellite_reclaim.py",
    "test_gk_satellite_claim_anchor.py",
    "test_gk_satellite_index_guard.py",
    "test_gk_satellite_finding_producer.py",
    "test_gk_task_gate.py",
    "test_gk_task_gate_group_tasks.py",
    "test_gk_history_archive.py",
    "test_gk_history_failloud.py",
    # t4(a)（2026-10-17，`ECC-2E9DA8D90CB2`）：写侧「每条 entry 全量落片」经
    #   `gk_satellite.append → claim_anchor` 写 write-claims 台账 ⟹ 须隔离。
    "test_gk_history_spill.py",
    # finding 归档生产者接线（`gk_finding.archive_closed` → `gk_satellite.append('finding')`）后，
    #   `append` 经 `claim_anchor` 写 write-claims 台账 ⟹ 这两文件的归档路径会写脏生产台账。
    "test_gk_finding.py",
    "test_gk_ember_burn.py",
    # sanctioned release 出口（`apply-worktree --release-claim`）行为臂：CLI 子进程经
    #   `gk_write_claims.release` 写台账 ⟹ 须隔离，否则写脏生产台账。
    "test_apply_worktree_release_claim.py",
    # state 撑爆闭环臂（`ECC-2A298C57FF7E`/`ECC-43D22663EFB5`）：`append`/溢出 → `claim_anchor`
    #   写台账 ⟹ 隔离（否则写脏生产台账）。
    "test_gk_state_bloat_reclaim.py",
)


@pytest.fixture(autouse=True)
def _isolate_claims_ledger_for_satellite_producers(request, tmp_path, monkeypatch):
    import os
    if os.path.basename(str(request.node.fspath)) in _CLAIMS_ISOLATED_TEST_FILES:
        monkeypatch.setenv("GK_WRITE_CLAIMS_PATH",
                           str(tmp_path / ".gatekeeper.write-claims.jsonl"))


# ── xdist 并发隔离：共享**仓级**资源（worktree 注册表 / 基线 / 台账 / 路由）────────────
# 2026-10-28 实测（`pytest -n 4 --dist loadfile`）：120 failed / 7 errors，全部集中在
# 同时对**同一个仓**执行 `git worktree add/remove`（r19）、共用 `/tmp/gk-e2e-fallback`
# （apply-worktree claims 的 stub 兜底根）、读写仓级基线/路由/密钥继承的臂 ⟹ 用**跨进程
# 文件锁**把这些测试文件串行化。单 worker（串行跑）时锁不阻塞，语义零变化。
# 判据：若新增用例会写仓级资源（git worktree / 主树 state / 仓级 jsonl），必须登记在此，
# 否则并行下是**假红**（不是回归，但会污染全量结论）。
_SHARED_REPO_TEST_FILES = frozenset({
    # git worktree 注册表：对被测仓做 add/remove
    "test_r19_keys_inherit.py",
    "test_gk_worktrees_extra.py",
    "test_gk_tamper_detect.py",
    "test_gk_apply_worktree.py",
    "test_gk_apply_worktree_claims.py",
    "test_gk_apply_worktree_close_out.py",
    "test_gk_apply_worktree_errors.py",
    "test_gk_apply_worktree_family_gate.py",
    "test_apply_worktree_release_claim.py",
    "test_gk_worktree_reclaim.py",
    "test_gk_worktree_reclaim_path_filter.py",
    "test_gk_worktree_route_visibility.py",
    "test_gk_gitnexus_worktree_normalize.py",
    # 写侧台账 / 卫星片 / 历史归档（仓级 jsonl 与索引）
    "test_gk_write_claims.py",
    "test_gk_write_claims_reclaim_guard.py",
    "test_gk_history_archive.py",
    "test_gk_satellite_reclaim.py",
    # 仓级基线 / 机器面 / 密钥继承 / 路由回填
    "test_gk_machine_check.py",
    "test_gk_foreign_scan.py",
    "test_gk_q2_hint_selfconsistency.py",
    "test_gk_q4_registration_action.py",
    "test_gk_finding_embed.py",
    "test_gk_finding_embed_memguard.py",
    "test_safety_net_convergence_node.py",
})


@pytest.fixture(autouse=True)
def _serialize_shared_repo_tests(request):
    """把共享仓级资源的测试文件在 xdist worker 间串行化（跨进程 `flock`）。"""
    import os
    import tempfile

    if os.path.basename(str(request.node.fspath)) not in _SHARED_REPO_TEST_FILES:
        yield
        return
    try:
        import fcntl
    except ImportError:  # 非 POSIX 平台不隔离（本仓测试只在 Linux/WSL 下跑）
        yield
        return
    lock_dir = os.environ.get("GK_TEST_LOCK_DIR") or tempfile.gettempdir()
    os.makedirs(lock_dir, exist_ok=True)
    with open(os.path.join(lock_dir, "gk-shared-repo-tests.lock"), "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
