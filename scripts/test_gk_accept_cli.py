#!/usr/bin/env python3
"""`scripts/_accept_cli.sh` 的自测（3 臂）—— 验收一键器的「基线 diff」逻辑必须可判别。

背景（2026-09-23）：全量回归 12.7 min，每次验收都重跑同一批**已知失败** ⟹ 固化基线 + 只跑子集。
本文件**不测**任何具体被测面，只测**一键器本身**的三种判定：
  ① 基线里的条目不再失败 ⟹ 报 `FIXED` 且 **exit 0**（不能把「修好了」当回归）；
  ② 基线外的失败 ⟹ 报 `NEW` 且 **exit 1**（真回归必须拦）；
  ③ `--snapshot` 把当前失败集写进基线后 ⟹ 同一条不再报 `NEW`（往返自洽）；
  ④ 基线缺失 ⟹ **exit 2**（fail-loud，禁止把「无基线」当「无失败」静默放行）。

被测面用**临时目录外的测试文件**（显式路径传入），与本仓测试状态**解耦**。
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
ACCEPT = SCRIPT_DIR / "_accept_cli.sh"
# 解释器**单源**（同 `_accept_cli.sh`）：env → `_accept_py.local`（本机私有）→ python3。
sys.path.insert(0, str(SCRIPT_DIR))
from gk_accept_py import resolve as _resolve_accept_py  # noqa: E402
PY = _resolve_accept_py()


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _accept(test_file: Path, baseline: Path, *extra: str):
    env = dict(os.environ, ACCEPT_BASELINE=_wsl(baseline), ACCEPT_PY=PY)
    return subprocess.run(
        ["bash", _wsl(ACCEPT), _wsl(test_file), *extra],
        capture_output=True, text=True, env=env, timeout=300)


@pytest.fixture(autouse=True)
def _need_bash():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下无法执行一键器）")


def _extract_block(out: str, marker: str) -> list:
    """抽 `[accept]` 输出块里带 marker 的条目行（缩进两空格的 nodeid 行）。"""
    return [ln.strip() for ln in out.splitlines()
            if marker in ln and ln.startswith("  ")]


def test_accept_stale_baseline_is_not_a_regression(tmp_path):
    """① 基线里的条目**已不再失败** ⟹ 不得当回归（exit 0 且不报 NEW）。
    另钉一条标定：**子集模式不判 `FIXED`** —— 否则会把「未被本跑覆盖」的文件全报成已修
    （首版实测：3 文件子集刷出 29 条假 FIXED）。"""
    tf = tmp_path / "test_zz_pass.py"
    tf.write_text("def test_zz_pass():\n    assert True\n", encoding="utf-8")
    bl = tmp_path / "baseline.txt"
    bl.write_text("# baseline\n" + _wsl(tf) + "::test_zz_pass\n", encoding="utf-8")
    r = _accept(tf, bl)
    assert r.returncode == 0, f"应 exit 0（无新增失败）\n{r.stdout}\n{r.stderr}"
    assert "✓ 无新增失败" in r.stdout, r.stdout
    assert "✗ NEW" not in r.stdout, f"stale 基线条目不得报为 NEW\n{r.stdout}"
    assert "FIXED" not in r.stdout, (
        f"子集模式不得判 FIXED（会刷未覆盖文件的假 FIXED）\n{r.stdout}")


def test_accept_flags_new_then_snapshot_absorbs_it(tmp_path):
    """②+③ 基线外失败 ⟹ exit 1；`--snapshot` 吸收后 ⟹ 同一条不再报 NEW 且 exit 0。"""
    tf = tmp_path / "test_zz_fail.py"
    tf.write_text("def test_zz_fail():\n    assert False, 'boom'\n", encoding="utf-8")
    bl = tmp_path / "baseline.txt"
    bl.write_text("# baseline（空）\n", encoding="utf-8")

    r1 = _accept(tf, bl)
    assert r1.returncode == 1, f"基线外失败必须 exit 1\n{r1.stdout}\n{r1.stderr}"
    new = _extract_block(r1.stdout, "::test_zz_fail")
    assert new, f"应列出 NEW 的 nodeid\n{r1.stdout}"

    r2 = _accept(tf, bl, "--snapshot")
    assert r2.returncode == 0, f"snapshot 应 exit 0\n{r2.stdout}\n{r2.stderr}"

    r3 = _accept(tf, bl)
    assert r3.returncode == 0, f"吸收后应 exit 0\n{r3.stdout}\n{r3.stderr}"
    assert not _extract_block(r3.stdout, "::test_zz_fail"), (
        f"已入基线的失败不得再报 NEW/FIXED\n{r3.stdout}")


def test_accept_missing_baseline_fails_loud(tmp_path):
    """④ 基线缺失 ⟹ exit 2（不得静默把「无基线」当「无失败」）。"""
    tf = tmp_path / "test_zz_pass2.py"
    tf.write_text("def test_zz_pass2():\n    assert True\n", encoding="utf-8")
    r = _accept(tf, tmp_path / "nope.txt")
    assert r.returncode == 2, f"基线缺失必须 exit 2（fail-loud）\n{r.stdout}\n{r.stderr}"
    assert "FATAL" in r.stdout, r.stdout


def test_accept_filters_parallel_only_false_positive(tmp_path):
    """⑤ `ECC-2C6363430A3B`：`-n auto` 下「并行失败 / 串行通过」的**假阳性**必须被滤除（exit 0）。

    夹具直接造出该形态：被测用例在 xdist worker 内失败（`PYTEST_XDIST_WORKER` 存在）、
    而**串行复核时通过** ⟹ 一键器须报「假阳性」并**放行**，不得误判为真回归。
    （真实触发源：跨文件状态泄漏 + 分块漂移；此处用可控等价形态钉住**复核逻辑**本身。）
    """
    tf = tmp_path / "test_zz_par.py"
    tf.write_text(
        "import os\n"
        "def test_zz_par():\n"
        "    assert not os.environ.get('PYTEST_XDIST_WORKER'), 'parallel-only fail'\n",
        encoding="utf-8")
    bl = tmp_path / "baseline.txt"
    bl.write_text("# baseline（空）\n", encoding="utf-8")
    env = dict(os.environ, ACCEPT_BASELINE=_wsl(bl), ACCEPT_PY=PY, ACCEPT_JOBS="2")
    r = subprocess.run(["bash", _wsl(ACCEPT), _wsl(tf)],
                       capture_output=True, text=True, env=env, timeout=300)
    assert r.returncode == 0, (
        f"并行假阳性应被串行复核滤除（exit 0），不得判真回归\n{r.stdout}\n{r.stderr}")
    assert "假阳性" in r.stdout, f"应报告假阳性条目\n{r.stdout}"
    assert "✗ NEW" not in r.stdout, f"滤除后不得再报 NEW\n{r.stdout}"


# ── ECC-34EEC2BC12D2（跨会话全量无互斥；2026-09-28 user 裁定「跨会话互斥 flock」）─────
# 痛点：两会话各自 `--full` ⟹ 争 CPU 互相拖慢，且都重跑同一批（= 最慢的串行全量 ×N）。
# 以下两臂用**假解释器**把 `--full` 缩成毫秒级（真 pytest 全量 ≈ 230s，不可入测），
# 从而可判别「互斥」与「复用」两个行为面本身。

def _stub_py(tmp_path: Path) -> Path:
    """假解释器：每次被 `"$PY" -m pytest …` 调用即向 `$STUB_LOG` 追加 START/END 行，并打印
    pytest 风格摘要。默认「全通过」⟹ 不触发 NEW 串行复核 ⟹ 每次调用 = 恰好一对 START/END。"""
    stub = tmp_path / "stub_py.sh"
    stub.write_text(
        "#!/bin/bash\n"
        'printf "START %s\\n" "$$" >> "$STUB_LOG"\n'
        '[ -n "${STUB_SLEEP:-}" ] && [ "$STUB_SLEEP" != "0" ] && sleep "$STUB_SLEEP"\n'
        'printf "END %s\\n" "$$" >> "$STUB_LOG"\n'
        'echo "2 passed in 0.01s"\n'
        "exit 0\n",
        encoding="utf-8")
    stub.chmod(0o755)
    return stub


def _max_depth(log: Path) -> int:
    """按 START/END 行算日志里的**最大并发深度**（>1 = 发生了重叠 = 未互斥）。"""
    depth = mx = 0
    for ln in log.read_text(encoding="utf-8").splitlines():
        if ln.startswith("START"):
            depth += 1
            mx = max(mx, depth)
        elif ln.startswith("END"):
            depth -= 1
    return mx


def test_accept_full_is_cross_session_serialized(tmp_path):
    """⑥ `ECC-34EEC2BC12D2`：两并发 `--full` 必须**互斥**（后到者等待，不得同时跑）。
    夹具：假解释器每次调用写 START/END 到日志 ⟹ 最大并发深度 >1 即判未互斥。"""
    log = tmp_path / "run.log"
    log.write_text("", encoding="utf-8")
    stub = _stub_py(tmp_path)
    bl = tmp_path / "baseline.txt"
    bl.write_text("# baseline（空）\n", encoding="utf-8")
    env = dict(os.environ, ACCEPT_BASELINE=_wsl(bl), ACCEPT_PY=_wsl(stub),
               STUB_LOG=_wsl(log), STUB_SLEEP="1.0", ACCEPT_JOBS="0",
               ACCEPT_REUSE_TTL="0", ACCEPT_LOCK_FILE=_wsl(tmp_path / "full.lock"))
    ps = [subprocess.Popen(["bash", _wsl(ACCEPT), "--full"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, env=env) for _ in range(2)]
    outs = [p.communicate(timeout=120) for p in ps]
    md = _max_depth(log)
    assert md == 1, (
        f"并发 --full 未互斥（最大并发深度={md}）\n{log.read_text(encoding='utf-8')}")
    assert all(p.returncode == 0 for p in ps), [o for o in outs]


def test_accept_full_reuses_fresh_result(tmp_path):
    """⑦ `ECC-34EEC2BC12D2`：取得锁后若已有**新鲜**结果戳（同 HEAD + 同基线 + TTL 内）⟹
    复用，不再跑（避免重复跑最慢的串行全量）。"""
    log = tmp_path / "run.log"
    log.write_text("", encoding="utf-8")
    stub = _stub_py(tmp_path)
    bl = tmp_path / "baseline.txt"
    bl.write_text("# baseline（空）\n", encoding="utf-8")
    env = dict(os.environ, ACCEPT_BASELINE=_wsl(bl), ACCEPT_PY=_wsl(stub),
               STUB_LOG=_wsl(log), ACCEPT_JOBS="0",
               ACCEPT_LOCK_FILE=_wsl(tmp_path / "full.lock"),
               ACCEPT_REUSE_TTL="1800")
    r1 = subprocess.run(["bash", _wsl(ACCEPT), "--full"], capture_output=True,
                        text=True, env=env, timeout=120)
    assert r1.returncode == 0, r1.stdout + r1.stderr
    r2 = subprocess.run(["bash", _wsl(ACCEPT), "--full"], capture_output=True,
                        text=True, env=env, timeout=120)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    starts = [ln for ln in log.read_text(encoding="utf-8").splitlines()
              if ln.startswith("START")]
    assert len(starts) == 1, (
        f"第二次 --full 应复用、不得再跑（STUB 调用数={len(starts)}）\n{r2.stdout}")
    assert "复用" in r2.stdout, f"第二次应打印复用提示\n{r2.stdout}"


# ── ECC-94AA4F0B3D3A（accept 基线位置绑定；2026-10-02 收尾：③ worktree 提示 + ② 豁免清单机检）──
# 痛点：`_accept_baseline.txt` 恒在**主树**拍摄，而部分臂**位置依赖**（真实技能目录 vs feature
#   worktree）⟹ 在 worktree 内跑 accept 会把这批臂的新增红当 `NEW` = **假回归**（实测 2 条）。

def test_accept_location_exempt_list_is_valid():
    """⑧（**机检臂**）位置依赖豁免清单必须自洽：文件存在、非空、每条形如
    `<test_*.py>::…` 且对应文件存在、不与基线重复、含「为何位置依赖」理由注释。

    纯静态检查（不跑被测面）⟹ 快速、确定性。
    """
    exempt = SCRIPT_DIR / "_accept_location_exempt.txt"
    assert exempt.is_file(), "缺位置依赖豁免清单 scripts/_accept_location_exempt.txt"
    txt = exempt.read_text(encoding="utf-8")
    entries = [ln.strip() for ln in txt.splitlines()
               if ln.strip() and not ln.lstrip().startswith("#")]
    # 允许**空清单**（条目已全部环境无关化；2026-10-02 `ECC-94AA4F0B3D3A` 闭环），但须留显式标记，
    # 防「文件被误清空」导致本机制静默失效（空 ≠ 未启用）。
    if not entries:
        assert any("当前无位置依赖条目" in ln for ln in txt.splitlines()
                   if ln.lstrip().startswith("#")), \
            "豁免清单为空却无「当前无位置依赖条目」标记（疑被误清空）"
    baseline = SCRIPT_DIR / "_accept_baseline.txt"
    bl = set()
    if baseline.is_file():
        bl = {ln.strip() for ln in baseline.read_text(encoding="utf-8").splitlines()
              if ln.strip() and not ln.lstrip().startswith("#")}
    for e in entries:
        assert "::" in e, f"非法 nodeid（缺 `::`）：{e}"
        fname = e.split("::", 1)[0]
        assert (SCRIPT_DIR / fname).is_file(), f"豁免条目指向不存在的测试文件：{e}"
        assert e not in bl, f"豁免条目同时进了基线（双重登记）：{e}"
    assert any("位置依赖" in ln for ln in txt.splitlines() if ln.lstrip().startswith("#")), \
        "豁免清单缺「为何位置依赖」说明注释"


def test_accept_exempt_location_dependent_not_new(tmp_path):
    """⑨（**行为臂**）豁免清单里的失败**不得**报 `NEW`（位置依赖非回归）⟹ exit 0 且列 `EXEMPT`。

    夹具：一个必然失败的用例 + 一份把它列为豁免的临时清单（`ACCEPT_EXEMPT` 注入）⟹ 若不豁免
    则会 exit 1 报 NEW（对照 test_accept_flags_new_then_snapshot_absorbs_it）。
    """
    tf = tmp_path / "test_zz_loc.py"
    tf.write_text("def test_zz_loc():\n    assert False, 'loc'\n", encoding="utf-8")
    bl = tmp_path / "baseline.txt"
    bl.write_text("# baseline（空）\n", encoding="utf-8")
    # 先跑一次（无豁免）拿到 CUR 里该失败的**真实 nodeid 形态**（pytest 对 tmp 绝对路径会输出
    # 相对 rootdir 的 `../../…` 形态 ⟹ 不得手写绝对路径，否则豁免条目与 CUR 逐字不等）。
    r0 = _accept(tf, bl)
    assert r0.returncode == 1, f"无豁免时应报 NEW 并 exit 1\n{r0.stdout}\n{r0.stderr}"
    hits = _extract_block(r0.stdout, "::test_zz_loc")
    assert hits, f"未从 NEW 块抽到 nodeid\n{r0.stdout}"
    nodeid = hits[0]
    ex = tmp_path / "exempt.txt"
    ex.write_text("# 位置依赖：演示\n" + nodeid + "\n", encoding="utf-8")
    env = dict(os.environ, ACCEPT_BASELINE=_wsl(bl), ACCEPT_PY=PY,
               ACCEPT_EXEMPT=_wsl(ex))
    r = subprocess.run(["bash", _wsl(ACCEPT), _wsl(tf)],
                       capture_output=True, text=True, env=env, timeout=300)
    assert r.returncode == 0, f"豁免项不得判真回归\n{r.stdout}\n{r.stderr}"
    assert "EXEMPT" in r.stdout, f"应显式列出 EXEMPT 命中\n{r.stdout}"
    assert "✗ NEW" not in r.stdout, f"豁免后不得再报 NEW\n{r.stdout}"


# ── 硬件自适应接线（2026-10-29，user 令「把硬件自适应接进去」）─────────────────────
def test_accept_and_redfirst_use_hub_adaptive_workers():
    """⑩（**机检臂**）并发度**基数**必须来自 `gk_hub_scheduler.adaptive_workers`。

    病：`gk_hub_scheduler` 的 docstring 声称 accept/redfirst 一律挂它，但两个 `.sh` 各自
    用 `nproc×2` 自算 ⟹ 「硬件自适应」从未接线（同一策略三个源）。
    """
    for name in ("_accept_cli.sh", "_redfirst_cli.sh"):
        txt = (SCRIPT_DIR / name).read_text(encoding="utf-8")
        assert "gk_hub_scheduler" in txt and "adaptive_workers" in txt, \
            "%s 未接 gk_hub_scheduler.adaptive_workers（并发度须单源）" % name
        assert "_CPU=" not in txt, "%s 仍有自算 nproc 的旧路径" % name


def test_accept_cli_wires_subprocess_factor():
    """408 公式接线（**机检臂**）：f 缺省 1（混合面）⟹ 不再 ×2；f=0 显式退回旧口径。

    f 必须**由公式单源**消费（`subprocess_factor=`），不得在 `.sh` 里另写一套阈值。
    """
    txt = (SCRIPT_DIR / "_accept_cli.sh").read_text(encoding="utf-8")
    assert 'ACCEPT_SUBPROC_FACTOR:-1' in txt, "f 缺省须为 1（每用例至少 1 次外部子进程）"
    assert "subprocess_factor=${_FACTOR}" in txt, "f 未传给 adaptive_workers（公式旁路）"
    assert "_DEF_JOBS=$(( _BASE_W * 2 ))" in txt, "f=0 旧口径须保留（紧急回退开关）"


def test_accept_cli_has_explosion_guard():
    """防爆硬闸（**机检臂**）：启动前空闲内存 <800MB 必须 fail-loud 拒绝，不静默串行。"""
    txt = (SCRIPT_DIR / "_accept_cli.sh").read_text(encoding="utf-8")
    assert "ACCEPT_MIN_FREE_MB:-800" in txt, "缺防爆硬闸默认值（800MB）"
    assert "防爆硬闸" in txt and "free_avail_mb" in txt, "硬闸未接 gk_hub_scheduler.free_avail_mb"
    assert "exit 2" in txt, "硬闸命中须 fail-loud（exit 2）"

