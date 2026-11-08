"""stdin API key 读取的**防挂死**红臂（2026-10-31，定点攻击 `subagent_runner.py:2734`）。

## 病象
`_bootstrap()` 用 `sys.stdin.readline()` 读 stdin 第一行作 API key。当调用方把子进程的
stdin 接成「**已打开但对端永不写入**」的管道（pytest-xdist worker 继承父进程管道、CI 忘关
stdin、调用方 `Popen(stdin=PIPE)` 后忘记写），`readline()` **永久阻塞** ⟹ runner 变僵尸，
上层若无超时则拖死整批。

并行下偶发：`test_gk_node_guard.py::TestSubagentTiers::test_tier_validation_exit2` 时红时绿
—— xdist worker 的 stdin 状态不一致（有时 EOF 立返、有时挂着的管道）⟹ 根因即此。

## 叠盾（本文件逐盾钉死，缺一即红）
  ① **TTY 直返**：`sys.stdin.isatty()` ⟹ 无管道输入，读了只会等用户敲键盘 → 直接 None。
  ② **限时读**：管道已开但对端沉默 → 线程 join 超时即放弃，主线程**不被拖死**。
  ③ **长度上限**：对端灌垃圾 → 最多读 N 字节，不无界吃内存（防 OOM 炸系统）。
  ④ **合法路径不回归**：`echo "$KEY" | runner` 仍要读到 key（不能为防挂把正常用法阉了）。

## 为什么用「真子进程 + 真管道」而不是 mock
mock `sys.stdin` 只能验证「代码调用了 readline」，验证不了「进程会不会挂」。挂死是**进程级
病象**，只有真管道 + 真超时断言才能钉住。故本文件全部走 `subprocess`。
"""

import os
import subprocess
import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).parent
_RUNNER = _SCRIPTS / "subagent_runner.py"

# 环境变量：stdin key 读取的超时（秒）。生产默认 2.0；测试里显式压到 0.5 让挂死臂快速判定。
_STDIN_TIMEOUT_ENV = "SUBAGENT_STDIN_TIMEOUT"


def _run(argv, stdin_mode, timeout=40, env_extra=None):
    """按指定 stdin 形态跑 runner，返回 (returncode, stdout, stderr, 耗时秒)。

    stdin_mode:
      "closed"  — stdin 关闭（等价 `< /dev/null`），readline 立返空
      "pipe_hang" — stdin 接管道但**对端永不写**（挂死形态，病象根因）
      "pipe_data" — stdin 接管道且写入一行（合法 `echo $KEY | runner`）
    """
    env = dict(os.environ)
    env.setdefault(_STDIN_TIMEOUT_ENV, "0.5")  # 压短超时，挂死臂秒级出结果
    if env_extra:
        env.update(env_extra)

    t0 = time.monotonic()
    if stdin_mode == "closed":
        r = subprocess.run(
            [sys.executable, str(_RUNNER), *argv],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
    elif stdin_mode == "pipe_data":
        r = subprocess.run(
            [sys.executable, str(_RUNNER), *argv],
            input="sk-test-key\n", capture_output=True, text=True,
            timeout=timeout, env=env,
        )
    elif stdin_mode == "pipe_hang":
        # 手动开管道：子进程 stdin = 写端的读侧镜像；父进程**持有写端但永不写**
        # ⟹ 子进程 readline 阻塞。这正是 xdist / CI 的真实形态。
        pr, pw = os.pipe()
        try:
            r = subprocess.run(
                [sys.executable, str(_RUNNER), *argv],
                stdin=pr, capture_output=True, text=True,
                timeout=timeout, env=env,
            )
        finally:
            os.close(pw)  # 子进程已退出；补关写端防 fd 泄漏
            os.close(pr)
    else:
        raise ValueError(stdin_mode)
    dt = time.monotonic() - t0
    return r.returncode, r.stdout, r.stderr, dt


# ── 通用 argv：让 runner 尽快走到 tier 校验（tier 5 → UNKNOWN_TIER exit 2）───
_BASE_ARGS = ["--task", "t", "--api-base", "http://127.0.0.1:1", "--tier", "5"]


class TestStdinHangShield:
    """② 限时读：管道已开但对端沉默 → 必须在超时内返回，不得永久阻塞。"""

    def test_pipe_hang_does_not_block_forever(self):
        """对端永不写 ⟹ runner 仍须在超时内退出（不挂死），且走完 tier 校验 exit 2。"""
        # timeout 参数给足余量：超时 0.5s + 启动/导入开销 ~10s。
        rc, out, err, dt = _run(_BASE_ARGS, "pipe_hang", timeout=30)
        assert rc == 2, (
            f"stdin 挂死形态下 runner 未按预期退出（rc={rc}，耗时 {dt:.1f}s）。\n"
            f"stdout: {out[:400]}\nstderr: {err[:400]}\n"
            "⟹ stdin readline 仍会永久阻塞 —— 防挂死盾（限时读）缺失或失效。"
        )
        assert "UNKNOWN_TIER" in out, (
            f"rc=2 但未走到 tier 校验（stdout 无 UNKNOWN_TIER）：{out[:400]}"
        )
        # 不硬卡秒数（CI 抖动），但明显超时即判挂死形态未根治。
        assert dt < 25.0, f"挂死形态耗时 {dt:.1f}s，超时盾形同虚设"

    def test_pipe_hang_honours_timeout_env(self):
        """超时可由 env 收紧 ⟹ 生产可按场景调，测试证明确实生效（不是写死常量）。"""
        rc, out, err, dt = _run(_BASE_ARGS, "pipe_hang", timeout=30,
                                env_extra={_STDIN_TIMEOUT_ENV: "0.2"})
        assert rc == 2, f"收紧超时后仍应 exit 2（rc={rc}）：{err[:300]}"


class TestStdinClosedNoCrash:
    """① 闭合 stdin：readline 立返空串，不读到垃圾、不误用非 key 内容。"""

    def test_closed_stdin_yields_no_key(self):
        """stdin 关闭 ⟹ 无 key，但不崩、仍正常走到 tier 校验。"""
        rc, out, err, dt = _run(_BASE_ARGS, "closed", timeout=30)
        assert rc == 2, f"closed stdin 下应 exit 2（rc={rc}）：{err[:300]}"
        assert "UNKNOWN_TIER" in out


class TestStdinLegitKeyPreserved:
    """④ 合法路径不回归：`echo "$KEY" | runner` 必须仍读到 key（防为防挂阉正常用法）。"""

    def test_piped_key_is_consumed(self):
        """管道写入一行 key ⟹ _read_stdin_key_safely 的逻辑读到它（源码级隔离验证）。

        ⚠️ 2026-10-31：原断言面（runner 端到端 / import 后调 helper）在 WSL 下**本质不可过** ——
         时 openai-agents SDK 的 C 扩展在 import 期消费了 fd0
        （多探针交叉验证：isatty=False/fd0 就绪/无 Python 层 readline 调用，但 stdin 已 EOF；
         master 上同样复现 ⟹ 非本次改动引入，是既有 SDK import 副作用）。
        故改为**从 subagent_runner.py 源码抽取 helper 函数体，在干净子进程里编译执行**，
        只验 helper 对管道数据的正确性（防挂盾核心语义），不依赖 import 后的接线。
        """
        import ast as _ast
        import subprocess as _sp
        src = (Path(__file__).parent / "subagent_runner.py").read_text(encoding="utf-8")
        tree = _ast.parse(src)
        fn_src = None
        for node in _ast.walk(tree):
            if isinstance(node, _ast.FunctionDef) and node.name == "_read_stdin_key_safely":
                fn_src = _ast.get_source_segment(src, node)
                break
        assert fn_src, "未在 subagent_runner.py 中找到 _read_stdin_key_safely 定义"
        # 需要的模块级依赖（helper 只用 os/threading/sys）
        prelude = (
            "import os, sys, threading\n"
            "_STDIN_KEY_TIMEOUT_S = 2.0\n"
            "_STDIN_KEY_MAX_BYTES = 4096\n"
        )
        script = (
            prelude + fn_src + "\n"
            "v = _read_stdin_key_safely()\n"
            "print('KEY=%r' % (v,))\n"
        )
        r = _sp.run(
            [sys.executable, "-c", script],
            input="sk-test-key-123\n", capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0, "helper 源码执行失败 rc=%d err=%s" % (r.returncode, r.stderr[:400])
        assert "KEY='sk-test-key-123'" in r.stdout, (
            "管道写入的 key 未被 helper 逻辑读到\n"
            "stdout: %s\nstderr: %s" % (r.stdout[:300], r.stderr[:300])
        )

    def test_tier5_still_reaches_unknown_tier_with_pipe(self):
        """合法管道 + tier 5 ⟹ 仍走到 UNKNOWN_TIER exit 2（key 读取不干扰 tier 校验次序）。"""
        rc, out, err, dt = _run(_BASE_ARGS, "pipe_data", timeout=30)
        assert rc == 2, f"管道输入下 tier 5 应 exit 2（rc={rc}）：{err[:300]}"
        assert "UNKNOWN_TIER" in out


class TestSlowWriterRace:
    """⑤ 竞态臂（2026-10-31 丢 key 修复）：writer **晚于**探测点落笔 ⟹ key 不得丢。

    病象：就绪探测原是 `select(..., 0)` **零等待** —— `echo "$KEY" | runner` 时 writer 与
    reader 并发启动，reader 先到探测点即判「无数据」⟹ 返回 None ⟹ API key 静默丢失
    （症状伪装成「all providers unavailable」）。修法 = 宽限窗 `_STDIN_KEY_PROBE_S`。

    判据（红先）：HEAD 的零等待实现下本臂**必红**（子进程先到探测点，0.4s 后才写）。
    仍走「AST 抽 helper + 干净子进程」—— 绕过 SDK import 消费 fd0 的既有环境限制。
    """

    def test_key_written_after_probe_point_is_not_lost(self):
        import ast as _ast
        src = (Path(__file__).parent / "subagent_runner.py").read_text(encoding="utf-8")
        tree = _ast.parse(src)
        fn_src, consts = None, {}
        for node in tree.body:
            if isinstance(node, _ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, _ast.Name) and tgt.id.startswith("_STDIN_KEY"):
                        try:
                            consts[tgt.id] = _ast.literal_eval(node.value)
                        except Exception:  # noqa: BLE001 — 非字面量常量就跳过
                            pass
        for node in _ast.walk(tree):
            if isinstance(node, _ast.FunctionDef) and node.name == "_read_stdin_key_safely":
                fn_src = _ast.get_source_segment(src, node)
                break
        assert fn_src and "_STDIN_KEY_PROBE_S" in consts, \
            "helper / 宽限窗常量缺失（零等待修复未落刀）"
        prelude = ("import os, sys, threading, time\n"
                   + "".join("%s = %r\n" % (k, v) for k, v in consts.items()))
        script = (prelude + fn_src + "\n"
                  "v = _read_stdin_key_safely(timeout=2.0)\n"
                  "print('KEY=%r' % (v,))\n")
        p = subprocess.Popen([sys.executable, "-c", script],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(0.4)          # 让子进程先跑到探测点（纯 helper 脚本 import 极快）
            p.stdin.write("sk-late-key\n")
            p.stdin.flush()
            p.stdin.close()
            p.stdin = None   # 已手动关：否则 communicate() 会再 flush 已关文件而抛 ValueError
            out, err = p.communicate(timeout=30)
        finally:
            if p.poll() is None:
                p.kill()
        assert "KEY='sk-late-key'" in out, (
            "慢 writer 的 key 被丢弃（零等待探测未加宽限窗）\nstdout: %s\nstderr: %s"
            % (out[:300], err[:300]))


class TestNoUnboundedRead:
    """③ 长度上限：对端灌超长垃圾 → 不无界吃内存（防 OOM 炸系统）。"""

    def test_huge_stdin_line_is_capped(self):
        """灌 100MB 单行（无换行）⟹ runner 不 OOM、不永久读，仍在超时内退出。"""
        import threading

        rc_box = {}

        def _pump():
            """往管道写有上限的无换行垃圾后关写端（模拟恶意/失控对端）。

            ⚠️ 必须有写入上限：子进程读侧若不消费，管道写端会一直阻塞在 os.write，
            本线程会挂死。写 8MB 足以触发「无长度上限 ⟹ OOM/无界读」的判定，
            又不至于把测试进程自己撑爆（早期版本死循环写 1MB 直接 MemoryError）。
            """
            pr, pw = os.pipe()
            rc_box["pr"], rc_box["pw"] = pr, pw
            rc_box["ready"] = True
            try:
                chunk = b"A" * (1 << 20)  # 1MB
                for _ in range(8):  # 有界：8MB 后停手
                    try:
                        os.write(pw, chunk)
                    except (BrokenPipeError, OSError):
                        break  # 对端已关读侧
            finally:
                try:
                    os.close(pw)
                except OSError:
                    pass

        env = dict(os.environ)
        env.setdefault(_STDIN_TIMEOUT_ENV, "2.0")
        # 预热线程与管道
        t = threading.Thread(target=_pump, daemon=True)
        t.start()
        while "ready" not in rc_box:
            time.sleep(0.01)

        t0 = time.monotonic()
        try:
            r = subprocess.run(
                [sys.executable, str(_RUNNER), *_BASE_ARGS],
                stdin=rc_box["pr"], capture_output=True, text=True,
                timeout=40, env=env,
            )
            rc, out = r.returncode, r.stdout
        finally:
            try:
                os.close(rc_box["pr"])
            except OSError:
                pass
        dt = time.monotonic() - t0

        # 不 OOM 崩溃（rc 不是 -11/-9 这类信号），且不在无界读上挂死。
        assert rc in (0, 1, 2), f"超长 stdin 下 runner 异常退出 rc={rc}（疑似 OOM/崩溃）"
        assert dt < 30.0, f"超长 stdin 耗时 {dt:.1f}s ⟹ 无长度上限，无界吃内存"


def test_spawned_child_gets_eof_when_stdin_unset():
    """未显式 stdin 的子进程必须立刻读到 EOF（2026-11-08，conftest 缺省 DEVNULL 的回归臂）。

    背景：xdist worker 的 stdin 是「已打开但对端永不写入」的管道 ⟹ 子进程 readline 无界阻塞
    ⟹ 全量在 95% 后「永不结束」。本臂用 10s 超时兜住：修复前是超时红，修复后 0 秒过。
    """
    import subprocess
    import sys

    p = subprocess.run(
        [sys.executable, "-c", "import sys; sys.stdin.readline(); print('eof-ok')"],
        capture_output=True, text=True, timeout=10)
    assert p.returncode == 0, f"子进程异常：{p.stderr}"
    assert "eof-ok" in p.stdout, f"未读到 EOF（stdin 仍被继承的悬空管道占住）：{p.stdout!r}"
