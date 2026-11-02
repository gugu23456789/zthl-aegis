"""红先：context 签名竞态（写者非原子 × 读者撞窗口 × 6 臂各自自愈）

病根（2026-10-30 实测复现）：
  `context --update` 用 `json.dump(open(ctx,'w'))` **就地截断重写**，签名字节随后另写一次，
  整段无锁；`_ctx_inject_probe` 无锁直读 ⟹ 6 臂并发时撞进「JSON 已换、.sig 仍旧」窗口，
  全部判 sig_invalid → 6 臂各自再跑 `context --update` 互相覆盖（日志 10-07/10-09/10-29
  三次 6 连爆，见 `gk_dbg.log` 的 `[ctx-inject] self-heal`）。

本文件钉住四件事（当前代码全红）：
  A. 读者 `_ctx_inject_probe` 取**共享锁**（`flock -s`）；
  B. 写者 `context --update` 取**独占锁**覆盖「重建 + 重签 + 发布」；
  C. 自愈**单飞**（`flock -n` on `${ctx_file}.heal`），等待臂不再重复 update；
  D. 构建器**原子落盘**（`os.replace`，读者永不看到半截 JSON）。
"""

import json
import os
import subprocess
import sys
import threading

SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(SKILL, "gatekeeper-cli.sh")
BUILD = os.path.join(SKILL, "scripts", "gk_context_build.py")


def _txt(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _slice(text, start, end="\n}\n"):
    i = text.find(start)
    assert i >= 0, "锚点缺失: %s" % start
    j = text.find(end, i)
    return text[i:j if j > 0 else len(text)]


def test_reader_probe_takes_shared_lock():
    body = _slice(_txt(CLI), "_ctx_inject_probe() {")
    assert "flock -s" in body, "读者侧无共享锁 ⟹ 会撞进写者窗口"


def test_writer_update_takes_exclusive_lock():
    """写者必须独占取锁。两条等价形态：就地 flock，或经可重入助手 `_ctx_lock_acquire`
    （后者是本仓现形态：同进程二次取锁会自死锁，故取锁收敛为单点）。"""
    text = _txt(CLI)
    i = text.find('scripts/gk_context_build.py" build')
    assert i > 0
    seg = text[max(0, i - 1500):i]
    inline = ".lock" in seg and "flock" in seg
    helper = _slice(text, "_ctx_lock_acquire() {")
    via_helper = (
        '_ctx_lock_acquire "$ctx_file"' in seg
        and "flock -w" in helper
        and 'exec {_fd}>"${_f}.lock"' in helper
        and "flock -s" not in helper
    )
    assert inline or via_helper, "写者侧无独占锁（既未就地 flock，也未走 _ctx_lock_acquire 单点）"


def test_sig_publish_is_atomic():
    text = _txt(CLI)
    assert '.sig.tmp' in text, "签名未走 tmp+mv（写一半被读到 = 伪 invalid）"


def test_selfheal_is_single_flight():
    body = _slice(_txt(CLI), "local _probe; _probe=$(_ctx_inject_probe", end="\n    if [ \"$_probe\" = \"ok\" ]")
    assert ".heal" in body and "flock -n" in body, "6 臂并发各自 update = 互相覆盖"


def test_selfheal_retries_probe_before_healing():
    body = _slice(_txt(CLI), "local _probe; _probe=$(_ctx_inject_probe", end="\n    if [ \"$_probe\" = \"ok\" ]")
    assert "sleep 0.1" in body, "瞬时窗口未退避重探 ⟹ 误触发自愈"


def test_builder_writes_atomically(tmp_path):
    assert "os.replace" in _txt(BUILD), "构建器仍就地重写（非原子）"
    skill = tmp_path / "skill"
    (skill / "scripts").mkdir(parents=True)
    (skill / "scripts" / "subagent_runner.py").write_text("class EccOutput:\n    pass\n", encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text('{"r_phase": "R5"}', encoding="utf-8")
    out = tmp_path / "ctx.json"
    errors = []
    stop = {"v": False}

    def reader():
        while not stop["v"]:
            try:
                if out.exists():
                    json.loads(out.read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    try:
        for _ in range(40):
            r = subprocess.run([sys.executable, BUILD, "build", str(skill), str(state), str(out)],
                               capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stderr
    finally:
        stop["v"] = True
        th.join(timeout=5)
    assert not errors, "读者看到半截 JSON: %r" % (errors[:1],)
    assert not list(tmp_path.glob("ctx.json.tmp*")), "临时文件残留（未 rename 或未清理）"
