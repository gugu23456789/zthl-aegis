#!/usr/bin/env python3
"""提交面单一入口回归（**陈旧锁 + 撕裂读**两条流程缺陷，2026-09-25）。

事故/病根（均实测，非推断）：
  ① **撕裂读进历史**：code commit `65974a8` 落了一枚损坏 blob（`gatekeeper-cli.sh` 2968-2977
     两段粘连、`bash -n` 直接 syntax error），而 `git status`/`git diff`/`git diff-files`
     **全报 clean**（索引 stat 缓存命中 ⟹ 不重算 hash）⟹ 唯 `git archive HEAD` 型测试才暴露
     （`ECC-E5364D7993C8`）。旧 `cmd_commit` 仅 `git commit -F`，**无 add / 无校验** ⟹ 谁 add、
     add 什么、提交前校准全靠 agent 自觉（`git add -A` 还会夹带并发会话文件）。
  ② **孤儿锁**：git 正常退出会删 `.git/index.lock`；进程被**杀**（工具宿主复用终端 / 超时 /
     会话中断）+ **多会话同仓** ⟹ 0 字节孤儿锁留存 ⟹ 后续提交恒失败（当日两次实测）。

本刀 = 把 `cmd_commit` 变**单一入口**，按序消除：锁预检（孤儿 ⟹ `mv` 归档**非删除**；
活锁 ⟹ fail-loud **不抢**）→ `git update-index --really-refresh`（破缓存致盲）→ 只 add
**显式路径** → `gk_commit_verify --mode staged`（blob ↔ 工作树**逐字节** + 解析面；坏 ⟹ 不提交）
→ 提交 → `--mode rev HEAD` 复核（兜住"校验后又被撕裂"的窗口）。

本文件在**沙箱真 CLI** 上锁四条判据（非模块自证）：
  arm34  坏语法文件被**拦截**（HEAD 会照提 ⟹ 真红）；
  arm35  `--verify-only` 抓「索引 blob ≠ 工作树」（撕裂读的机械判据）；
  arm36  孤儿锁归档 + 提交成功 / 新鲜锁 fail-loud **不抢**；
  arm37  legacy 纯消息提交**零回归**（非红臂，红先 `-k` 不含它）。
"""
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`bash` 此处是 WSL bash；WSL 原生路径原样透传）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _sh(cmd: str, timeout: int = 180):
    return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=timeout)


def _mk_skillroot(tmp_path: Path) -> Path:
    """沙箱技能根：`scripts` 软链 + CLI 实拷 + 最小 state（standing）。"""
    sb = (tmp_path / "skill").resolve()
    sb.mkdir()
    r = _sh('ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
            % (_wsl(SCRIPT_DIR), _wsl(sb), _wsl(CLI_SRC), _wsl(sb)))
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(
        '{"stage":"STAGE_0","r_phase":"R1","worktree":"",'
        '"gate_data":{"project_type":"standing","ecc_findings":[]}}',
        encoding="utf-8", newline="\n")
    return sb


def _mk_repo(tmp_path: Path, name: str = "repo") -> Path:
    """造一个最小真 git 仓（含一枚合法 `good.sh` 首提交）。"""
    rp = (tmp_path / name).resolve()
    rp.mkdir()
    r = _sh('cd "%s" && git init -q && git config user.email t@t '
            '&& git config user.name t && git config commit.gpgsign false '
            '&& printf "echo ok\\n" > good.sh && git add good.sh && git commit -q -m init'
            % _wsl(rp))
    assert r.returncode == 0, f"git 仓搭建失败：{r.stdout}{r.stderr}"
    return rp


def _cli(sb: Path, args: str, timeout: int = 300):
    return _sh('cd "%s" && bash gatekeeper-cli.sh %s' % (_wsl(sb), args), timeout=timeout)


def _last_json(out: str) -> dict:
    import json
    lines = [ln for ln in out.strip().splitlines() if ln.startswith("{")]
    assert lines, f"未回 JSON：{out[:500]}"
    return json.loads(lines[-1])


def _head(rp: Path) -> str:
    return _sh('git -C "%s" rev-parse HEAD' % _wsl(rp)).stdout.strip()


def _hash_blob(rp: Path, data: bytes) -> str:
    r = subprocess.run(["git", "-C", str(rp), "hash-object", "-w", "--stdin"],
                       input=data, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.decode().strip()


def _trash_dir(sb: Path) -> Path:
    """回收落点**单源**（禁第二份路径推算）—— 直接问 `gk_route_center`。"""
    sys.path.insert(0, str(SCRIPT_DIR))
    import gk_route_center as grc
    return Path(grc.trash_dir(str(sb)))


def test_arm34_commit_blocks_syntactically_broken_staged_file(tmp_path):
    """判据㉔（红先 · 拦截）：坏语法 `bad.sh` 已暂存 ⟹ `commit` 须**拒绝提交**（损坏不进历史）。

    修前：旧 `cmd_commit` 只 `git commit -F` ⟹ 照提坏文件、HEAD 前进（真红）。
    修后：流程步 ④（`--mode staged` 解析面）判 `PARSE_FAIL` ⟹ `COMMIT_VERIFY_FAILED` + 不提交。
    """
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    (rp / "bad.sh").write_text("if [ 1 = 1 ]; then\n  echo hi\n", encoding="utf-8")  # 缺 fi
    a = _sh('git -C "%s" add bad.sh' % _wsl(rp))
    assert a.returncode == 0, a.stderr
    head_before = _head(rp)

    r = _cli(sb, 'commit --repo "%s" -m "arm34"' % _wsl(rp))
    out = r.stdout + r.stderr
    d = _last_json(out)
    assert d.get("ok") is False, f"坏语法文件未被拦截（损坏已进历史）：{out[:700]}"
    assert "COMMIT_VERIFY_FAILED" in (d.get("error") or ""), d
    assert _head(rp) == head_before, "HEAD 前进了 ⟹ 损坏进了历史（未真正阻止提交）"


def test_arm35_verify_only_catches_blob_worktree_divergence(tmp_path):
    """判据㉕（红先 · 机械入口）：`--verify-only` 须抓出「索引 blob ≠ 工作树」（撕裂读形态）。

    造法：把一枚**与工作树不同**的 blob 经 `git update-index --cacheinfo` 塞进索引
    （复刻事故：`add` 那次读取撕裂、对象库坏了而工作树好）。修前无 `--verify-only` ⟹ 真红。
    """
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    torn = _hash_blob(rp, b"echo torn\n# concatenated garbage\n")
    p = _sh('git -C "%s" update-index --cacheinfo 100644,%s,good.sh' % (_wsl(rp), torn))
    assert p.returncode == 0, p.stderr

    r = _cli(sb, 'commit --repo "%s" --verify-only' % _wsl(rp))
    out = r.stdout + r.stderr
    d = _last_json(out)
    assert d.get("ok") is False, f"blob≠工作树 未被 --verify-only 抓住：{out[:700]}"
    bad = d.get("bad") or []
    assert any(b.get("path") == "good.sh" for b in bad), f"坏项未点名 good.sh：{d}"
    assert any("BLOB_MISMATCH" in (b.get("reason") or "") for b in bad), f"未判 BLOB_MISMATCH：{d}"


def test_arm36_stale_lock_archived_fresh_lock_not_stolen(tmp_path):
    """判据㉖（红先 · 孤儿锁）：① 新鲜锁 ⟹ fail-loud **不抢**；② 陈旧锁 ⟹ 归档（非删除）后提交成功。

    修前：旧 `cmd_commit` 无锁预检 ⟹ 两种情形都直接 `git commit` 失败（真红），且锁永不清理。
    """
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    (rp / "good.sh").write_text("echo ok2\n", encoding="utf-8")
    lock = rp / ".git" / "index.lock"

    # ① 新鲜锁（年龄 < GK_COMMIT_LOCK_GRACE）⟹ 可能真在跑 ⟹ fail-loud 不抢
    lock.write_text("", encoding="utf-8")
    r1 = _cli(sb, 'commit --repo "%s" --add good.sh -m "arm36a"' % _wsl(rp))
    out1 = r1.stdout + r1.stderr
    d1 = _last_json(out1)
    assert d1.get("ok") is False, f"新鲜锁应 fail-loud：{out1[:700]}"
    assert "COMMIT_LOCK_HELD" in (d1.get("error") or ""), d1
    assert lock.exists(), "新鲜锁被抢（违反「活锁不抢」—— 会与真在跑的 git 相撞）"

    # ② 陈旧锁（抹旧 mtime）⟹ 孤儿 ⟹ `mv` 归档到回收区（**非删除**）后提交成功
    t = _sh('touch -d "2020-01-01" "%s"' % _wsl(lock))
    assert t.returncode == 0, t.stderr
    tr = _trash_dir(sb)
    before = set(tr.glob("index.lock.stale-*")) if tr.is_dir() else set()

    r2 = _cli(sb, 'commit --repo "%s" --add good.sh -m "arm36b"' % _wsl(rp))
    out2 = r2.stdout + r2.stderr
    d2 = _last_json(out2)
    assert d2.get("ok") is True, f"陈旧锁未归档致提交失败：{out2[:700]}"
    assert not lock.exists(), "陈旧锁仍在工作区 ⟹ 未归档"
    after = set(tr.glob("index.lock.stale-*")) if tr.is_dir() else set()
    new = after - before
    assert new, f"陈旧锁被**删除**而非归档到 {tr}（须可回溯，禁删除）"


def test_arm37_legacy_message_only_commit_still_works(tmp_path):
    """判据㉗（**非红臂** · 零回归）：`commit --repo <r> --add <p> -m <msg>` 仍能正常提交（绿）。"""
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    (rp / "good.sh").write_text("echo ok3\n", encoding="utf-8")
    head_before = _head(rp)

    r = _cli(sb, 'commit --repo "%s" --add good.sh -m "legacy"' % _wsl(rp))
    out = r.stdout + r.stderr
    d = _last_json(out)
    assert d.get("ok") is True, f"纯消息提交回归：{out[:700]}"
    assert _head(rp) != head_before, "提交成功但 HEAD 未前进（异常）"
    assert d.get("verified", 0) >= 1, f"提交面校验未跑（verified 缺/零）：{d}"


def _proc_cmdline(pid: int) -> str:
    try:
        return Path("/proc/%d/cmdline" % pid).read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def test_arm38_live_git_process_blocks_stale_lock_reclaim(tmp_path):
    """判据㉘（红先 · 活锁）：锁**陈旧**（mtime 抹旧）但确有 **git 进程在跑**（cwd/cmdline 指向本仓）
    ⟹ 须 fail-loud `COMMIT_LOCK_HELD` 且**不抢**（一旦归档活锁 = 与真在跑的 git 相撞 ⟹ 损坏）。

    造法：起一个真在跑的 git（`git -C <rp> hash-object -w --stdin` 读 stdin 阻塞，comm=git、
    cmdline 含仓路径），再把锁 mtime 抹旧。修前无预检 ⟹ 真红。
    """
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    (rp / "good.sh").write_text("echo ok4\n", encoding="utf-8")
    lock = rp / ".git" / "index.lock"
    lock.write_text("", encoding="utf-8")
    _sh('touch -d "2020-01-01" "%s"' % _wsl(lock))

    live = subprocess.Popen(["git", "-C", str(rp), "hash-object", "-w", "--stdin"],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        assert live.poll() is None, "测试前提失败：git 进程未保持存活"
        cl = _proc_cmdline(live.pid)
        assert "git" in cl and str(rp) in cl, f"测试前提失败：活 git cmdline 未含 token：{cl!r}"

        tr = _trash_dir(sb)
        before = set(tr.glob("index.lock.stale-*")) if tr.is_dir() else set()
        r = _cli(sb, 'commit --repo "%s" --add good.sh -m "arm38"' % _wsl(rp))
        out = r.stdout + r.stderr
        d = _last_json(out)
        assert d.get("ok") is False and "COMMIT_LOCK_HELD" in (d.get("error") or ""), \
            f"活锁（git 在跑）应 fail-loud 不抢：{out[:700]}"
        assert lock.exists(), "活锁被抢（陈旧但 git 正在跑 —— 归档它会与真 git 相撞）"
        after = set(tr.glob("index.lock.stale-*")) if tr.is_dir() else set()
        assert not (after - before), "活锁被归档（应保持不动）"
    finally:
        try:
            live.stdin.close()
        except Exception:
            pass
        live.terminate()
        try:
            live.wait(timeout=10)
        except Exception:
            live.kill()


def test_arm39_non_git_wrapper_does_not_block_reclaim(tmp_path):
    """判据㉙（红先 · **防子串假阳性**）：一名为 `bash`（非 git）的进程，其 cmdline 同时含
    `git` 字样与本仓路径 ⟹ **不得**被误判成活锁（孤儿锁仍须归档、提交仍须成功）。

    守卫的是 `pgrep -af git`（按 cmdline 子串）这一错法的回归 —— 实测诊断行会自我命中。
    诱饵 argv = `["bash","-c","while :; do sleep 300; done","git",<rp>]`（用循环防 bash exec 优化
    掉自身，确保 cmdline 保住两 token；测试内自校验该前提）。
    """
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    (rp / "good.sh").write_text("echo ok5\n", encoding="utf-8")
    lock = rp / ".git" / "index.lock"
    lock.write_text("", encoding="utf-8")
    _sh('touch -d "2020-01-01" "%s"' % _wsl(lock))

    decoy = subprocess.Popen(["bash", "-c", "while :; do sleep 300; done", "git", str(rp)])
    try:
        time.sleep(0.3)
        assert decoy.poll() is None, "测试前提失败：诱饵进程未保持存活"
        cl = _proc_cmdline(decoy.pid)
        assert "git" in cl and str(rp) in cl, f"测试前提失败：诱饵 cmdline 未含两 token：{cl!r}"

        r = _cli(sb, 'commit --repo "%s" --add good.sh -m "arm39"' % _wsl(rp))
        out = r.stdout + r.stderr
        d = _last_json(out)
        assert d.get("ok") is True, f"非 git 包装器被误判成活锁（cmdline 子串假阳性）：{out[:700]}"
        assert not lock.exists(), "孤儿锁未归档（被假阳性拦下）"
    finally:
        decoy.terminate()
        try:
            decoy.wait(timeout=10)
        except Exception:
            decoy.kill()
