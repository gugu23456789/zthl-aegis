"""R19 红先集：副本 .keys 继承（软链单源）+ .gitignore 模式订正（`.keys/` → `.keys`）。

病象（§4.7.0 实测）：`git worktree add` **不带未跟踪文件** ⟹ 副本无 `.keys/` ⟹
`context --update` 可重建 ctx 但 `{"ok":false,"error":"context sign failed"}` ⟹
`CONTEXT_STALE_OR_UNSIGNED` 恒拦 ⟹ L3113 自愈门与失败态同源（**结构性失效**）。

四臂（修前实测 3 failed / 1 passed —— 臂1/2/4 红、唯一绿 = 对照臂3）：
  1. worktree_keys_inherit        —— 红先：副本无 .keys ⟹ CLI 自动继承（软链）+ 指纹与主副本一致
  2. keys_gitignore_symlink       —— 红先：建软链后 `git check-ignore .keys` rc=0（修前 rc=1）
  3. keys_no_clobber（对照）      —— 已有 .keys 实目录时**不覆盖**（修前修后皆绿）
  4. keys_absent_source           —— 红先：无源且无 .keys ⟹ **显式失败**（修前为 rc=0 假绿
                                     `{"ok":true,"fingerprints":{}}` ⟹ 独立真缺陷，非对照）

纪律：不触碰真实 key / 真实 state（临时 worktree 建在 tmp，STATE_FILE 一律不注入）。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# 被测仓根：默认 = 本文件所在技能仓；`R19_REPO` 可覆盖为**修前树**（红先对照用）。
REPO = Path(os.environ.get("R19_REPO") or Path(__file__).resolve().parent.parent)
CLI = "gatekeeper-cli.sh"


def _run(args: list[str], cwd: Path, cli_dir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("STATE_FILE", None)  # 不注入：避免误写真实域 state
    # `GK_BUDGET_OVERRIDE=1`（`ECC-1F6514B84334`，2026-09-26 实测）：本文件验的是 **.keys 继承**
    # （键面），不是用户编辑 ⟹ 与生产面 `gk_agent_edit._cli_gate_ok` 同一口径。修前
    # `_run([...], REPO, REPO)`（主副本那一次）的 `audit`（写类子命令）扣**真** state 的
    # 主 agent 额度 1 次/验收轮；副本内那次因副本**无 state** 而不计（`_bill_edit` 早退）。
    env["GK_BUDGET_OVERRIDE"] = "1"
    return subprocess.run(
        ["bash", str(cli_dir / CLI), *args],
        cwd=str(cwd), env=env, capture_output=True, text=True, timeout=180,
    )


@pytest.fixture()
def copy_worktree():
    """建一个**无 .keys** 的技能仓 linked worktree（tmp 下）。"""
    wt = Path(tempfile.mkdtemp(prefix="r19wt-")) / "skill"
    subprocess.run(
        ["git", "-C", str(REPO), "worktree", "add", "--detach", str(wt), "HEAD"],
        capture_output=True, text=True, check=True, timeout=120,
    )
    assert not (wt / ".keys").exists(), "前提失败：worktree 不应带 .keys（未跟踪文件不被检出）"
    yield wt
    subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(wt)],
                   capture_output=True, text=True, timeout=120)
    shutil.rmtree(wt.parent, ignore_errors=True)


def test_worktree_keys_inherit(copy_worktree: Path):
    """臂1（红先）：副本无 .keys ⟹ CLI 自动继承主副本 keys，且指纹一致。"""
    wt = copy_worktree

    # **触发**：在副本内跑任意 CLI 命令（R19 前置位于「SKILL_DIR 确定后、命令派发前」）——
    # 修前该前置不存在 ⟹ 无任何动作 ⟹ 下述断言全红。
    r0 = _run(["audit", "--key", "fingerprint"], wt, wt)

    assert (wt / ".keys").exists(), (
        f"副本 .keys 未被继承（软链缺失）；CLI rc={r0.returncode} out={r0.stdout[:160]}")
    assert (wt / ".keys").is_symlink(), "继承须为**软链单源**，不得是复制体"

    # 指纹须与主副本一致（证明确实指到同一套私钥）
    r_main = _run(["audit", "--key", "fingerprint"], REPO, REPO)
    r_wt = _run(["audit", "--key", "fingerprint"], wt, wt)
    assert r_main.returncode == 0, f"主副本 fingerprint 失败：{r_main.stderr[:200]}"
    assert r_wt.returncode == 0, f"副本 fingerprint 失败（签名不可用）：{r_wt.stderr[:200]}"
    fp_main = json.loads(r_main.stdout)["fingerprints"]
    fp_wt = json.loads(r_wt.stdout)["fingerprints"]
    assert fp_wt == fp_main, f"副本指纹与主副本不一致：{fp_wt} vs {fp_main}"

    # 端到端：副本私钥须**可签**、且用副本公钥**可验** —— 病象正是
    #   `{"ok":false,"error":"context sign failed"}`。原语与 `_ctx_inject_probe` 同源
    #   （`openssl pkeyutl -sign/-verify -rawin`，说明：1 个 -sigfile）。
    #   载荷落在 tmp、私钥**只读**（`.keys` 是软链 ⟹ 严禁向其内写临时文件）。
    tmp = Path(tempfile.mkdtemp(prefix="r19sig-"))
    msg, sig = tmp / "probe.msg", tmp / "probe.sig"
    kd = wt / ".keys"
    msg.write_bytes(b"r19-sign-probe")
    try:
        s = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(kd / "context_ed25519.pem"),
             "-rawin", "-in", str(msg), "-out", str(sig)],
            capture_output=True, text=True, timeout=60)
        assert s.returncode == 0, f"副本私钥不可签（{s.stderr[:200]}）"
        v = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(kd / "context_ed25519.pub"),
             "-rawin", "-in", str(msg), "-sigfile", str(sig)],
            capture_output=True, text=True, timeout=60)
        assert "Verified" in (v.stdout + v.stderr), f"副本签名不可验：{v.stdout} {v.stderr}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_keys_gitignore_symlink(copy_worktree: Path):
    """臂2（红先）：软链形态的 .keys 必须被忽略（`.keys/` 尾斜杠模式不匹配软链）。"""
    wt = copy_worktree
    if not (wt / ".keys").exists():  # 依赖臂1 的继承；独立跑时自建软链以验 ignore 规则本身
        (wt / ".keys").symlink_to(REPO / ".keys")
    r = subprocess.run(["git", "-C", str(wt), "check-ignore", ".keys"],
                       capture_output=True, text=True)
    # 修前（`.keys/`）：rc=1（未忽略）⟹ 软链处于可被 git add 拾取的状态
    assert r.returncode == 0, (
        f"`.keys` 软链未被忽略（check-ignore rc={r.returncode}）——"
        f".gitignore 模式须由 `.keys/` 订正为 `.keys`")


def test_keys_no_clobber(copy_worktree: Path):
    """臂3（对照，修前也绿）：副本已有 .keys 实目录 ⟹ 不得覆盖/替换。"""
    wt = copy_worktree
    (wt / ".keys").mkdir()
    (wt / ".keys" / "marker").write_text("keep-me", encoding="utf-8")

    _run(["audit", "--key", "fingerprint"], wt, wt)  # 触发继承前置

    assert (wt / ".keys").is_dir() and not (wt / ".keys").is_symlink(), "实目录被替换成软链"
    assert (wt / ".keys" / "marker").read_text(encoding="utf-8") == "keep-me", "实目录内容被污染"


def test_keys_absent_source_fail_loud():
    """臂4（红先）：无源且无 .keys ⟹ **显式失败**，不得静默假绿。

    构造：`git archive HEAD` 出洁净树（**不含未跟踪的 .keys**、也无 .git ⟹ 派生不出源）。
    """
    plain = Path(tempfile.mkdtemp(prefix="r19plain-")) / "skill"
    plain.mkdir(parents=True)
    arc = subprocess.run(["git", "-C", str(REPO), "archive", "HEAD"],
                         capture_output=True, text=True, check=True, timeout=120)
    subprocess.run(["tar", "-x", "-C", str(plain)], input=arc.stdout,
                   text=True, check=True, timeout=120)
    assert not (plain / ".keys").exists(), "前提失败：洁净树不应含 .keys"
    assert not (plain / ".git").exists(), "前提失败：洁净树不应含 .git"

    r = _run(["audit", "--key", "fingerprint"], plain, plain)
    # 收紧（ECC-533FBB592F9C / L2 交叉审查提出）：原断言 `not (rc==0 and ok:true)` 过弱 ——
    #   非 JSON 崩溃 / 异常退出 / 空输出**同样满足**，即「显式失败 + JSON-only 契约」未被钉住。
    #   改为钉**报文面**：末行须可解析为 JSON 对象、且 ok is False、且带显式错误键。
    try:
        payload = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception as exc:
        pytest.fail(f"无 keys 时输出非 JSON（违 JSON-only 契约）：rc={r.returncode} "
                    f"out={r.stdout[:200]!r} err={r.stderr[:200]!r}（{exc}）")
    assert isinstance(payload, dict), f"失败报文体非 JSON 对象：{payload!r}"
    assert payload.get("ok") is False, f"无 keys 时未显式失败（假绿）：{payload!r}"
    assert payload.get("error"), f"失败报文缺显式错误键（真因不可达）：{payload!r}"

    shutil.rmtree(plain.parent, ignore_errors=True)


# ── f7（ECC-4039AC65A825，2026-09-22）：R19 三条**覆盖缺口**补臂 ──────────────────────
# L2 交叉审查指出：R19 前置有 3 条分支从未被任何臂覆盖 ——
#   ① 关闸 `GK_KEYS_INHERIT=0`（外层 if 的第一个合取项）
#   ② 源存在但源无 `.keys`（`[ -d "$_mwt/.keys" ] || return 1`）
#   ③ `SKILL_DIR` 自身即主工作树（`[ "$_mwt" != "$SKILL_DIR" ] || return 1`）
# ①②③ 都属「**不动作**」语义：不建链、不报假失败、下游仍 fail-loud。缺臂 ⟹ 任一条被改坏
# （例如误改成"随手建个自指软链"或"静默复制")都不会有测试变红。

_R19_BEGIN = "# ─── R19（2026-09-22）：副本 `.keys` 继承"
_R19_END = "# 默认 state 落点"


def _r19_block() -> str:
    """从被测 CLI 抽取 R19 前置**整段**（源抽取 ⟹ 与真实现同源，抽取标记失效即 FAIL）。"""
    src = (REPO / CLI).read_text(encoding="utf-8")
    a, b = src.find(_R19_BEGIN), src.find(_R19_END)
    assert a != -1 and b != -1 and b > a, "R19 段抽取标记缺失（代码已搬走/改名？本臂失效）"
    return src[a:b]


def test_r19_source_has_three_gates():
    """钉子：三条闸必须在源里**逐条**存在（防臂6/7 静默失去覆盖对象）。

    2026-10-27 订正：③ 由**逐字比较**改为 `realpath` 归一比较（成因 = Windows/WSL 路径形态
    不同时守卫失效 ⟹ `ln -s 自身/.keys 自身/.keys` 造出自指软链，见开源前置计划 §5.2 U12）；
    同时新增「link 落点双保险」。钉子随之改为断言新形态。
    """
    blk = _r19_block()
    assert '"${GK_KEYS_INHERIT:-1}" != "0"' in blk, "关闸（①）不在源里"
    assert 'realpath "$_mwt"' in blk and 'realpath "$SKILL_DIR"' in blk, \
        "「自身即主工作树」（③）未走 realpath 归一"
    assert '[ -d "$_mwt/.keys" ] || return 1' in blk, "「源无 .keys」（②）不在源里"
    assert '[ -e "$SKILL_DIR/.keys" ] || [ -L "$SKILL_DIR/.keys" ]' in blk, \
        "link 落点双保险不在源里"


@pytest.fixture()
def no_keys_origin():
    """**无 `.keys`** 的临时 git 仓（主工作树 `main`）+ 其 linked worktree `wt`。

    为 ②③ 两支而建：`wt` 满足「SKILL_DIR ≠ 主工作树且源无 `.keys`」（②），
    `main` 满足「SKILL_DIR 即主工作树」（③）。两者都**不得**产生任何 `.keys`。
    """
    root = Path(tempfile.mkdtemp(prefix="r19nokeys-"))
    main, wt = root / "main", root / "wt"
    main.mkdir()
    ident = ["-c", "user.email=t@example.invalid", "-c", "user.name=r19arm",
             "-c", "commit.gpgsign=false"]
    subprocess.run(["git", *ident, "-C", str(main), "init", "-q"],
                   capture_output=True, text=True, check=True, timeout=120)
    subprocess.run(["git", *ident, "-C", str(main), "commit", "-q", "--allow-empty", "-m", "init"],
                   capture_output=True, text=True, check=True, timeout=120)
    subprocess.run(["git", "-C", str(main), "worktree", "add", "--detach", str(wt), "HEAD"],
                   capture_output=True, text=True, check=True, timeout=120)
    assert not (main / ".keys").exists(), "前提失败：临时主仓不应有 .keys"
    assert not (wt / ".keys").exists(), "前提失败：linked worktree 不应有 .keys"
    yield main, wt
    subprocess.run(["git", "-C", str(main), "worktree", "remove", "--force", str(wt)],
                   capture_output=True, text=True, timeout=120)
    shutil.rmtree(root, ignore_errors=True)


def _r19_harness(skill_dir: Path, tmp_path: Path) -> str:
    """在**隔离 bash** 里跑抽取出的 R19 段（SKILL_DIR 注入），返回观测串。

    只观测契约面：是否**建了** `.keys` + 是否置了失败真因 env（`GK_R19_KEYS_INHERIT_FAILED`）。
    """
    script = ("set -uo pipefail\n"
              f'SKILL_DIR="{skill_dir}"\n'
              f'GK_DBG_LOG="{tmp_path}/r19_dbg.log"\n'
              + _r19_block()
              + '\nif [ -e "$SKILL_DIR/.keys" ]; then echo "KEYS_PRESENT"; else echo "KEYS_ABSENT"; fi\n'
              + 'echo "FAILENV=${GK_R19_KEYS_INHERIT_FAILED:-}"\n')
    p = tmp_path / "r19_harness.sh"
    p.write_text(script, encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", str(p)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"harness 非零退出（{r.returncode}）：{r.stdout}{r.stderr}"
    return r.stdout


def test_r19_off_switch_no_inherit(copy_worktree: Path):
    """臂5（**缺口①**）：副本无 `.keys` + `GK_KEYS_INHERIT=0` ⟹ 前置**整体跳过**（不建链），
    且下游签名面**仍 fail-loud**（关闸 ≠ 假绿）。

    ⚠ 本条是真 CLI 端到端（副本内跑），非源抽取：关闸在最外层合取项，须由真实进程证。
    """
    wt = copy_worktree
    env = dict(os.environ)
    env.pop("STATE_FILE", None)
    env["GK_KEYS_INHERIT"] = "0"
    r = subprocess.run(["bash", str(wt / CLI), "audit", "--key", "fingerprint"],
                       cwd=str(wt), env=env, capture_output=True, text=True, timeout=180)
    assert not (wt / ".keys").exists(), (
        f"关闸失效：GK_KEYS_INHERIT=0 仍建了 .keys（rc={r.returncode}）")
    assert not (wt / ".keys").is_symlink()
    try:
        payload = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception as exc:
        pytest.fail(f"关闸后输出非 JSON（违 JSON-only 契约）：rc={r.returncode} "
                    f"out={r.stdout[:200]!r} err={r.stderr[:200]!r}（{exc}）")
    assert payload.get("ok") is False and payload.get("error"), (
        f"关闸后仍无 keys 却未显式失败（假绿）：{payload!r}")


def test_r19_source_without_keys_is_noop(no_keys_origin, tmp_path):
    """臂6（**缺口②**）：源（主工作树）无 `.keys` ⟹ 不动作（不建链、不报假失败）。"""
    main, wt = no_keys_origin
    out = _r19_harness(wt, tmp_path)
    assert "KEYS_ABSENT" in out, f"源无 .keys 却产生了 .keys（②闸失效）：{out}"
    tail = [l for l in out.replace("\r", "").splitlines() if l.strip()]
    assert tail[-1] == "FAILENV=", (
        f"② 只是「不继承」，不应置失败真因 env（只有建链失败才置）：{out}")
    assert not (wt / ".keys").exists() and not (wt / ".keys").is_symlink()


def test_r19_self_is_main_worktree_is_noop(no_keys_origin, tmp_path):
    """臂7（**缺口③**）：`SKILL_DIR` 自身即主工作树 ⟹ 不动作（**不得**建自指软链）。"""
    main, _ = no_keys_origin
    out = _r19_harness(main, tmp_path)
    assert "KEYS_ABSENT" in out, f"自身即主工作树却建了 .keys（③闸失效 / 自指软链）：{out}"
    assert not (main / ".keys").exists() and not (main / ".keys").is_symlink(), (
        "出现自指软链（.keys → .keys）")

