"""红队攻击向量：context 签名竞态（攻击者**不守锁**时的 fail-closed 面）

背景：2026-10-30 修掉「写者非原子 + 读者无锁 + 6 臂各自自愈」后，防线变成
「写者独占锁 / 读者共享锁 / 原子发布」。但**锁只约束守规矩的写者**，攻击者可以无视锁直接
改文件。本文件钉住的不是锁，而是**锁被绕过时读者仍必须 fail-closed**：

  AV-1  篡改 JSON 保旧签名        → sig_invalid（不得 ok）
  AV-2  截断 JSON（半写）         → sig_invalid（不得崩、不得 ok）
  AV-3  空 .sig（0 字节）         → sig_invalid
  AV-4  用别的内容的签名顶包      → sig_invalid
  AV-5  删 .sig                   → sig_missing
  AV-6  删 JSON 留 .sig           → ctx_missing_orphan_sig
  AV-7  锁文件不可打开（权限攻击）→ 读者 **fail-open 但仍给正确裁决**（不得挂死）
  AV-8  伪造「正常」配对后再次篡改 → 先 ok 后 sig_invalid（无缓存/无粘滞）

判别方式：直接抽取 CLI 里的 `_ctx_inject_probe` 单点函数在临时 shell 中执行（真实现，非复刻）。
"""

import os
import subprocess
import sys

import pytest

SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(SKILL, "gatekeeper-cli.sh")
KEY_DIR = os.path.join(SKILL, ".keys")
PRIV = os.path.join(KEY_DIR, "context_ed25519.pem")
PUB = os.path.join(KEY_DIR, "context_ed25519.pub")
PY = sys.executable


def _txt(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    """把 CLI 的 `_ctx_inject_probe` 原样抽出来，注入公钥与 RG，返回调用器。"""
    text = _txt(CLI)
    i = text.index("_ctx_inject_probe() {")
    j = text.index("\n}\n", i) + 3
    fn = text[i:j]
    d = tmp_path_factory.mktemp("probe")
    sh = d / "probe.sh"
    sh.write_text(
        "#!/usr/bin/env bash\nset -u\nRG=rg\n_CONTEXT_PUB_KEY='%s'\n%s\n_ctx_inject_probe \"$1\" \"$2\"\n"
        % (PUB, fn), encoding="utf-8")
    sh.chmod(0o755)

    def call(ctx_file, sig_file):
        r = subprocess.run(["bash", str(sh), str(ctx_file), str(sig_file)],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    return call


def _sign(path):
    """用真密钥给 path 签名，返回 `.sig` 的**原始字节**（与 CLI 的 field sig --b64 同管线）。

    ⚠ 两级都是 bytes：
      - 输入 `sign-raw` 输出的是 JSON（"sig" 为 base64），必须 bytes 管道（`text=True` 会在非 UTF-8 处炸）；
      - 输出 `field sig --b64` 是 **64 字节裸签名**（不是文本！）—— 落盘须 `write_bytes`。
    """
    r = subprocess.run([PY, os.path.join(SKILL, "scripts", "gk_crypto_cli.py"),
                        "sign-raw", PRIV, path], capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    r2 = subprocess.run([PY, os.path.join(SKILL, "scripts", "gk_json_utils.py"),
                         "field", "sig", "--b64"], input=r.stdout,
                        capture_output=True, timeout=60)
    assert r2.returncode == 0, r2.stderr.decode("utf-8", "replace")
    assert len(r2.stdout) == 64, "裸签名应为 64 字节，实得 %d" % len(r2.stdout)
    return r2.stdout


@pytest.fixture()
def pair(tmp_path):
    ctx = tmp_path / "subagent-context.json"
    ctx.write_text('{"files": ["a"], "r_phase": "R5"}\n', encoding="utf-8")
    sig = tmp_path / "subagent-context.json.sig"
    sig.write_bytes(_sign(str(ctx)))
    return ctx, sig


def test_av1_tamper_json_keeps_old_sig(probe, pair):
    ctx, sig = pair
    assert probe(ctx, sig) == "ok"
    ctx.write_text('{"files": ["a", "b"], "r_phase": "R5"}\n', encoding="utf-8")
    assert probe(ctx, sig) == "sig_invalid"


def test_av2_truncated_json(probe, pair):
    ctx, sig = pair
    raw = ctx.read_bytes()
    ctx.write_bytes(raw[: len(raw) // 2])
    assert probe(ctx, sig) == "sig_invalid"


def test_av3_empty_sig(probe, pair):
    ctx, sig = pair
    sig.write_bytes(b"")
    assert probe(ctx, sig) == "sig_invalid"


def test_av4_sig_from_other_content(probe, pair, tmp_path):
    ctx, sig = pair
    other = tmp_path / "other.json"
    other.write_text('{"files": [], "r_phase": "IDLE"}\n', encoding="utf-8")
    sig.write_bytes(_sign(str(other)))
    assert probe(ctx, sig) == "sig_invalid"


def test_av5_missing_sig(probe, pair):
    ctx, sig = pair
    sig.unlink()
    assert probe(ctx, sig) == "sig_missing"


def test_av6_orphan_sig(probe, pair):
    ctx, sig = pair
    ctx.unlink()
    assert probe(ctx, sig) == "ctx_missing_orphan_sig"


def test_av7_lock_unopenable_still_verdicts(probe, pair, tmp_path):
    """把锁文件做成不可打开（目录 0555）⟹ 读者 fail-open，但裁决必须依旧正确且不挂死。"""
    ctx, sig = pair
    ctx.chmod(0o444)
    sig.chmod(0o444)
    os.chmod(tmp_path, 0o555)
    try:
        assert probe(ctx, sig) == "ok"
        ctx.chmod(0o644)
        ctx.write_text('{"files": ["z"]}\n', encoding="utf-8")
        ctx.chmod(0o444)
        assert probe(ctx, sig) == "sig_invalid"
    finally:
        os.chmod(tmp_path, 0o755)


def test_av8_no_sticky_ok_after_tamper(probe, pair):
    ctx, sig = pair
    assert probe(ctx, sig) == "ok"
    for _ in range(3):
        ctx.write_text('{"files": ["tampered"]}\n', encoding="utf-8")
        assert probe(ctx, sig) == "sig_invalid"
    # 重新签好后必须回到 ok（无负向粘滞）
    sig.write_bytes(_sign(str(ctx)))
    assert probe(ctx, sig) == "ok"


def test_av9_six_parallel_updates_never_expose_invalid(probe):
    """AV-9（2026-10-30 补，对应历史「同一秒 6 条 self-heal」）：
    6 臂并发 `context --update` 时，观测线程**只允许**看到 ok —— 写者独占锁 + 原子发布
    生效时不会出现「新 JSON + 旧 .sig」窗口；修复前该臂会偶发 sig_invalid。

    ⚠ `GK_GX_DIR` 指向不存在的目录：只砍掉与本性质**无关**的 gitnexus 图基线探测
    （实测单次 `gitnexus status` 168s，占 update 总耗时 90%+），**不砍** build+sign+发布链路
    —— 6 个真进程仍各自走 `_ctx_lock_acquire` 独占锁 + `os.replace` + `.sig.tmp` 发布。
    不这么做时单臂 ~190s、6 臂并发会把机器压到不可用（用户已报告过整机假死）。
    """
    import threading
    import time

    ctx = os.path.join(SKILL, "references", "subagent-context.json")
    sig = ctx + ".sig"
    env = dict(os.environ, GK_GX_DIR="/nonexistent/gk-redteam")
    stop = {"v": False}
    seen = []

    def watcher():
        while not stop["v"]:
            seen.append(probe(ctx, sig))
            time.sleep(0.1)

    th = threading.Thread(target=watcher, daemon=True)
    th.start()
    try:
        procs = [subprocess.Popen(["bash", CLI, "context", "--update"], cwd=SKILL, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(6)]
        outs = [p.communicate(timeout=300) for p in procs]
    finally:
        stop["v"] = True
        th.join(timeout=10)
    for (out, err), p in zip(outs, procs):
        assert p.returncode == 0, err[-400:]
        assert '"ok":true' in out.replace(" ", "").lower(), out[-200:]
    assert probe(ctx, sig) == "ok"
    assert seen and set(seen) == {"ok"}, sorted(set(seen))


def test_av10_static_red_contract_is_clean():
    """AV-10：`_red_attacks.py::red_ctx_sig_race` 在 HEAD 必须零 finding
    （任一 finding = 某条并发防线被摘掉，红队即可重放 6 连爆）。"""
    sys.path.insert(0, os.path.join(SKILL, "scripts"))
    import _red_attacks as RA
    assert RA.red_ctx_sig_race() == []


def test_av11_red_cli_phase_ctx():
    """AV-11：`_red_attacks.py ctx` 是 `audit --red` 的可见入口（禁「函数在、入口不通」）。"""
    import json
    r = subprocess.run([PY, os.path.join(SKILL, "scripts", "_red_attacks.py"), "ctx"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-400:]
    d = json.loads(r.stdout)
    assert d["phase"] == "ctx" and d["findings"] == 0, d
