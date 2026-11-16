#!/usr/bin/env python3
"""RED-DIFF 自描述契约双通道对拍 — 红先测试（2026-11-10）。

背景：原 `red_diff` 的 8 条向量全部是「外部 SWE 契约 JSON → 提交树存在性扫描」，
本仓恒无该契约 ⟹ 恒走 `RED-DIFF-CONTRACT` info 分支，实际**永不打**（静态向量
打不出东西的同一病灶）。本测试锁住新增的自描述通道：

  通道 A（实现面）：`gatekeeper-cli.sh` 的 `_CMD_REG` 注册项与函数定义；
                    `_red_attacks.py` 的 phase 分支 → 被调用函数
  通道 B（声明面）：`references/cli-protocol.md` 命令小节；`gk_chain.py` 的
                    `Step("RED-*")` 序列；`references/red-vectors.json` stations

判据 = 双向集合一致，且每条向量必须通过**变异门**：
  注入单点漂移 → 必须报；同一变异复原 → 必须静默（防「永远绿的假向量」）。
"""
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _red_attacks  # noqa: E402

SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = (
    "gatekeeper-cli.sh",
    "scripts/_red_attacks.py",
    "scripts/gk_chain.py",
    "references/red-vectors.json",
    "references/cli-protocol.md",
)


def _tree(tmp_path):
    """复制对拍所需的 5 个真实文件到临时树（保持相对路径）。"""
    for rel in FILES:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(os.path.join(SKILL, rel), str(dst))
    return str(tmp_path)


def _mutate(root, rel, old, new):
    p = os.path.join(root, rel)
    with open(p, encoding="utf-8") as f:
        txt = f.read()
    assert old in txt, "变异锚点不存在（测试自身失效）: %r" % old
    with open(p, "w", encoding="utf-8") as f:
        f.write(txt.replace(old, new, 1))


def _ids(root=None):
    return [f["id"] for f in _red_attacks.red_diff_decl(*([] if root is None else [root]))]


def test_repo_self_described_contract_is_clean():
    """真实仓库：两通道当前一致 → 零 findings（否则向量一上线就是噪音）。"""
    assert _red_attacks.red_diff_decl() == []


def test_missing_cmd_function_detected(tmp_path):
    """变异：`_CMD_REG[balance]` 指向的函数被改名 → 注册指向死函数必须报。"""
    root = _tree(tmp_path)
    _mutate(root, "gatekeeper-cli.sh", "\ncmd_balance() {", "\ncmd_balance_renamed() {")
    ids = _ids(root)
    assert "RED-DIFF-DECL-REG" in ids, ids


def test_missing_cmd_doc_detected(tmp_path):
    """变异：命令文档小节丢失 → 声明面漂移必须报（medium）。"""
    root = _tree(tmp_path)
    _mutate(root, "references/cli-protocol.md", "### cmd_balance", "### cmd_balance_old")
    ids = _ids(root)
    assert "RED-DIFF-DECL-DOC" in ids, ids


def test_missing_phase_impl_detected(tmp_path):
    """变异：phase 分支调用的 red_ghost() 被改名 → 红队站静默空跑必须报。"""
    root = _tree(tmp_path)
    _mutate(root, "scripts/_red_attacks.py", "\ndef red_ghost():", "\ndef red_ghost_renamed():")
    ids = _ids(root)
    assert "RED-DIFF-DECL-PHASE" in ids, ids


def test_unregistered_station_detected(tmp_path):
    """变异：chain 有站但登记表无该站 → 站不可登记/覆盖假绿必须报。"""
    root = _tree(tmp_path)
    p = os.path.join(root, "references", "red-vectors.json")
    with open(p, encoding="utf-8") as f:
        reg = json.load(f)
    reg["stations"] = [s for s in reg["stations"] if s["id"] != "RED-GHOST"]
    with open(p, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False)
    ids = _ids(root)
    assert "RED-DIFF-DECL-STATION" in ids, ids


def test_missing_contract_files_fail_loud(tmp_path):
    """文件缺失 = 不可对拍，必须 high 报错（禁静默 PASS）。"""
    empty = tmp_path / "empty"
    empty.mkdir()
    fs = _red_attacks.red_diff_decl(str(empty))
    assert [f["id"] for f in fs] == ["RED-DIFF-DECL-MISSING"]
    assert fs[0]["severity"] == "high"
    assert len(fs[0].get("description", "")) > 0


def test_restore_silences(tmp_path):
    """变异门反向：同一份文件复原后必须静默（防「恒报」的假向量）。"""
    root = _tree(tmp_path)
    _mutate(root, "gatekeeper-cli.sh", "\ncmd_balance() {", "\ncmd_balance_renamed() {")
    assert "RED-DIFF-DECL-REG" in _ids(root)
    shutil.copy2(os.path.join(SKILL, "gatekeeper-cli.sh"),
                 os.path.join(root, "gatekeeper-cli.sh"))
    assert _red_attacks.red_diff_decl(root) == []


def test_red_diff_keeps_contract_info_first_without_contract(tmp_path):
    """无外部契约时：CONTRACT info 仍在首位，且自描述向量照跑（非假绿）。"""
    submit = tmp_path / "submit"
    submit.mkdir()
    old = {k: os.environ.get(k) for k in ("RED_DIFF_CONTRACT", "RED_DIFF_SUBMIT")}
    os.environ["RED_DIFF_CONTRACT"] = ""
    os.environ["RED_DIFF_SUBMIT"] = str(submit)
    try:
        fs = _red_attacks.red_diff()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    assert fs and fs[0]["id"] == "RED-DIFF-CONTRACT"
    assert all(f["id"] != "RED-DIFF-DECL-REG" for f in fs)
