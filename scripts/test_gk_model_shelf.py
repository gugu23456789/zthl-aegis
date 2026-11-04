#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""红先/性质臂：模型制品保质期机检（`gk_model_shelf`）。

覆盖：原子下载/哈希、缺失制品 FAIL、探针 pin 一致、在线元数据注入、退出码。
"""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_model_shelf as S  # noqa: E402


class _Resp:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_opener(url, timeout=0):
    u = getattr(url, "full_url", url)            # `_download` 传 Request（带 UA）
    if u.endswith("tokenizer.json"):
        return _Resp(b'{"version":"1.0","model":{"type":"BPE"}}')
    if u.endswith("tokenizer_config.json"):
        return _Resp(b'{"model_max_length":1048576}')
    return _Resp(json.dumps({"sha": S.PINNED["repo_commit"],
                             "config": {"model_type": "deepseek_v41"}}).encode())


def test_refresh_atomic_and_manifest(tmp_path):
    """refresh：下载到缓存、sha 与内容一致、manifest 落盘（源码不动）。"""
    meta = S.refresh(cache_dir=str(tmp_path), opener=_fake_opener)
    assert os.path.isfile(meta["tokenizer_path"])
    with open(meta["tokenizer_path"], "rb") as f:
        assert meta["sha256"] == hashlib.sha256(f.read()).hexdigest()
    assert meta["config_bytes"] > 0
    assert os.path.isfile(os.path.join(str(tmp_path), "manifest.json"))


def test_refresh_falls_back_to_mirror(tmp_path):
    """官方端点不可达 ⟹ 自动回退 hf-mirror（本机 WSL 的真实网络形态）。"""
    def op(url, timeout=0):
        u = getattr(url, "full_url", url)
        if "huggingface.co" in u and "hf-mirror" not in u:
            raise OSError("blocked")
        return _fake_opener(url, timeout)

    meta = S.refresh(cache_dir=str(tmp_path), opener=op)
    assert meta["endpoint"].startswith("https://hf-mirror.com")
    assert os.path.isfile(meta["tokenizer_path"])


def test_tokenizer_checks_missing_is_fail(tmp_path):
    """制品缺失 ⟹ FAIL（不是静默 UNKNOWN）。"""
    rows, info = S.tokenizer_checks(path=str(tmp_path / "nope.json"))
    assert rows[0]["status"] == "FAIL" and not info


def test_pin_checks_match_current_code():
    """探针常量与 PINNED 一致；S 新鲜度按真实指纹状态断言（1017 已换代）。

    2026-11-04：phase 族在**公开包**属导出排除面 ⟹ `pin_checks()` 返回 `NOT_SHIPPED`
    单行。此处**具名 skip**（不是静默放行）：私仓仍跑全部真断言。
    """
    rows = S.pin_checks()
    by = {r["check"]: r["status"] for r in rows}
    if by.get("probe_import") == "NOT_SHIPPED":
        pytest.skip("phase 族不随公开包（NOT_SHIPPED）—— 私仓跑真断言")
    assert by["niah_long_pairs"] == "PASS"
    assert by["niah_top_logprobs"] == "PASS"
    assert by["stride_S_candidate"] == "PASS"
    # V4.1-Flash-1017 指纹 e72d3c7f… ≠ S=2 取证指纹 aeb56401… ⟹ 必须 FAIL。
    assert by["stride_S_freshness"] == "FAIL"


def test_online_checks_injected_opener():
    """在线检查：model_type / commit 对齐 ⟹ PASS；注入 opener，不触网。"""
    rows = S.online_checks(opener=_fake_opener)
    by = {r["check"]: r["status"] for r in rows}
    assert by["hf_model_type"] == "PASS"
    assert by["repo_commit"] == "PASS"


def test_online_checks_falls_back_to_mirror():
    """官方 API 不可达 ⟹ 走 hf-mirror（WSL 真实网络形态），仍能检出 commit。"""
    def op(url, timeout=0):
        u = getattr(url, "full_url", url)
        if "huggingface.co" in u and "hf-mirror" not in u:
            raise OSError("blocked")
        return _fake_opener(url, timeout)

    by = {r["check"]: r["status"] for r in S.online_checks(opener=op)}
    assert by["hf_api"] == "PASS"
    assert by["repo_commit"] == "PASS"


def test_online_checks_detects_repo_commit_drift():
    """权重仓换代（sha 变）⟹ repo_commit FAIL，即升级门禁的触发信号。"""
    def op(url, timeout=0):
        return _Resp(json.dumps({"sha": "0" * 40,
                                 "config": {"model_type": "deepseek_v41"}}).encode())

    by = {r["check"]: r["status"] for r in S.online_checks(opener=op)}
    assert by["repo_commit"] == "FAIL"


def test_fingerprint_rows_pass_fail_unknown():
    """指纹三态：同 ⟹ PASS；异 ⟹ FAIL；缺 ⟹ UNKNOWN（不静默通过）。"""
    assert S.fingerprint_rows(
        {"fingerprint": S.PINNED["system_fingerprint"]})[0]["status"] == "PASS"
    assert S.fingerprint_rows({"fingerprint": "deadbeef"})[0]["status"] == "FAIL"
    assert S.fingerprint_rows(
        {"fingerprint": None, "reason": "no key"})[0]["status"] == "UNKNOWN"


def test_live_fingerprint_without_key_is_unknown(monkeypatch):
    """无 API key ⟹ 不发请求、UNKNOWN（CI 无密钥时不得误报 PASS/FAIL）。"""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("GATEKEEPER_API_KEY", raising=False)
    obs = S.live_fingerprint()
    assert obs["fingerprint"] is None
    assert S.fingerprint_rows(obs)[0]["status"] == "UNKNOWN"


def test_live_fingerprint_injected_opener():
    """最小调用走 /chat/completions，解析 system_fingerprint。"""
    def op(req, timeout=0):
        assert req.full_url.endswith("/chat/completions")
        return _Resp(json.dumps({"system_fingerprint": "fp-test",
                                 "model": "deepseek-flash"}).encode())

    obs = S.live_fingerprint(api_key="k", opener=op)
    assert obs["fingerprint"] == "fp-test"


def test_run_check_exit_code_on_fail(tmp_path):
    """任一 FAIL ⟹ 退出码 1（可作 CI/开跑前门禁）。"""
    assert S.run_check(path=str(tmp_path / "nope.json")) == 1


def test_allow_stale_phase_only_downgrades_phase_row():
    """只把已知的 S 过期降为 WARN；其他 FAIL 必须保留。"""
    rows = S._apply_allow_stale([
        {"check": "stride_S_freshness", "status": "FAIL", "detail": "stale"},
        {"check": "repo_commit", "status": "FAIL", "detail": "drift"},
    ])
    assert rows[0]["status"] == "WARN"
    assert rows[1]["status"] == "FAIL"


def test_run_check_allow_stale_phase_exit_code(monkeypatch):
    """定时 guard：仅 S 过期 ⟹ 退出 0；其他漂移仍退出 1。"""
    monkeypatch.setattr(S, "tokenizer_checks",
                        lambda path=None: ([{"check": "tokenizer",
                                             "status": "PASS",
                                             "detail": "ok"}], {}))
    monkeypatch.setattr(S, "pin_checks",
                        lambda: [{"check": "stride_S_freshness",
                                  "status": "FAIL", "detail": "stale"}])
    assert S.run_check(allow_stale_phase=True) == 0
    assert S.run_check(allow_stale_phase=False) == 1
