#!/usr/bin/env python3
"""test_gk_kvm_launcher.py — A9（2026-10-28）红线锁：三件套 + 禁宿主直跑

A9 裁定：「新增 RED-AIG 车道 + KVM 启动器（**启动/超时/网络隔离**三件套），AIG **只在沙箱内**
处理不可信输入」。本文件锁的是**纪律**（可机检），不是「AIG 能不能扫出漏洞」：

  1. 启动：argv 必须含 `-enable-kvm`；`/dev/kvm` 缺失 ⟹ fail-loud（不静默降级 TCG）。
  2. 超时：`subprocess.run(timeout=…)`，超时算失败（不是「返回半截算成功」）。
  3. 网络隔离：`-net none -nic none` + `-snapshot`（不落盘）+ `-sandbox on`。
  4. 禁宿主直跑：无镜像 / 无 KVM ⟹ 拒绝执行；`red_aig` 无任何绕过分支。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_kvm_launcher as KV  # noqa: E402
import _red_attacks as RA  # noqa: E402


class _R:
    returncode = 0

    def __init__(self, out="", err=""):
        self.stdout = out
        self.stderr = err


# ─── 1. 启动 ──────────────────────────────────────────────────────────────

def test_probe_shape(monkeypatch):
    monkeypatch.setenv("GK_QEMU_BIN", "/fake/qemu")
    p = KV.probe()
    assert set(p) >= {"ok", "kvm", "kvm_dev", "qemu", "reason"}
    assert p["kvm_dev"] == "/dev/kvm"


def test_build_argv_carries_three_pieces(monkeypatch):
    monkeypatch.setenv("GK_QEMU_BIN", "/fake/qemu")
    argv = KV.build_argv(["aig", "scan", "/s"], image="/img.qcow2",
                         kernel="/vmlinuz", initrd="/initrd")
    flat = " ".join(argv)
    assert "-enable-kvm" in argv, "启动面：必须是真 KVM（禁静默 TCG 降级）"
    assert ["-net", "none"] == argv[argv.index("-net"):argv.index("-net") + 2], "网络隔离：-net none"
    assert "-nic" in argv and argv[argv.index("-nic") + 1] == "none", "网络隔离：-nic none"
    assert "-snapshot" in argv, "不可信输入不落盘"
    assert ["-sandbox", "on"] == argv[argv.index("-sandbox"):argv.index("-sandbox") + 2]
    assert "readonly=on" in flat, "镜像必须只读挂载"
    assert "gk_argv=" in flat, "命令须经内核 cmdline 传入（不落到宿主 shell）"


def test_build_argv_kernel_mode_requires_kernel(monkeypatch):
    monkeypatch.setenv("GK_QEMU_BIN", "/fake/qemu")
    with pytest.raises(ValueError):
        KV.build_argv(["x"], image="/img.qcow2", mode="kernel")


def test_build_argv_rejects_unknown_mode(monkeypatch):
    monkeypatch.setenv("GK_QEMU_BIN", "/fake/qemu")
    with pytest.raises(ValueError):
        KV.build_argv(["x"], image="/img.qcow2", mode="magic")


def test_encode_cmd_roundtrip():
    import base64
    cmd = ["aig", "scan", "路径 with space"]
    enc = KV.encode_cmd(cmd)
    raw = enc + "=" * (-len(enc) % 4)
    assert json.loads(base64.urlsafe_b64decode(raw).decode("utf-8")) == cmd
    assert "," not in enc and " " not in enc, "cmdline 切分面不得被命令内容污染"


# ─── 4. 禁宿主直跑（先于 2/3 校验：没有隔离面就不执行）────────────────────

def test_run_without_image_refuses(monkeypatch):
    monkeypatch.setattr(KV, "probe", lambda: {"ok": True, "kvm": True, "qemu": "/fake/qemu",
                                              "kvm_dev": "/dev/kvm", "reason": ""})
    monkeypatch.delenv("GK_KVM_IMAGE", raising=False)
    r = KV.run_isolated(["echo", "hi"])
    assert r["ok"] is False and "拒绝在宿主执行" in r["error"]


def test_run_without_kvm_refuses(monkeypatch):
    monkeypatch.setattr(KV, "probe", lambda: {"ok": False, "kvm": False, "qemu": "",
                                              "kvm_dev": "/dev/kvm",
                                              "reason": "/dev/kvm 不存在"})
    r = KV.run_isolated(["echo", "hi"], image="/tmp/x.qcow2")
    assert r["ok"] is False and "KVM 沙箱不可用" in r["error"]


# ─── 2/3. 超时 + 网络隔离在真实 spawn 参数上 ──────────────────────────────

def test_run_passes_timeout_and_isolation(monkeypatch, tmp_path):
    img = tmp_path / "guest.qcow2"
    img.write_bytes(b"fake")
    monkeypatch.setattr(KV, "probe", lambda: {"ok": True, "kvm": True, "qemu": "/fake/qemu",
                                              "kvm_dev": "/dev/kvm", "reason": ""})
    monkeypatch.setenv("GK_QEMU_BIN", "/fake/qemu")
    seen = {}

    def _run(argv, **kw):
        seen["argv"], seen["kw"] = argv, kw
        return _R(out="scanned")

    monkeypatch.setattr(KV.subprocess, "run", _run)
    r = KV.run_isolated(["aig", "scan"], image=str(img), kernel="/vmlinuz", timeout_s=42)
    assert r["ok"] is True
    assert seen["kw"]["timeout"] == 42.0, "超时未下传"
    assert "-enable-kvm" in seen["argv"] and "none" in seen["argv"]


def test_run_timeout_is_failure(monkeypatch, tmp_path):
    import subprocess
    img = tmp_path / "guest.qcow2"
    img.write_bytes(b"fake")
    monkeypatch.setattr(KV, "probe", lambda: {"ok": True, "kvm": True, "qemu": "/fake/qemu",
                                              "kvm_dev": "/dev/kvm", "reason": ""})
    monkeypatch.setattr(KV, "build_argv", lambda *a, **k: ["/fake/qemu"])

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="qemu", timeout=k.get("timeout", 1))

    monkeypatch.setattr(KV.subprocess, "run", _boom)
    r = KV.run_isolated(["aig"], image=str(img), timeout_s=5)
    assert r["ok"] is False and r["timeout"] is True


def test_timeout_is_clamped():
    assert KV._clamp_timeout("not-a-number") == KV.DEFAULT_TIMEOUT_S
    assert KV._clamp_timeout(0) == KV.DEFAULT_TIMEOUT_S
    assert KV._clamp_timeout(10 ** 9) == KV.MAX_TIMEOUT_S


# ─── RED-AIG 车道纪律 ─────────────────────────────────────────────────────

def test_red_aig_disabled_is_reported_not_exempt(monkeypatch):
    monkeypatch.delenv("AIG_BIN", raising=False)
    f = RA.red_aig()
    assert len(f) == 1 and f[0]["id"] == "RED-AIG-01" and f[0]["severity"] == "info"


def test_red_aig_never_runs_on_host(monkeypatch, tmp_path):
    """有 AIG_BIN、KVM 可用、但**没有镜像** ⟹ high（不是静默跳过，也不退回宿主）。"""
    monkeypatch.setenv("AIG_BIN", "/opt/aig")
    monkeypatch.delenv("GK_KVM_IMAGE", raising=False)
    monkeypatch.setattr(KV, "probe", lambda: {"ok": True, "kvm": True, "qemu": "/fake/qemu",
                                              "kvm_dev": "/dev/kvm", "reason": ""})

    def _no_spawn(*a, **k):
        raise AssertionError("没有 KVM 镜像时仍尝试 spawn ⟹ 宿主直跑风险")

    monkeypatch.setattr(KV.subprocess, "run", _no_spawn)
    f = RA.red_aig()
    assert len(f) == 1 and f[0]["id"] == "RED-AIG-02" and f[0]["severity"] == "high"


def test_red_aig_runs_only_through_launcher(monkeypatch):
    """全前置就绪 ⟹ 只经 `run_isolated` 执行（禁自带 subprocess）。"""
    monkeypatch.setenv("AIG_BIN", "/opt/aig")
    monkeypatch.setenv("GK_KVM_IMAGE", "/tmp/guest.qcow2")
    calls = []
    monkeypatch.setattr(KV, "probe", lambda: {"ok": True, "kvm": True, "qemu": "/fake/qemu",
                                              "kvm_dev": "/dev/kvm", "reason": ""})
    monkeypatch.setattr(KV, "run_isolated",
                        lambda cmd, **k: calls.append((cmd, k)) or {"ok": True})
    assert RA.red_aig() == []
    assert calls and calls[0][0][0] == "/opt/aig"
