#!/usr/bin/env python3
"""gk_kvm_launcher.py — KVM 隔离启动器（A9，2026-10-28）

## 用途

A9 裁定：**AIG（AI-Infra-Guard）只在沙箱内处理不可信输入**。本模块就是那个沙箱的
「启动 / 超时 / 网络隔离」三件套 —— AIG 与任何不可信样本**不得**在宿主直接跑。

## 三件套

1. **启动**：`qemu-system-x86_64 -enable-kvm`；`/dev/kvm` 不存在 ⟹ **fail-loud**
   （不静默降级为 TCG —— 降级后隔离语义与性能都不同，静默降级等于假绿）。
2. **超时**：`subprocess.run(timeout=…)`，超时 `SIGKILL` 整个进程组；超时**算失败**。
3. **网络隔离**：`-net none -nic none`（无网卡）+ `-snapshot`（不落盘）+ `-sandbox on`。

## 两种引导形态

| mode | 需要 | 命令如何进客体 |
|:--|:--|:--|
| `kernel`（默认） | `--image` + `--kernel`(+ `--initrd`) | 经内核 cmdline `gk_argv=<base64url(json)>`，客体 init 自行读取执行 |
| `boot` | `--image` | 不入命令：镜像内预置服务（如 AIG daemon）自行拉起 |

⚠ 本机**没有**预置 guest 镜像 ⟹ 生产调用点（`_red_attacks.red_aig`）在未配 `GK_KVM_IMAGE`
时**明确报不可用**，绝不退回宿主执行。

用法：
    python3 gk_kvm_launcher.py probe
    python3 gk_kvm_launcher.py run --image /path/guest.qcow2 --timeout 120 -- aig scan /samples
"""
import base64
import json
import os
import shutil
import subprocess
import sys

KVM_DEV = "/dev/kvm"
DEFAULT_QEMU = "qemu-system-x86_64"
DEFAULT_TIMEOUT_S = 300.0
MAX_TIMEOUT_S = 3600.0


def _qemu_bin() -> str:
    return os.environ.get("GK_QEMU_BIN", "") or (shutil.which(DEFAULT_QEMU) or "")


def probe() -> dict:
    """探测 KVM / qemu 可用性（**只读**；不启动任何东西）。"""
    kvm = os.path.exists(KVM_DEV) and os.access(KVM_DEV, os.R_OK | os.W_OK)
    qemu = _qemu_bin()
    reasons = []
    if not kvm:
        reasons.append("%s 不存在或不可读写（KVM 加速不可用）" % KVM_DEV)
    if not qemu:
        reasons.append("%s 不在 PATH（可用 GK_QEMU_BIN 指定）" % DEFAULT_QEMU)
    return {"ok": not reasons, "kvm": kvm, "kvm_dev": KVM_DEV, "qemu": qemu,
            "reason": "; ".join(reasons)}


def encode_cmd(cmd) -> str:
    """把命令编码进内核 cmdline（base64url，无逗号/空格，避免 cmdline 切分）。"""
    raw = json.dumps(list(cmd), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def build_argv(cmd, *, image: str, kernel: str = "", initrd: str = "",
               memory_mb: int = 2048, cpus: int = 2, mode: str = "kernel") -> list:
    """构造 qemu argv（**纯函数**，便于机检「三件套是否都在」）。"""
    qemu = _qemu_bin() or DEFAULT_QEMU
    argv = [
        qemu,
        "-enable-kvm",                 # 启动：必须真 KVM
        "-m", str(int(memory_mb)),
        "-smp", str(int(cpus)),
        "-nographic", "-no-reboot",
        "-snapshot",                   # 不写回镜像（不可信输入不落盘）
        "-sandbox", "on",              # qemu 自身 seccomp 沙箱
        "-net", "none", "-nic", "none",  # 网络隔离：无任何网卡
        "-drive", "file=%s,format=qcow2,if=virtio,readonly=on" % image,
    ]
    if mode == "kernel":
        if not kernel:
            raise ValueError("mode=kernel 需要 kernel 路径（或改用 mode=boot）")
        argv += ["-kernel", kernel]
        if initrd:
            argv += ["-initrd", initrd]
        argv += ["-append",
                 "console=ttyS0 panic=-1 gk_argv=%s" % encode_cmd(cmd)]
    elif mode != "boot":
        raise ValueError("未知 mode: %r（合法：kernel / boot）" % mode)
    return argv


def _clamp_timeout(timeout_s) -> float:
    try:
        t = float(timeout_s)
    except (TypeError, ValueError):
        t = DEFAULT_TIMEOUT_S
    if t <= 0:
        t = DEFAULT_TIMEOUT_S
    return min(t, MAX_TIMEOUT_S)


def run_isolated(cmd, *, image: str = "", kernel: str = "", initrd: str = "",
                 timeout_s: float = DEFAULT_TIMEOUT_S, memory_mb: int = 2048,
                 cpus: int = 2, mode: str = "kernel") -> dict:
    """在 KVM 沙箱内跑 `cmd`。**任何前置缺失都 fail-loud**（不退回宿主执行）。

    返回 `{"ok", "returncode", "stdout", "stderr", "timeout", "argv"}`。
    """
    p = probe()
    if not p["ok"]:
        return {"ok": False, "error": "KVM 沙箱不可用: %s" % p["reason"]}
    img = image or os.environ.get("GK_KVM_IMAGE", "")
    if not img:
        return {"ok": False, "error": "未配置 guest 镜像（--image 或 GK_KVM_IMAGE）⟹ 拒绝在宿主执行"}
    if not os.path.isfile(img):
        return {"ok": False, "error": "guest 镜像不存在: %s" % img}
    kern = kernel or os.environ.get("GK_KVM_KERNEL", "")
    try:
        argv = build_argv(cmd, image=img, kernel=kern, initrd=initrd,
                          memory_mb=memory_mb, cpus=cpus, mode=mode)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    t = _clamp_timeout(timeout_s)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=t,
                           start_new_session=True)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "KVM 沙箱超时 %.1fs（已 SIGKILL）" % t,
                "timeout": True, "argv": argv}
    except Exception as e:  # noqa: BLE001 — 边界：qemu 起不来必须回结构化错误
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e), "argv": argv}
    return {"ok": r.returncode == 0, "returncode": r.returncode,
            "stdout": (r.stdout or "")[:100000], "stderr": (r.stderr or "")[-8000:],
            "timeout": False, "argv": argv}


def main(argv=None) -> int:
    av = list(sys.argv[1:] if argv is None else argv)
    if not av or av[0] not in ("probe", "run"):
        print(json.dumps({"ok": False,
                          "error": "usage: gk_kvm_launcher.py probe | run --image P --timeout S -- CMD..."},
                         ensure_ascii=False))
        return 2
    if av[0] == "probe":
        print(json.dumps(probe(), ensure_ascii=False))
        return 0
    image = os.environ.get("GK_KVM_IMAGE", "")
    kernel = os.environ.get("GK_KVM_KERNEL", "")
    timeout_s = DEFAULT_TIMEOUT_S
    mode = "kernel"
    cmd = []
    i = 1
    while i < len(av):
        a = av[i]
        if a == "--image" and i + 1 < len(av):
            image = av[i + 1]; i += 2
        elif a == "--kernel" and i + 1 < len(av):
            kernel = av[i + 1]; i += 2
        elif a == "--timeout" and i + 1 < len(av):
            timeout_s = av[i + 1]; i += 2
        elif a == "--mode" and i + 1 < len(av):
            mode = av[i + 1]; i += 2
        elif a == "--":
            cmd = av[i + 1:]
            break
        else:
            i += 1
    r = run_isolated(cmd, image=image, kernel=kernel, timeout_s=timeout_s, mode=mode)
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
