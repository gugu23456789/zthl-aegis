#!/usr/bin/env python3
"""gk_cron_external_ref.py — cron 外部参考检查 job（2026-09-01）

用户质询"cron 那边需要查询的外部参考呢？cron 实装过但是这段时间怎么又是没动静"：
  - 调度器（Windows 任务计划 GatekeeperCronTick）每小时真实运行，但 jobs.json 缺失
    （仅残留 lock/sha256）且 tick 无 due job 不落痕 → 无 job 可跑 = 看起来"没动静"。
  - 本脚本 = L4 外部参考 job 的确定性执行体（Hermes context_from 模式上游数据源）：
    ① gitnexus npm 全局版本 vs npm 最新版本（上游依赖漂移检测）
    ② 本地 git 未推送提交数（远端同步健康）
    ③ 上次提交距今天数（陈旧检测）
  输出 JSON 契约（wake gate 兼容：输出含 JSON 即 agent 可继续）。

确定性：0 API（npm view 走网络注册表查询 = 唯一外部依赖，其余全本地）。
调用：cron 注册 `--script scripts/gk_cron_external_ref.py --no-agent`（纯脚本，不启 agent）。
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_host_paths import user_home as _user_home  # noqa: E402


def _run(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1


# 2026-10-29 去硬编码：gitnexus 全局包的落点由**用户目录**派生（`gk_host_paths.user_home`，
# 不写死用户名）；调用方已按当前宿主形态（WSL `/mnt/...` 或 Windows `C:/...`）给出路径。
_WIN_PKG_CANDIDATES = [
    os.path.join(_user_home(), "AppData", "Roaming", "npm", "node_modules",
                 "gitnexus", "package.json"),
]


def _read_gitnexus_local_version() -> str:
    """读 Windows 全局 gitnexus package.json version（WSL/Windows 双形态路径）。"""
    import json as _json
    for _p in _WIN_PKG_CANDIDATES:
        try:
            with open(_p, "r", encoding="utf-8") as _f:
                return str(_json.load(_f).get("version", "unknown"))
        except Exception:
            continue
    return "unknown"


def main() -> None:
    out: dict = {"ok": True, "source": "cron-external-ref", "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")}

    # ① gitnexus 上游版本漂移（npm 注册表 vs 全局安装）
    local_v = _read_gitnexus_local_version()
    out["gitnexus_local"] = local_v
    latest_out, latest_err, latest_rc = _run(["npm", "view", "gitnexus", "version"])
    if latest_rc == 0 and latest_out:
        out["gitnexus_latest"] = latest_out
        out["gitnexus_drift"] = (local_v != latest_out) if local_v != "unknown" else "unknown"
    else:
        out["gitnexus_latest"] = "unknown"
        out["gitnexus_drift"] = "unknown"
        out["gitnexus_drift_note"] = "npm view 失败（离线?）— 非阻断"

    # ② git 未推送提交 + 陈旧检测（WSL git，与 gatekeeper 一致）
    git_cmds = {
        "unpushed": ["git", "rev-list", "--count", "@{u}..HEAD"],
        "last_commit_days": ["git", "log", "-1", "--format=%ct"],
    }
    for key, cmd in git_cmds.items():
        so, se, rc = _run(cmd, timeout=15)
        if key == "unpushed":
            out["unpushed_commits"] = int(so) if (rc == 0 and so.strip().isdigit()) else -1
            if rc != 0 or not so.strip().isdigit():
                out["unpushed_note"] = "无 upstream / git 异常 — 非阻断"
        else:
            if rc == 0 and so.strip().isdigit():
                ts = int(so.strip())
                days = (time.time() - ts) / 86400
                out["last_commit_days"] = round(days, 1)
            else:
                out["last_commit_days"] = None

    # ③ 汇总（wake gate：供 cron agent 模式判断是否需要人工介入）
    flags = []
    if out.get("gitnexus_drift") is True:
        flags.append(f"gitnexus 版本漂移: local={out['gitnexus_local']} latest={out['gitnexus_latest']}")
    if out.get("unpushed_commits", 0) > 0:
        flags.append(f"{out['unpushed_commits']} 个未推送提交")
    if isinstance(out.get("last_commit_days"), float) and out["last_commit_days"] > 30:
        flags.append(f"最后提交 {out['last_commit_days']} 天前（陈旧）")
    out["findings"] = flags
    out["needs_attention"] = bool(flags)
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
