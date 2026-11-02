#!/usr/bin/env python3
"""gk_cron_model_radar.py — 模型发布雷达（cron 作业内核）

设计约束（owner 2026-11-01）：
  · **0 API / 0 LLM**：只发 HTTPS GET（HuggingFace 公开 API，无需 key），不调任何对话端点；
  · **低负载、不 OOM**：单请求、8s 超时、响应上限 512KB、内存占用 < 30MB；每 3 天一次；
  · **幂等**：状态缓存 `~/.gatekeeper/radar/state.json`，仅「新模型 / 新更新时间」产事件；
  · **finding 落点**：`gk_finding.py register` ⟹ state `findings[]` + `.finding-journal.jsonl`
    （append-only）。**不写** `references/ecc-finding-*.md`（长文归档，公开包已排除）。

用法：`cron` 作业 `--script scripts/gk_cron_model_radar.py --no-agent`。
stdout 末行为 JSON（cron 兼容）；任何网络/解析失败都**不抛栈**，以具名 error 退出 0/1。
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HF_URL = ("https://huggingface.co/api/models?author=deepseek-ai"
          "&sort=lastModified&direction=-1&limit=20")
HOME = Path(os.environ.get("HOME") or str(Path.home()))
RADAR_DIR = HOME / ".gatekeeper" / "radar"
STATE = RADAR_DIR / "state.json"
EVENTS = RADAR_DIR / "events.jsonl"
STATE_FILE = HOME / ".gatekeeper.state"


def _fetch(url: str, timeout: int = 8, cap: int = 512 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": "zthl-aegis-radar/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(cap + 1)
    if len(raw) > cap:
        raise ValueError("response_too_large")
    return json.loads(raw.decode("utf-8", "replace"))


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _register_finding(title: str, source: str, root_key: str) -> str:
    """登记 finding（失败只留痕，不阻断雷达）。返回状态字符串。"""
    tool = Path(__file__).resolve().parent / "gk_finding.py"
    if not tool.exists() or not STATE_FILE.exists():
        return "skipped:no_state_or_tool"
    try:
        r = subprocess.run(
            [sys.executable, str(tool), "register", str(STATE_FILE), title, source,
             "--domain", "spz-gatekeeper-r-sequence.model-radar",
             "--root-key", root_key],
            capture_output=True, text=True, timeout=30)
        return "ok" if r.returncode == 0 else "error:%s" % (r.stderr or "")[:120]
    except (subprocess.TimeoutExpired, OSError) as e:
        return "error:%s" % type(e).__name__


def main() -> int:
    started = time.time()
    out = {"ok": False, "new": [], "checked": 0, "source": "huggingface:deepseek-ai"}
    try:
        models = _fetch(HF_URL)
    except Exception as e:  # 网络失败：具名退出，不落假数据
        out.update({"error": "fetch_failed:%s" % type(e).__name__,
                    "elapsed_ms": int((time.time() - started) * 1000)})
        print(json.dumps(out, ensure_ascii=False))
        return 1
    if not isinstance(models, list):
        out.update({"error": "bad_payload"})
        print(json.dumps(out, ensure_ascii=False))
        return 1
    old = _load_state()
    baseline = not old
    new_state, events = {}, []
    for m in models:
        if not isinstance(m, dict):
            continue
        mid = str(m.get("id") or m.get("modelId") or "")
        if not mid:
            continue
        stamp = str(m.get("lastModified") or m.get("createdAt") or "")
        new_state[mid] = stamp
        out["checked"] += 1
        if not baseline and old.get(mid) != stamp:
            ev = {"ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "model": mid, "last_modified": stamp}
            events.append(ev)
    RADAR_DIR.mkdir(parents=True, exist_ok=True)
    if events:
        with EVENTS.open("a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            f.flush()
    STATE.write_text(json.dumps(new_state, ensure_ascii=False, indent=1), encoding="utf-8")
    findings = []
    for ev in events:
        findings.append(_register_finding(
            "模型发布雷达：%s 更新（%s）" % (ev["model"], ev["last_modified"]),
            "huggingface:%s" % ev["model"],
            "model_radar:%s:%s" % (ev["model"], ev["last_modified"])))
    out.update({"ok": True, "new": events, "findings": findings, "baseline": baseline,
                "elapsed_ms": int((time.time() - started) * 1000)})
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
