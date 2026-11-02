#!/usr/bin/env python3
"""gk_audit_cron_run.py — audit-daily 作业体（指纹跳过 + 逐域计时 + 告警）

背景（2026-11-01 实测）：默认三域 state/docs/memory 合计 ~10s，**不是**性能瓶颈；
真正的问题是「没人跑 / 跑没跑不知道」。本驱动在保持既有语义（单域有界、失败告警、
rc 真实）的前提下补三件事：
  ① **指纹跳过**：`git HEAD + state 文件 mtime/size` 未变且上次成功 ⟹ 直接复用缓存
     （默认最长 7 天强制重跑，`--max-age-days` 可调；`--force` 立即重跑）；
  ② **逐域计时**：日志行 `domain=... rc=... sec=... verdict=...`（原只有 rc）；
  ③ 缓存/告警原子写（tmp + replace），失败才写 alert，成功即删。

调用：`bash scripts/gk_audit_cron.sh`（cron no_agent 作业体），env 兼容：
  GK_AUDIT_CRON_DOMAINS / GK_AUDIT_CRON_TIMEOUT / GK_AUDIT_CRON_FORCE
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_DOMAINS = ("state", "docs", "memory")


def _fingerprint(skill_dir: str, state_file: str) -> str:
    """git HEAD + state mtime_ns/size（docs/references 为 tracked ⟹ HEAD 已覆盖）。"""
    try:
        head = subprocess.check_output(
            ["git", "-C", skill_dir, "rev-parse", "HEAD"], text=True,
            stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, OSError):
        head = "no-git"
    parts = ["head=" + head]
    try:
        st = os.stat(state_file)
        parts.append("state=%d:%d" % (st.st_mtime_ns, st.st_size))
    except OSError:
        parts.append("state=missing")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _verdict(raw: str) -> str:
    """与 gk_audit_cron.sh 旧判据逐字同义（mismatch 不算失败）。"""
    try:
        d = json.loads(raw.strip())
    except ValueError:
        return "bad:unparseable"
    if not isinstance(d, dict):
        return "bad:not-object"
    if d.get("ok") is False:
        return "bad:" + str(d.get("error") or "ok=false")[:80]
    r = d.get("result") if isinstance(d.get("result"), dict) else {}
    for k in ("heredoc_error", "error"):
        if r.get(k):
            return "bad:" + str(r[k])[:80]
    return "ok"


def _read_cache(path: Path) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def run(skill_dir: str, domains, timeout: int, cache_path: Path, alert_path: Path,
        log_path: Path, state_file: str, max_age_days: float = 7.0,
        force: bool = False) -> dict:
    started = time.time()
    fp = _fingerprint(skill_dir, state_file)
    cache = _read_cache(cache_path)
    age_days = (time.time() - float(cache.get("ts") or 0)) / 86400.0
    if (not force and cache.get("fingerprint") == fp and cache.get("all_ok")
            and age_days < max_age_days):
        line = "=== %s audit-cron skipped (unchanged, age=%.2fd) ===" % (
            time.strftime("%Y-%m-%dT%H:%M:%S%z"), age_days)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return {"ok": True, "skipped": True, "reason": "unchanged",
                "fingerprint": fp, "age_days": round(age_days, 3),
                "results": cache.get("results", {})}
    cli = str(Path(skill_dir) / "gatekeeper-cli.sh")
    results, failed = {}, []
    with log_path.open("a", encoding="utf-8") as f:
        f.write("=== %s audit-cron start (domains=%s fp=%s) ===\n"
                % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), " ".join(domains), fp[:12]))
        for d in domains:
            t0 = time.time()
            try:
                r = subprocess.run(["bash", cli, "audit", "--" + d], cwd=skill_dir,
                                   capture_output=True, text=True, timeout=timeout)
                rc, out = r.returncode, (r.stdout or "")
            except subprocess.TimeoutExpired:
                rc, out = 124, ""
            sec = round(time.time() - t0, 1)
            last = out.strip().splitlines()[-1] if out.strip() else ""
            v = _verdict(last) if rc == 0 else "rc=%d" % rc
            ok = (rc == 0 and v == "ok")
            if not ok:
                failed.append("%s(%s)" % (d, v))
            results[d] = {"rc": rc, "verdict": v, "sec": sec,
                          "bytes": len(out.encode("utf-8")),
                          "last": last[:400]}
            f.write("--- domain=%s rc=%d sec=%s verdict=%s\n" % (d, rc, sec, v))
        f.write("=== %s audit-cron exit=%d ===\n"
                % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), 1 if failed else 0))
    all_ok = not failed
    _write_atomic(cache_path, {"fingerprint": fp, "ts": time.time(),
                               "all_ok": all_ok, "results": results})
    if all_ok:
        try:
            alert_path.unlink()
        except OSError:
            pass
    else:
        _write_atomic(alert_path, {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                   "rc": 1, "failed_domains": " ".join(failed),
                                   "log": str(log_path), "state": state_file})
    return {"ok": all_ok, "skipped": False, "fingerprint": fp,
            "failed_domains": failed, "results": results,
            "elapsed_s": round(time.time() - started, 1)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill-dir", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--domains", default=os.environ.get("GK_AUDIT_CRON_DOMAINS",
                                                        " ".join(DEFAULT_DOMAINS)))
    ap.add_argument("--timeout", type=int,
                    default=int(os.environ.get("GK_AUDIT_CRON_TIMEOUT", "600")))
    ap.add_argument("--max-age-days", type=float, default=7.0)
    ap.add_argument("--force", action="store_true",
                    default=os.environ.get("GK_AUDIT_CRON_FORCE") == "1")
    a = ap.parse_args(argv)
    home = Path(os.environ.get("HOME") or str(Path.home()))
    state_file = os.environ.get("STATE_FILE") or str(home / ".gatekeeper.state")
    domains = [x for x in a.domains.replace(",", " ").split() if x]
    out = run(a.skill_dir, domains, a.timeout,
              home / ".gatekeeper" / "audit-cron.cache.json",
              home / ".gatekeeper" / "audit-cron.alert.json",
              home / ".gatekeeper" / "audit-cron.log",
              state_file, a.max_age_days, a.force)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
