#!/usr/bin/env python3
"""gk_red_stand.py — 红队**常态化攻击机**（standing red-team attack driver，2026-11-05）。

与 `gk_red_keyleak.py` 的分工
============================
· `gk_red_keyleak.py` = **向量实现**（每个泄漏面一条判据，CI 用，确定性、离线）。
· 本脚本 = **攻击循环**：把向量跑成一次「攻击波次」，落台账、算连击（streak）、到阈值升级。
  它不是"再写一遍检查"，而是让检查**持续发生且可追踪**（cron 24h 一波）。

机制
====
1. **向量注册表**：`VECTORS` 是数据（id → callable），加新攻击面 = 加一行；
2. **波次台账**：每次结果 append 到 `~/.gatekeeper/red-history.jsonl`（`GK_RED_HISTORY` 可覆盖，
   保留最近 500 行）——「上次红是什么时候、红了多少次」可查；
3. **连击升级**：连续 `streak >= 3` 波仍有 HIGH ⟹ 输出 `escalate=true` + 登记命令建议
   （默认**不**自动写 finding 台账，避免 cron 污染；`--register` 给出显式命令）；
4. **cron 常态化**：由 `gatekeeper-cli.sh cron create red-stand ... --script scripts/gk_red_stand.py
   --no-agent` 注册，tick 每 24h 打一波（`cron-stand-install` 见 README/本文末尾）。

用法
====
  python3 scripts/gk_red_stand.py            # 跑一波（人读）
  python3 scripts/gk_red_stand.py --json     # 机器读
  python3 scripts/gk_red_stand.py --strict   # 有 HIGH ⟹ 退出 1（CI 用）
  python3 scripts/gk_red_stand.py --register # 额外打印 finding 登记命令（不执行）

退出码：0 = 无 HIGH（或非 --strict）；1 = `--strict` 且有 HIGH。
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

HIGH, MEDIUM, INFO = "high", "medium", "info"
MAX_LINES = 500
HIGH_STREAK_ESCALATE = 3


def ledger_path() -> Path:
    p = (os.environ.get("GK_RED_HISTORY") or "").strip()
    return Path(p) if p else Path.home() / ".gatekeeper" / "red-history.jsonl"


# ── 向量 ───────────────────────────────────────────────────────────────────
def vector_keyleak():
    """V1：密钥泄露向量（argv / xtrace / history / 日志 / 排除面）。"""
    import gk_red_keyleak
    r = gk_red_keyleak.run()
    return r["findings"]


def vector_state_integrity():
    """V2：state 面（未签名决议 / 无校验和 / 注入倾向字段）—— 复用 RED 序列的既有探针。"""
    try:
        import _red_attacks as R
    except Exception as e:  # noqa: BLE001 — 依赖缺失不冒充「安全」
        return [{"id": "V2-UNAVAILABLE", "severity": INFO,
                 "title": "state 向量不可用", "detail": "%s: %s" % (type(e).__name__, e)}]
    out = []
    for fn in ("red_scope", "red_postex"):
        try:
            for f in getattr(R, fn)() or []:
                sev = f.get("severity")
                out.append({"id": f.get("id") or fn, "severity": sev if sev in (HIGH, MEDIUM, INFO) else INFO,
                            "title": f.get("title", ""), "detail": f.get("description", "")})
        except Exception as e:  # noqa: BLE001
            out.append({"id": "V2-%s-ERR" % fn, "severity": INFO,
                        "title": "%s 探针异常" % fn, "detail": str(e)})
    return out


def vector_bak_age():
    """V3：`.bak` 是否超出轮换宽限期（**策略对齐**，不是数个数）。

    轮换机制（`audit --key rotate`）自带 `find .keys -name '*.bak' -mtime +7 -exec rm`；
    本向量检查这条策略**是否真的生效**（drvfs 上 mtime/权限都可能异常）。
    """
    grace = 7.0
    try:
        grace = float(os.environ.get("GK_KEY_BAK_GRACE_DAYS", "7"))
    except ValueError:
        pass
    kd = ROOT / ".keys"
    if not kd.is_dir():
        return []
    now, stale = time.time(), []
    for p in kd.glob("*.bak"):
        try:
            if (now - p.stat().st_mtime) / 86400.0 > grace:
                stale.append(p.name)
        except OSError:
            continue
    if not stale:
        return []
    return [{"id": "V3-BAK-STALE", "severity": MEDIUM,
             "title": ".bak 超出 %g 天宽限期（轮换清理未生效）" % grace,
             "detail": "%d 份：%s" % (len(stale), ", ".join(sorted(stale)[:5]))}]


VECTORS = (
    ("V1-keyleak", vector_keyleak),
    ("V2-state-integrity", vector_state_integrity),
    ("V3-bak-age", vector_bak_age),
)


# ── 台账 / 连击 ─────────────────────────────────────────────────────────────
def read_history(path=None) -> list:
    p = path or ledger_path()
    out = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if isinstance(d, dict) and "high" in d:
                out.append(d)
    except OSError:
        return []
    return out


def append_history(row: dict, path=None) -> Path:
    p = path or ledger_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        rows = read_history(p)[-MAX_LINES:] + [row]
        tmp = p.with_name(p.name + ".tmp-%d" % os.getpid())
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
        os.replace(tmp, p)
    except OSError:
        pass                        # 台账写不进不得影响攻击本身
    return p


def _streak(rows: list) -> int:
    """连续 HIGH 波次数（从末尾往前数）。"""
    n = 0
    for r in reversed(rows):
        if int(r.get("high") or 0) > 0:
            n += 1
        else:
            break
    return n


def run() -> dict:
    findings, ran = [], 0
    for _vid, fn in VECTORS:
        try:
            findings += fn() or []
            ran += 1
        except Exception as e:  # noqa: BLE001 — 向量崩溃不得吞掉其它向量
            findings.append({"id": "VECTORS-ERR", "severity": HIGH,
                             "title": "攻击向量崩溃", "detail": "%s: %s" % (type(e).__name__, e)})
    high = [f for f in findings if f["severity"] == HIGH]
    row = {"ts": int(time.time()), "high": len(high), "medium":
           len([f for f in findings if f["severity"] == MEDIUM]),
           "ids": [f["id"] for f in high]}
    path = append_history(row)
    streak = _streak(read_history(path))
    return {"ok": not high, "vectors": ran, "high": len(high),
            "medium": row["medium"], "findings": findings,
            "streak": streak, "escalate": streak >= HIGH_STREAK_ESCALATE,
            "ledger": str(path)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_red_stand.py")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="有 HIGH 时退出 1")
    ap.add_argument("--register", action="store_true", help="打印 finding 登记命令（不执行）")
    a = ap.parse_args(argv)
    r = run()
    if a.register and r["high"]:
        r["register_hint"] = (
            "python3 scripts/gk_finding.py register <state> "
            "'red-stand: 密钥/状态攻击向量 HIGH' 'red-stand'")
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("RED-STAND %s — waves=%d high=%d medium=%d streak=%d%s" % (
            "OK" if r["ok"] else "FAIL", r["vectors"], r["high"], r["medium"],
            r["streak"], "  ⟹ ESCALATE（连续 %d 波）" % r["streak"] if r["escalate"] else ""))
        for f in r["findings"]:
            print("[%s] %s %s — %s" % (f["severity"], f["id"], f["title"], f["detail"]))
        if r.get("register_hint"):
            print("登记：%s" % r["register_hint"])
    return 1 if (a.strict and r["high"]) else 0


if __name__ == "__main__":
    sys.exit(main())
