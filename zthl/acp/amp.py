"""AMP（Agent Monitoring Protocol）兼容层 —— 规范层。

唯一源
------
- `zthl-harness-adapter` 计划 §2.7「AMP 兼容层设计」（六类日志 / 数据源映射 / 落点）。
- ACPs v2.2.0 `acps-specs/09-ACPs-spec-AMP/ACPs-spec-AMP.md`（本地 clone tag `v2.2.0`）：
  `LogRecord`（§5.1.2）、`logId` 幂等键（§5.1.3）、六类 Body（§5.2-5.6）。

落点与形态（计划 §2.7）
-----------------------
`~/.zthl/amp/{heartbeat,metrics,access,message,audit,system}.log`，每类一文件，
JSONL，默认 **7 天轮转**。**不部署官方 `monitor-server`**（零服务依赖裁定）——只保证
schema 严格对齐，使文件可被官方栈消费。

环境开关
--------
- `GK_AMP=0`            全局关闭（默认 `1`）
- `GK_AMP_DIR`          落点覆盖（默认 `~/.zthl/amp`；`GK_ZTHL_HOME` 可改 `~/.zthl` 根）
- `GK_AMP_RETENTION_DAYS` 轮转阈值（默认 `7`）
- `GK_AIC`              智能体身份码；缺省占位并显式标注未注册（真 AIC = ZH3-H14b）
- `_AUDIT_KEY_DIR`      审计日志 Ed25519 私钥目录（复用 `gk_budget_ledger._sign` 单源）

纪律
----
1. **遥测不得阻断调用**：`write()` / `emit()` 内所有异常静默。
2. **不落正文**：记录只含结构性元数据（工具名 / 判定 / 状态码 / 耗时），不含命令正文与文件内容。
3. `audit` 类按规范**必须签名**；无 audit key 时**不冒充已签**，显式回标
   `attributes["zthl.integrity"] = "unsigned(no-audit-key)"`。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional

__all__ = [
    "SCHEMA_VERSION", "LOG_TYPES", "SEVERITY_NUMBER",
    "amp_dir", "enabled", "now_iso",
    "new_log_id", "new_trace_id", "new_span_id",
    "build", "emit", "write", "rotate", "query", "sign_record",
]

SCHEMA_VERSION = "1.0.0"

#: 六类日志（spec `ACPsLogType`，顺序同 §4.1）
LOG_TYPES = ("heartbeat", "metrics", "access", "message", "audit", "system")

#: `SeverityNumber`：每组基本级别（同 OTel / spec §5.1.2）
SEVERITY_NUMBER = {
    "TRACE": 1, "DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21,
}

DEFAULT_AIC = "zthl-core-local"
DEFAULT_RETENTION_DAYS = 7
_DEFAULT_SERVICE = "spz-gatekeeper-r-sequence"


# ── 落点与环境 ────────────────────────────────────────────────────────────────
def amp_dir() -> Path:
    """AMP 数据目录。

    默认 = `<技能仓>/.zthl/amp`（**不跟随 `Path.home()`**：本仓 hook 实际由 `wsl bash` 以
    root 启动，`Path.home()` 会落到 `/root` ⟹ 观测面随宿主/WSL 用户漂移，2026-10-26 实测踩中）。
    `GK_AMP_DIR` > `GK_ZTHL_HOME` > 仓内默认。
    """
    d = os.environ.get("GK_AMP_DIR", "").strip()
    if d:
        return Path(d)
    home = os.environ.get("GK_ZTHL_HOME", "").strip()
    base = Path(home) if home else (Path(__file__).resolve().parent.parent.parent / ".zthl")
    return base / "amp"


def enabled() -> bool:
    return os.environ.get("GK_AMP", "1") != "0"


def _retention_days() -> int:
    try:
        return max(1, int(os.environ.get("GK_AMP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)))
    except ValueError:
        return DEFAULT_RETENTION_DAYS


def now_iso(ts: Optional[float] = None) -> str:
    """ISO 8601 带时区（`2026-10-26T17:18:11+0800`）。"""
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts if ts is not None else time.time()))


# ── 标识符（spec §5.1.2 / §5.1.3）────────────────────────────────────────────
def new_log_id() -> str:
    """UUIDv7：48bit 毫秒时间戳 + 版本/变体位 + 随机位（§5.1.3 推荐形态）。"""
    ms = int(time.time() * 1000) & ((1 << 48) - 1)
    b = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    b[6] = (b[6] & 0x0F) | 0x70          # version 7
    b[8] = (b[8] & 0x3F) | 0x80          # variant 10xx
    h = bytes(b).hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def new_trace_id() -> str:
    """128bit 随机 → 32 hex（无连字符）。"""
    return uuid.UUID(bytes=os.urandom(16)).hex


def new_span_id() -> str:
    """64bit 随机 → 16 hex。"""
    return os.urandom(8).hex()


# ── LogRecord 构造（spec §5.1.2）──────────────────────────────────────────────
def _default_resource() -> dict:
    res = {
        "service.name": os.environ.get("GK_AMP_SERVICE", _DEFAULT_SERVICE),
        "deployment.environment.name": os.environ.get("GK_AMP_ENV", "local"),
    }
    # host.name 默认不采集（本机主机名常含个人信息）；需要时显式开启
    if os.environ.get("GK_AMP_HOSTNAME", "") == "1":
        host = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME")
        if host:
            res["host.name"] = host
    return res


def build(
    log_type: str,
    body: Any,
    *,
    aic: Optional[str] = None,
    timestamp: Optional[str] = None,
    observed_timestamp: Optional[str] = None,
    log_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    parent_span_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    severity: str = "INFO",
    resource: Optional[dict] = None,
    attributes: Optional[dict] = None,
    integrity: Optional[dict] = None,
) -> dict:
    """构造一条 `LogRecord`。`log_type` 不在六类内 ⟹ `ValueError`（fail-loud）。"""
    if log_type not in LOG_TYPES:
        raise ValueError(f"unknown AMP logType: {log_type!r} (expected one of {LOG_TYPES})")
    sev = (severity or "INFO").upper()
    rec: dict = {
        "schemaVersion": SCHEMA_VERSION,
        "timestamp": timestamp or now_iso(),
        "aic": (aic or os.environ.get("GK_AIC", "") or DEFAULT_AIC),
        "logId": log_id or new_log_id(),
        "logType": log_type,
        "severityText": sev,
        "severityNumber": SEVERITY_NUMBER.get(sev, SEVERITY_NUMBER["INFO"]),
        "body": body if body is not None else {},
        "resource": resource or _default_resource(),
    }
    # 缺省 AIC 是占位符 ⟹ 显式标注，不冒充已注册（真 AIC = ZH3-H14b）
    if not (aic or os.environ.get("GK_AIC", "")):
        rec.setdefault("attributes", {})["zthl.aic.registered"] = False
    if observed_timestamp:
        rec["observedTimestamp"] = observed_timestamp
    if trace_id:
        rec["traceId"] = trace_id
    if span_id:
        rec["spanId"] = span_id
    if parent_span_id:
        rec["parentSpanId"] = parent_span_id
    if correlation_id:
        rec["correlationId"] = correlation_id
    if attributes:
        rec.setdefault("attributes", {}).update(attributes)
    if integrity:
        rec["integrity"] = integrity
    return rec


# ── 签名（spec §5.6.1「审计日志必须签名」）────────────────────────────────────
# 单源复用：密钥载入/签名原语来自既有 `gk_budget_ledger._sign`（禁第三实现）。
_SIGN_SCOPE_KEYS = ("timestamp", "aic", "logId", "traceId", "spanId",
                    "parentSpanId", "correlationId", "logType", "body")


def _canonical_scope(rec: dict) -> bytes:
    """签名范围 = 顶层公共字段 + 整个 body；JCS 近似（键升序、无空白、UTF-8）。"""
    scope = {k: rec[k] for k in _SIGN_SCOPE_KEYS if k in rec}
    return json.dumps(scope, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sign_digest(digest: str, key_dir: Optional[str]):
    """→ `(mode, sig_b64, key_fp)`。复用既有审计钥签名原语；不可用则 `("sha256", "", "")`。"""
    try:
        scripts = Path(__file__).resolve().parent.parent.parent / "scripts"
        if str(scripts) not in sys.path:
            sys.path.insert(0, str(scripts))
        from gk_budget_ledger import _sign, _key_dir  # noqa: PLC0415（懒加载，避重依赖）
        return _sign(digest, _key_dir(key_dir or ""))
    except Exception:
        return "sha256", "", ""


def sign_record(rec: dict, key_dir: Optional[str] = None) -> dict:
    """就地补 `integrity`（EdDSA）。无钥 ⟹ 显式回标未签名，**不冒充已签**。"""
    if rec.get("integrity"):
        return rec
    try:
        digest = hashlib.sha256(_canonical_scope(rec)).hexdigest()
        mode, sig, fp = _sign_digest(digest, key_dir)
    except Exception:
        mode, sig, fp = "sha256", "", ""
    if mode != "ed25519":
        rec.setdefault("attributes", {})["zthl.integrity"] = "unsigned(no-audit-key)"
        return rec
    rec["integrity"] = {"alg": "EdDSA", "kid": fp, "sig": sig}
    return rec


# ── 写入与轮转（计划 §2.7「六类各一文件，默认 7 天轮转」）──────────────────────
def rotate(path: Path, days: Optional[int] = None) -> Optional[Path]:
    """文件 mtime 超过保留期 ⟹ 改名归档（`access.log` → `access.log.20261019T101500`）。"""
    try:
        st = path.stat()
    except OSError:
        return None
    if st.st_size == 0:
        return None
    if time.time() - st.st_mtime < (days or _retention_days()) * 86400:
        return None
    dst = path.with_name(f"{path.name}.{time.strftime('%Y%m%dT%H%M%S', time.localtime(st.st_mtime))}")
    try:
        os.replace(path, dst)
        return dst
    except OSError:
        return None


def write(rec: dict) -> Optional[Path]:
    """追加一条记录到 `<logType>.log`。任何异常静默（遥测不得阻断调用）。"""
    if not enabled():
        return None
    try:
        d = amp_dir()
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{rec['logType']}.log"
        rotate(p)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        return p
    except Exception:
        return None


def emit(log_type: str, body: Any, *, sign: bool = False, **kw) -> Optional[dict]:
    """构造 + （审计类）签名 + 写入。返回落盘记录；关闭/失败时 `None`。"""
    if not enabled():
        return None
    try:
        rec = build(log_type, body, **kw)
        if sign or log_type == "audit":
            sign_record(rec)
        write(rec)
        return rec
    except Exception:
        return None


# ── 读面（查询；计划 §2.7「查询面」的库内实现，CLI 见 gk_amp_query.py）────────
def _parse_since(since: Any) -> Optional[float]:
    """`since` 支持 epoch 秒 / `30m` `2h` `7d` / ISO 8601。解析失败 ⟹ `None`（不过滤）。"""
    if since is None or since == "":
        return None
    if isinstance(since, (int, float)):
        return float(since)
    s = str(since).strip()
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(s) > 1 and s[-1] in unit and s[:-1].isdigit():
        return time.time() - int(s[:-1]) * unit[s[-1]]
    try:
        from datetime import datetime
        t = s
        if len(t) >= 5 and t[-5] in "+-" and t[-4:].isdigit():   # +0800 → +08:00
            t = t[:-2] + ":" + t[-2:]
        return datetime.fromisoformat(t).timestamp()
    except Exception:
        return None


def _dig(rec: Any, dotted: str) -> Any:
    """点号路径取值；**键名自身含点**时按最长前缀优先（如 `attributes.zthl.decision`）。"""
    cur, parts, i = rec, dotted.split("."), 0
    while i < len(parts) and isinstance(cur, dict):
        for j in range(len(parts), i, -1):
            key = ".".join(parts[i:j])
            if key in cur:
                cur, i = cur[key], j
                break
        else:
            return None
    return None if i < len(parts) else cur


def query(
    log_type: Optional[str] = None,
    *,
    since: Any = None,
    limit: int = 200,
    where: Optional[dict] = None,
    root: Optional[Path] = None,
) -> list:
    """读回记录（时间升序，取最近 `limit` 条）。`where` 支持点号路径，值相等即命中。"""
    types: Iterable[str] = (log_type,) if log_type else LOG_TYPES
    cutoff = _parse_since(since)
    base = Path(root) if root else amp_dir()
    out = []
    for t in types:
        if t not in LOG_TYPES:
            raise ValueError(f"unknown AMP logType: {t!r}")
        p = base / f"{t}.log"
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if cutoff is not None:
                ts = _parse_since(rec.get("timestamp", ""))
                if ts is not None and ts < cutoff:
                    continue
            if where and any(_dig(rec, k) != v for k, v in where.items()):
                continue
            out.append(rec)
    out.sort(key=lambda r: str(r.get("timestamp", "")))
    return out[-limit:] if limit and limit > 0 else out
