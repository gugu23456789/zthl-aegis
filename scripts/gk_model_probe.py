#!/usr/bin/env python3
"""模型版本探针（W2A §6.1 / §6.3(3) F1b；`ECC-75F6A2BB7F2B`）。

**问题**：判 stride / 相位周期 `S` 等**版本相关量**时**禁据 alias 推断** —— 模型名可**沿用同一
alias 仅换后端**（上游换代不改名）。`S` 是 per-model 的（DeepSeek-V4 `{4,128}` / V4.1 `{2}`），
据 alias 预设 `S` ⟹ 功效门 `N_LENGTHS ≥ 2S` 与相位装配全踩空。

**两条实测通道**（`resolve` 依次尝试）：
  1. **元数据层** —— `system_fingerprint`（OpenAI 兼容；后端一换即变）= 版本**判别量**；
     若操作方给出 `fingerprint → S` 表 ⟹ 直接定 `S`。`model` 字段（alias）**只记录、不作判据**。
  2. **行为层回退** —— 给定逐长度 `L=0..n-1` 的观测序列，测**最短周期** `S`（不依赖任何名字）。

**fail-loud**：两通道都定不出 `S` ⟹ `resolved=false`、`stride=None`（下游**不得**静默假设 `S=2`）。

纯函数、无 API、无外链（`meta` / 序列由调用方注入）⟹ 可单测。**禁**直接执行（技能内置 cmd 路由）。
"""
import json
import sys

# 模型特异候选：来自厂商技术报告与本仓臂定义；**随模型退役即失效** ⟹ 仅作候选，
# 不得当正源钉死（判 S 仍须 fingerprint 表或行为层序列）。
CANDIDATE_STRIDES = (2, 3, 4, 5, 6, 8, 12, 16, 24, 32, 128)


def normalize_meta(payload):
    """从 `/models` 列表 或 `chat/completions` 响应里抽 `model_id` / `model_ids` / `fingerprint`。

    `fingerprint` 取 `system_fingerprint`（取不到 ⟹ `None`）。**alias（`model`）只作记录**，
    本模块**不**据它设 `resolved`（调用方亦不得据它推 `S`）。
    """
    if not isinstance(payload, dict):
        return {"model_id": None, "model_ids": [], "fingerprint": None}
    data = payload.get("data")
    if isinstance(data, list):
        ids = [d.get("id") for d in data if isinstance(d, dict) and d.get("id")]
        return {"model_id": None, "model_ids": ids, "fingerprint": None}
    mid = payload.get("model")
    fp = payload.get("system_fingerprint")
    return {"model_id": mid if isinstance(mid, str) else None,
            "model_ids": [],
            "fingerprint": fp if isinstance(fp, str) and fp else None}


def stride_from_series(series, candidates=CANDIDATE_STRIDES):
    """行为层：给定逐长度 `L=0..n-1` 的观测，取**最短**周期 `p ∈ candidates`
    满足 `series[i] == series[i+p]`（∀ i）。无候选匹配 ⟹ `stride=None`（fail-loud，不猜）。
    """
    n = len(series) if isinstance(series, (list, tuple)) else 0
    if n < 2:
        return {"stride": None, "n": n}
    for p in sorted(int(c) for c in candidates):
        if 0 < p < n and all(series[i] == series[i + p] for i in range(n - p)):
            return {"stride": p, "n": n}
    return {"stride": None, "n": n}


def resolve(*, meta=None, series=None, candidates=CANDIDATE_STRIDES, known_strides=None):
    """定 `S`：元数据层（`fingerprint` 表）优先，行为层回退；都定不出 ⟹ `resolved=false`。

    `resolved=false` 是**契约**：下游（相位装配 / 功效门）须停止并索要真值，
    **不得**回落 `S=2`（alias 换后端不换名 ⟹ alias 不可作版本判据）。
    """
    m = normalize_meta(meta)
    fp = m["fingerprint"]
    stride = None
    source = None
    if known_strides and fp and fp in known_strides:
        try:
            stride = int(known_strides[fp])
            source = "fingerprint-table"
        except (TypeError, ValueError):
            stride = None
            source = None
    if stride is None and series is not None:
        st = stride_from_series(series, candidates)
        if st["stride"] is not None:
            stride = st["stride"]
            source = "behavioral"
    return {"model_id": m["model_id"], "model_ids": m["model_ids"], "fingerprint": fp,
            "stride": stride, "source": source, "resolved": stride is not None,
            "candidates": list(candidates)}


def main(argv):
    """薄 CLI shim（经 `gatekeeper-cli.sh model-probe` 调用）：把 JSON 参数折进 `resolve`。"""
    kw = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--meta", "--series", "--known-strides", "--candidates") and i + 1 < len(argv):
            kw[a[2:].replace("-", "_")] = json.loads(argv[i + 1])
            i += 2
        else:
            sys.stderr.write('{"ok":false,"error":"unknown arg: %s"}\n' % a)
            return 2
    print(json.dumps(resolve(**kw), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
