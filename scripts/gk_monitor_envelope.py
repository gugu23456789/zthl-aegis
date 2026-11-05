#!/usr/bin/env python3
"""subagent ECC 信封校验（自 `gatekeeper-cli.sh::cmd_monitor` 两个内联块下沉，2026-11-04）。

stdout 契约与内联块**逐字一致**（bash 侧按 stdout 字面判，不看退出码语义）：

  validate  stdin = ECC JSON ⟹ 结构合法打印 `VALID`；不合法**无输出** + 非零退出
  hmac      stdin = ECC JSON + env `SUBAGENT_ID` / `GATEKEEPER_HMAC_KEY`
            ⟹ `valid` / `no_hmac` / `invalid`；异常时无输出 + 非零退出
            （bash 侧 `|| echo "skip"` 兜底，与内联实现一致）

为什么同文件：两块原本各自内联一份**逐字相同**的 pydantic 模型（≈1.1 KB × 2）。合成一个文件后
模型只留一处 —— 否则任一侧改字段就会形成第二份 schema（漂移面），而两份都会在运行期生效。
"""
import json
import os
import sys


def _model():
    """pydantic 信封模型（运行时导入：与内联块一致，缺依赖时 fail-loud 无输出）。"""
    from typing import Literal, Optional

    from pydantic import BaseModel, Field

    class E(BaseModel):
        file: str
        lines: str
        status: Literal['confirmed', 'suspect']
        note: Optional[str] = None

    class F(BaseModel):
        worked: list[str] = Field(default_factory=list)
        failed: list[str] = Field(default_factory=list)
        not_tried: list[str] = Field(default_factory=list)

    class A(BaseModel):
        tool: str
        path: str
        reason: str
        timestamp: str

    class O(BaseModel):
        mode: str = 'subagent'
        subagent_id: str
        nonce: str
        timestamp: str
        task: str
        conclusion: str
        evidence: list[E] = Field(default_factory=list)
        findings: F = Field(default_factory=F)
        next_steps: list[str] = Field(default_factory=list)
        confidence: Literal['high', 'medium', 'low'] = 'medium'
        tools_used: list[str] = Field(default_factory=list)
        guardrail: str = 'passed'
        turns: int = 0
        total_items: int = 0
        token_budget: Optional[int] = None
        total_tokens: int = 0
        item_budget: Optional[int] = None
        budget_status: str = 'ok'
        hmac: Optional[str] = None
        jwt_token: Optional[str] = None
        access_violations: list[A] = Field(default_factory=list)
        overall_score: Optional[float] = None
        verdicts: dict = Field(default_factory=dict)
        vocab_violations: list[dict] = Field(default_factory=list)
        seven_dim_score: dict = Field(default_factory=dict)
        challenges: list[str] = Field(default_factory=list)
        slashed: list[str] = Field(default_factory=list)
        kept: list[str] = Field(default_factory=list)
        agent_payload: dict = Field(default_factory=dict)
        gx_status: dict = Field(default_factory=dict)
        verification: dict = Field(default_factory=dict)
        evidence_anchor: dict = Field(default_factory=dict)
        agent_identity: dict = Field(default_factory=dict)
        token_usage: dict = Field(default_factory=dict)
        assertions: list[dict] = Field(default_factory=list)
        tool_call_count: int = 0

    return O


def validate(raw: str) -> int:
    """结构校验：合法 ⟹ 打印 `VALID` 返回 0；不合法 ⟹ 无输出、返回 1。"""
    try:
        O = _model()
        O(**json.loads(raw))
    except Exception as e:  # 与内联块一致：异常只走 stderr（bash 侧 2>/dev/null 吞掉）
        print("%s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1
    print('VALID')
    return 0


def hmac_status(raw: str) -> int:
    """HMAC 三态：`valid` / `no_hmac` / `invalid`；异常 ⟹ 无输出、返回 1。

    签名口径（**勿改**）：payload 用磁盘上的**原始键序**，去掉 hmac/jwt_token，
    紧凑序列化后 HMAC-SHA256；64-hex 主密钥按 bytes.fromhex 解释（与 runner 同构）。
    """
    import hashlib
    import hmac

    try:
        O = _model()
        raw_obj = json.loads(raw)
        out = O(**raw_obj)
        sub_id = os.environ['SUBAGENT_ID']
        master = os.environ['GATEKEEPER_HMAC_KEY']
    except Exception as e:
        print("%s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1
    del sub_id  # 与内联块一致：sub_id 可预测，禁止参与派生（仅作环境契约存在性检查）
    sk = bytes.fromhex(master) if len(master) == 64 else master.encode()
    data = dict(raw_obj)
    data.pop('hmac', None)
    data.pop('jwt_token', None)
    expected = hmac.new(sk, json.dumps(data, separators=(',', ':'), default=str).encode(),
                        hashlib.sha256).hexdigest()
    if out.hmac == expected:
        print('valid')
        return 0
    if not out.hmac:
        print('no_hmac')
        return 0
    print('invalid')
    return 0


def main(argv=None) -> int:
    mode = (argv or sys.argv[1:] or [""])[0]
    raw = sys.stdin.read()
    if mode == "validate":
        return validate(raw)
    if mode == "hmac":
        return hmac_status(raw)
    print("usage: gk_monitor_envelope.py validate|hmac", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
