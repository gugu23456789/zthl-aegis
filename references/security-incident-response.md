# 密钥泄露应急处置流程（BP.08.05 对照）

> 2026-08-13 依据零信任国标草案《网络安全技术 零信任能力成熟度模型及评价方法》BP.08.05 制度要求补建。
> 适用：gatekeeper CLI 单机本地环境（`.keys/` 目录 = `~/.trae/skills/spz-gatekeeper-r-sequence/.keys/`）。

## 泄露识别信号（触发条件）

| 信号 | 来源 | 优先级 |
|:--|:--|:--|
| `KEY INTEGRITY COMPROMISED`（key-meta.json sha256 失配） | `audit --key status` / rotate 前置检查 | 🔴 立即 |
| `pubkey_fingerprint_mismatch`（key-meta 指纹 vs 磁盘公钥） | `_verify_key_integrity` | 🔴 立即 |
| subagent `.keys/` 访问违规（access_violations 计入熵） | `gk_gate_entropy.py` + `subagent_runner.py` 硬阻断 | 🟡 升级 |
| 私钥文件权限异常（非 600）或出现在非 `.keys/` 目录 | 人工巡检 / self-check | 🟡 |

## 响应步骤（泄漏识别 → 报告 → revoke → rotate → 验证 → 审计）

```
1. 识别     确认上述任一信号（audit --key status / self-check / 红队 RED-POSTEX）
2. 隔离     立即 `audit --key revoke <key_type>`   # 私钥 shred 销毁 + 公钥移 .revoked/（NIST §Destroyed）
             （revoke 自动扫描 gate_data 中 .keys/ 违规作为 compromise_evidence）
3. 重建     `audit --key rotate <key_type>`        # CapiscIO 重叠轮换：新 key 验证后旧 .bak 退役
4. 验证     `audit --key status` + `self-check`    # 确认 key-integrity + fingerprint 恢复 ok
5. 审计     `audit --key status` 查 key_rotation_log_tail（revoke/rotate 事件留痕）
             `audit --state` 确认 human_resolutions 签名仍可验（audit 公钥线）
6. 记录     写入 ECC-FINDING（事件时间线 + 波及范围 + 处置动作）
```

## 与现有机制的衔接

- **revoke**（`audit --key revoke`）：已实现 shred + `.revoked/` 隔离 + compromise_evidence 扫描 + key_rotation_log 留痕
- **rotate**（`audit --key rotate <type> [auto|manual]`）：CapiscIO 重叠轮换，7 天 .bak 宽限期
- **完整性与指纹**：`key-meta.json` sha256（`.key-integrity.sha256`）+ 公钥指纹（rotate 前置校验）
- **不可否认性**：human_resolutions 终裁签名走 audit 密钥（30d 轮换）+ 真验签（2026-08-13 落地）
- **周期轮换**：context=1d / audit=30d 自动（cmd_advance 检查过期），事件写入 `gate_data.key_rotation_log[]`

## 事后恢复要点

- 泄露密钥签的存量记录：audit 公钥线记录可在 7 天内用 `.bak` 公钥验（CapiscIO 宽限期）；超期需 `key_rotation_log` 找回归档公钥（或从 `.revoked/`）
- 所有 `.bak`/`.revoked` 材料按 NIST 状态机（deactivated/revoked → destroyed）生命周期管理，`audit --key destroy` 清理
