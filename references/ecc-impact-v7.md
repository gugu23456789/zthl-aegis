# ECC-IMPACT: 飞轮 v7 实施计划裁定

**ECO-EDIT 7D 评分**:
| 维度 | 分值 | 依据 |
|:--|:--:|:--|
| Scope (范围) | 85 | 四层+ATH 在设计范围内，P0/P1/P2 清晰 |
| Evidence (证据) | 75 | rg/论文/API 测试/ATH 源码四源交叉验证 |
| Assumptions (假设) | 70 | ATH Native 可行 (ath-sdk 验证)，logprobs 已验证 |
| Recovery (回退) | 85 | 所有变更增量可逆 |
| References (参考) | 90 | 4 论文 + 4 ATH 组件 + API 实测 |
| Bias (偏差) | 75 | 优先级倒挂已修正，ATH 误判已修正 |
| Cost (成本) | 80 | CLI 级改动，零新基础设施 |

**综合**: 80/100 — 设计成熟可执行

**裁定**: 推进 ECO-AUDIT。从 P0 项开始实施：
- R-seq 1: HMAC → JWT ES256 迁移
- R-seq 2: STATE_MISMATCH advance 门禁
- R-seq 3: JTI nonce 消费端校验
- R-seq 4: 熵监视器违规率计数

<!-- DECISION score=0.80 verdicts={"F1": "PASS", "F2": "PASS", "F3": "WARN", "F4": "PASS", "F5": "PASS", "F6": "PASS", "F7": "PASS"} decision=Proceed to ECO-AUDIT. P0: JWT migration + STATE_MISMATCH + JTI + entropy monitor. -->
