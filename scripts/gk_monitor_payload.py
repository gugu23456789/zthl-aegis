"""monitor 落库载荷（自 `gatekeeper-cli.sh::cmd_monitor` 内联块逐字下沉，2026-11-04）。

契约不变（**勿改**）：
- stdin = subagent 全量 JSON；env = `GK_PY_SCRIPTS` / `GK_PY_STATE` / `GK_TASK` /
  `GK_HMAC_VALID` / `GK_AGENT_IDENTITY` / `GK_BATCH_*` / `GK_ARM_DELTA` 等；
- 本文件是**脚本式模块**（模块级执行、读 stdin 写 state），刻意不包 `main()`：
  逐字搬运以保住 HMAC 原始键序与持锁 RMW 语义；
- 等价性由 `scripts/gk_monitor_fixture.py`（stdout + 落库 state 双产物）守护。
"""
import json,sys,os
sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])
from gk_json_utils import dump_state, state_lock
from gk_subagent_report import normalize_evidence
out=json.loads(sys.stdin.read())
# ECC-4E6D7F42CA05（2026-09-27）：本块 = 「读 state → 改（subagent_history/subagent_last/
# _sealed_agent_score → 写 state」的 RMW，此前**全程无锁** ⟹ 并发臂完成时互相覆盖
# （subagent_history 条目静默丢失）。修法 = 取锁横跨读-写；dump_state 再取锁是**可重入**的、
# 不自锁。进程退出即关 fd 释放锁（含下方 JTI_REPLAY 的早退 sys.exit）。
_lk=state_lock(os.environ['GK_PY_STATE']); _lk.__enter__()
d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
gd=d.setdefault('gate_data',{})
hist=gd.setdefault('subagent_history',[])
# ECC 4-field structured summary
# ECC-74B7327230D8（2026-09-27）：原式 e.split(':') 遇 Windows 盘符路径（C:/…/x.py:13）
#   把**盘符冒号当分隔符** ⟹ file='C'、lines 塞全路径（行号/描述错位）；渲染侧又拼回原样 ⟹
#   症状被掩盖。归一下沉到 gk_subagent_report.normalize_evidence（按**首个「冒号+数字」**切）——
#   下沉到**已跟踪**模块的唯一动机 = 内联 python 不可单测（红先行为臂须可导入）；新建模块会被
#   red-first 沙箱软链回工作树 ⟹ 假绿。⚠ 注释内**禁 ASCII 反引号**（本 payload 在 bash 双引号区内，
#   反引号触发命令替换，实测 2026-09-27；守护臂 test_gk_eval_injection.cli_double_quoted_regions_have_no_backticks）。
evidence=normalize_evidence(out.get('evidence',[]))
findings=out.get('findings',{})
if isinstance(findings,str): findings={'worked':[findings],'failed':[],'not_tried':[]}
# 2026-10-19：模型常把 findings 三键留空（实测 11/11），而其结构化区段 kept/challenges
#   已有内容 ⟹ 回填 worked/failed（slashed 是"可砍掉"，不冒充 not_tried）。原字段不丢。
if not any((findings or {}).get(k) for k in ('worked','failed','not_tried')):
  findings={'worked':list(out.get('kept',[]) or [])[:5],
            'failed':list(out.get('challenges',[]) or [])[:5],
            'not_tried':[]}
# C4（ECC-D9D2382BB535，2026-09-28）：entry 只是「小摘要投影」，**全量机检字段外置**在
#   docs/analysis/subagent/<subagent_id>.json（C5 已证 304/304 配对；实测该 .json 含
#   gx_status/verification/evidence_anchor/token_usage/agent_payload 等）。三件：
#   ② machine_check 最小摘要（**由全量派生、禁独立计算**；超 _MACHINE_CHECK_MAX_BYTES 降级）；
#   ③ _ENTRY_KEYS = 投影键集**单源**（下方自检 entry 键 ⊆ 本集，防再丢面/误加面）。
#   ⚠ 注释内禁 ASCII 反引号（本 payload 在 bash 双引号区内 ⟹ 触发命令替换）。
_MACHINE_CHECK_MAX_BYTES=512
_ENTRY_KEYS=('task','subagent_id','conclusion','kept','slashed','challenges','evidence','findings',
             'next_steps','confidence','tools_used','seven_dim_score','overall_score','verdicts',
             'vocab_violations','budget_status','total_tokens','token_budget','total_items',
             'item_budget','hmac_status','output_file','report_file','machine_check',
             'access_violations','batch_id','tier','arm_group','arm_delta','arm_obs',
             'assertions','tool_call_count')
def _mc_field(x, key):
  return (x or {}).get(key, '') if isinstance(x, dict) else ''
# 2026-10-31（owner 裁定 A）：monitor --api 的分数只进 monitor_history（advisory），复盘面
#   原来看不见它 ⟹ 把最近一条投影进机检面（score/verdict/mode/ts），与 token/guardrail 同屏。
_mh=gd.get('monitor_history') or []
_mon=_mh[-1] if isinstance(_mh,list) and _mh else {}
if not isinstance(_mon,dict): _mon={}
_mon_last={'score': _mon.get('score'), 'verdict': _mon.get('verdict'),
           'mode': _mon.get('mode'), 'ts': _mon.get('ts')} if _mon else {}
_mc={'dump_ok': True,  # C4① 落盘校验结果（落盘段已 fail-loud；此处记状态位）
     'verification': _mc_field(out.get('verification'), 'status'),
     'evidence_anchor': _mc_field(out.get('evidence_anchor'), 'status'),
     'gx_status': _mc_field(out.get('gx_status'), 'verdict'),
     'token_usage_rounds': _mc_field(out.get('token_usage'), 'rounds'),
     'guardrail': out.get('guardrail',''), 'turns': out.get('turns',0), 'mode': out.get('mode',''),
     'nonce_len': len(str(out.get('nonce','') or '')), 'timestamp': out.get('timestamp',''),
     'monitor_last': _mon_last,
     # 2026-10-31：身份验签三态（外层已 fail-closed：invalid 不会到这里）
     'agent_identity': os.environ.get('GK_AGENT_IDENTITY','unsigned')}
if len(json.dumps(_mc,ensure_ascii=False).encode())>_MACHINE_CHECK_MAX_BYTES:
  _mc={'dump_ok': True, 'verification': _mc['verification'],
       'evidence_anchor': _mc['evidence_anchor'], 'gx_status': _mc['gx_status'],
       'monitor_last': _mon_last, 'agent_identity': _mc['agent_identity']}
# §18.1（2026-10-03，ECC-5538DD07B709 RC1/N1）：批身份随派发落库（与 tier 同批补，治 ECC-489C8AE274E6）。
#   批 = 一次 MoA 派发单元；各臂由派发侧给同一 plan/窄任务/纪元桶 ⟹ 同一 batch_id。
#   无计划作用域（如 RED-SCOPE）⟹ batch_id 空串（不凭空聚类无关臂）。
#   ⚠ 本 payload 在 bash 双引号区内 ⟹ 禁 ASCII 反引号（命令替换）**且禁 ASCII 双引号**
#   （ASCII 双引号会提前闭合 python3 -c 的引号，载荷被截断 → NameError → HISTORY_WRITE_FAILED；
#    本处曾用 backslash-n 的双引号字面量踩此坑，2026-10-03 实测由 crossfull 抓到；
#    守护臂见 test_gk_moa_batch_identity.py::test_history_payload_has_no_stray_double_quote）。
from gk_moa_aggregate import compute_batch_id, plan_key_from_task, merge_sealed_agent_score, arm_score, arm_observables
_b_plan = os.environ.get('GK_BATCH_PLAN','') or plan_key_from_task(out.get('task') or os.environ.get('GK_TASK',''))
_b_narrow = os.environ.get('GK_BATCH_NARROW','')
if not _b_narrow:
  _b_narrow = chr(10).join(sorted(str(x.get('id','')) for x in (gd.get('narrow_tasks') or []) if isinstance(x,dict)))
_b_epoch = os.environ.get('GK_BATCH_EPOCH','') or None
_batch_id = compute_batch_id(_b_plan, _b_narrow, _b_epoch) if (_b_plan or _b_narrow) else ''
# W2A-P2（2026-10-16）：**消融腿**观测量 —— §2 五件在**臂装配侧**产出（治 §14.7.1「仪器与结果变量
#   两条通道从未会合」）。Δ 经 env 「GK_ARM_DELTA」；φ/det_F1/cache 由 「arm_observables」 单源派生
#   （缺 S / 缺 gold / 缺 usage 各**具名拒估**，禁静默 0）。⚠ 本处禁 ASCII 双引号/反引号。
_D=os.environ.get('GK_ARM_DELTA','')
try:
  _Dn=int(str(_D).strip()) if str(_D).strip() else 0
except Exception:
  _Dn=0
_S=os.environ.get('GK_STRIDE','')
try:
  _Sn=int(str(_S).strip()) if str(_S).strip() else None
except Exception:
  _Sn=None
_gold=None
_rg=os.environ.get('GK_ARM_GOLD','')
if _rg:
  try: _gold=json.loads(_rg)
  except Exception: _gold=None
_obs=arm_observables(out, delta=_Dn, stride=_Sn, gold=_gold, provider=os.environ.get('GK_ARM_PROVIDER','') or 'deepseek')
entry={
  # F-REV-18 (2026-09-10): 原为 out.get('task','''\$task''')——任务文本被当 python 源码
  # 字面量内插。任务含 Windows 反斜杠路径（如 <home>）时 python 编译期即
  # SyntaxError（truncated \\UXXXXXXXX escape）→ 整块写回 heredoc 失败 → 被
  # '2>/dev/null || true' 静默吞掉 → subagent_history 不写 → ECO-EDIT→ECO-AUDIT
  # 门禁链断裂（与 L2865 注释自述的 tampered 断裂同路径、第二触发源）。
  # 修复：任务文本改经 env 传递（对齐 SUBAGENT_ID 模式），不再进入 python 源码。
  # F-REV-53（2026-09-14）：**去截断**。原 [:200] 使 task_fingerprint（F-REV-8 归属绑定）
  # 双向失效 —— standing 通道 task 前缀是固定 boilerplate（>200 字符），区分信息（词汇串）
  # 全在被截掉的尾部 ⟹ 实测 20/20 条同指纹（缺省锚=全留，绑定退化）；而 '--task' 传**全量
  # 原文**时指纹与存储副本不符（全排，MoA 零 references）。正解 = 去截断而非另落派生字段
  # （派生字段无法从记录重算 = 第二事实源）。展示侧仍有界（MoA 截 200/300）。
  'task':(out.get('task') or os.environ.get('GK_TASK','')),
  # 2026-08-28: ECC 字段上限由 runner 侧档位界限（_ECC_BOUNDS）权威裁切，聚合端保留有界全文，
  # 不再二次截断（MoA aggregator 消费此完整有界 ECC）。
  # 2026-09-08 dryrun 缺口3修复: 补 subagent_id/conclusion/kept/slashed/challenges — MoA
  # aggregator 溯源（trace.ids）与聚合裁决依赖这些字段；此前缺失致 trace.ids=['',''] +
  # conclusion 被误标 no_conclusion 可疑。
  'subagent_id': out.get('subagent_id',''),
  # F-REV-52（2026-09-14）：删二次截断。runner 侧已按 _ECC_BOUNDS[tier]['conclusion'] 权威
  # 裁切（tier3=2000 / tier4=3000），此处 [:500] 与之冲突、且与本段注释自述的「聚合端保留
  # 有界全文，不再二次截断」自相矛盾 ⇒ 实测 tier-3 臂结论 2000→500，丢 75%（F-REV-49 是
  # runner 侧恰好 2000，两者不同源，不可并案）。
  'conclusion': (out.get('conclusion') or ''),
  'kept': out.get('kept', [])[:5],
  'slashed': out.get('slashed', [])[:5],
  'challenges': out.get('challenges', [])[:5],
  'evidence':evidence,
  'findings':findings,
  'next_steps':out.get('next_steps',[]),
  'confidence':out.get('confidence',''),
  'tools_used':out.get('tools_used',[]),
  # 2026-10-19：结构化逐断言 + 实际工具调用轨迹（tools_used 是发放清单）。
  'assertions':out.get('assertions',[]),
  'tool_call_count':out.get('tool_call_count',0),
  # F-REV-52（2026-09-14）：7 维分原**只**落 '_sealed_agent_score'（单槽，下一臂即覆盖）
  # ⇒ 每臂评分不可回溯：本轮 arm1/arm2 的 7 维分已从 state 消失（只能从 CLI stdout 捞回）。
  # 补进 append-only 的 subagent_history ⟹ 随既有窗口 + 余烬全量转储留存。
  # T-c（2026-10-06，owner 裁定）：原注「不动 _sealed_agent_score 的单槽语义（覆盖即设计意图）」
  #   已作废 —— 单槽 = 单臂冒充 agent 侧 ⟹ 下方 P1-Seal #2 改为同批臂间 running mean。
  'seven_dim_score':out.get('seven_dim_score',{}) or {},
  'overall_score':out.get('overall_score') or arm_score(out),
  # F-REV-41 (2026-09-13): MoA 聚合器消费字段此前**未落库**（entry 白名单断链）⇒
  # gk_moa_aggregate._suspect_flags 的 vocab_violation / budget_* 永不触发、
  # hmac_status 恒 'verified_at_write'（实装但零生效假绿）。补齐聚合器读侧字段面 +
  # 落 HMAC 校验态（GK_HMAC_VALID ∈ valid|no_hmac|skip|invalid，由外层 bash 注入）。
  'verdicts':out.get('verdicts',{}) or {},
  'vocab_violations':out.get('vocab_violations',[]) or [],
  'budget_status':out.get('budget_status','ok'),
  'total_tokens':out.get('total_tokens',0),
  'token_budget':out.get('token_budget'),
  'total_items':out.get('total_items',0),
  'item_budget':out.get('item_budget'),
  'hmac_status':os.environ.get('GK_HMAC_VALID','skip'),
  # C3②（ECC-3BECE9FAD12A，2026-09-27）：落库条目补**指针** —— 指向全量 ECC JSON 与双盲
  #   评分报告的落盘文件（外层 sub_out_file / sub_report_file，经 env 传入，对齐 SUBAGENT_ID 模式）。
  #   此前 entry 只有摘要，主 agent 审核 / 人类评分须凭 subagent_id 去 docs/analysis/subagent/
  #   反查（隐式约定）。⚠ 注释内禁 ASCII 反引号（本 payload 在 bash 双引号区内，反引号触发命令替换）。
  'output_file':os.environ.get('GK_OUTPUT_FILE',''),
  'report_file':os.environ.get('GK_REPORT_FILE',''),
  'machine_check':_mc,
  # §18.1（2026-10-03）：批身份 + 档位（与 batch_id 同批补，治 ECC-489C8AE274E6）；
  #   tier 由外层 env SUBAGENT_TIER 注入（角色/窄任务路由的最终值）。
  'batch_id':_batch_id,
  'tier':os.environ.get('SUBAGENT_TIER',''),
  # §18.3（2026-10-04）：组别身份（G1 相同对 / G2 正交互补 / G3 污染组）—— 由派发侧编排方
  #   显式注入（实测聚合端**不可机检**：无此字段时窄任务指纹簇≠真组，且 template 注入不进
  #   _POISON_PATTERNS ⟹ 组③结构性不可见）。聚合端只读不猜。
  'arm_group':os.environ.get('GK_ARM_GROUP',''),
  # W2A-P2（2026-10-16）：消融腿 —— Δ（派发侧显式注入，聚合端只读不猜）+ 观测量（φ/det_F1/cache，
  #   由 §2 五件在**臂装配侧**产出，非事后从 verdicts 推）。
  'arm_delta':os.environ.get('GK_ARM_DELTA',''),
  'arm_obs':_obs
}
# Capture access violations for audit trail (crypto material access attempts)
avs=out.get('access_violations',[])
if avs:
  entry['access_violations']=[{'tool':a.get('tool',''),'path':a.get('path',''),'reason':a.get('reason',''),'timestamp':a.get('timestamp','')} for a in avs[:10]]
# C4③（ECC-D9D2382BB535）：投影键集**自检** —— entry 键必须 ⊆ 声明集 _ENTRY_KEYS
#   （防再丢面 / 误加面）；越集即 fail-loud（非零退出 → 外层 HISTORY_WRITE_FAILED 兜底）。
_extra=sorted(set(entry)-set(_ENTRY_KEYS))
if _extra:
  raise SystemExit('ENTRY_KEY_UNDECLARED: %s' % _extra)
# R3: JTI replay detection (Map + prune, inspired by ATH jti-replay.ts)
# 2026-09-22（R22 / 红队 C4 修复）：原实现 = **仅**「按过期惰性 prune」，两个缺口：
#   ① **无上限**：每次 subagent 落库都写一条 ⟹ 表随写入频率无界增长，与 state
#      262144 B 阈值耦合 —— 撞阈后本块 json.dump **整份写失败**，而下行以 || true
#      兜底 ⟹ jti 记录不落盘 ⟹ **静默 fail-open**（重放不再被拦），且病象呈现为
#      无关的'写失败'（判据指向错误方向）。
#   ② **缺 nonce 时静默跳过**（原 if nonce 双分支皆不执行）⟹ 零留痕 = 静默放弃防重放。
#   修法：prune-on-write（保留）+ **上限驱逐**（超 _JTI_MAX 按**最早过期**先删，即只删
#      最接近失效者 ⟹ 对「1h 内重放拦截」的削弱最小）+ 驱逐/缺 nonce **留痕**。
#      告警不可走 stderr（本块的 stderr 由收尾重定向汇入 GK_DBG_LOG、非直出用户面；
#      C3① 之前更是整段被吞）⟹ 直接追加日志。
import time as _t
now_s=_t.time()
_JTI_MAX=2000
jti_store=gd.setdefault('jti_store',{})
# Prune expired entries (prune-on-write)
expired=[k for k,v in jti_store.items() if v<now_s]
for k in expired: del jti_store[k]
_evicted=0
if len(jti_store)>_JTI_MAX:
  for k in sorted(jti_store,key=lambda x:jti_store[x])[:len(jti_store)-_JTI_MAX]:
    del jti_store[k]; _evicted+=1
nonce=out.get('nonce','')
if _evicted or not nonce:
  try:
    open(os.path.join(os.environ['GK_PY_SCRIPTS'],'gk_dbg.log'),'a',encoding='utf-8').write(
      '[jti] WARN %s pruned=%d evicted=%d size=%d nonce=%s %s\n'
      % ('nonce 缺失 → 本轮防重放未生效' if not nonce else '上限驱逐',
         len(expired), _evicted, len(jti_store), nonce or '<empty>',
         __import__('datetime').datetime.now().astimezone().isoformat()))
  except Exception:
    pass
if nonce and nonce in jti_store:
  print(json.dumps({'ok':False,'error':'JTI_REPLAY','nonce':nonce,'subagent_id':out.get('subagent_id','')}))
  sys.exit(0)
if nonce:
  jti_store[nonce]=now_s+3600  # 1h expiry (matches JWT exp)
hist.append(entry)
# t4(a)（2026-10-17，ECC-2E9DA8D90CB2）：**臂输出全量直接落卫星 history 片**，state 只留元数据。
#   原状：conclusion 全量内联，卫星片仅在 >96KB 溢出时才产生（主 state 非「只存元数据」）。
#   序：① 全量落片（in-tx 并入 gd 的 satellite_index，禁另起 state 写）→ ② **成功才**抹成
#   元数据投影（spilled / conclusion_len）；落片失败**保留全量**（fail-safe，禁静默丢结论）。
#   读侧 gk_moa_aggregate._satellite_history_union 按 subagent_id 用片内全量**原位替换**占位。
#   ⚠ 本 payload 在 bash 双引号区内 ⟹ 禁 ASCII 反引号 + 禁 ASCII 双引号。
try:
  import os as _os3
  sys.path.insert(0,_os3.environ['GK_PY_SCRIPTS'])
  import gk_satellite as _sat4
  _r4=_sat4.append(_os3.environ['GK_PY_STATE'],'history',[entry],
                   batch_id=(entry.get('batch_id') or 'history-live'),
                   arm=(entry.get('subagent_id') or 'state'), gd=gd)
  if _r4.get('ok'):
    entry['conclusion_len']=len(str(entry.get('conclusion') or ''))
    entry['spilled']=True
    entry.pop('conclusion',None)
  else:
    sys.stderr.write('HISTORY_SPILL_FAILED n=1: %s\n' % (_r4.get('error'),))
except Exception as _sx:
  sys.stderr.write('HISTORY_SPILL_FAILED n=1: %s\n' % (_sx,))
# F-REV-51/52（2026-09-14）：条数配额 → 字节配额。条数与 state 阈值（262144 B）**不同量纲**
# ⇒ 一改 conclusion 界（500→档位 2000）就会撞阈值 = F-REV-51 的病因。改为与阈值同量纲：
# 按序列化字节从**最旧**裁、保留最近（至少留 1 条）；条数上限保留为兜底。
# 先例：gk_narrow_route._NT_MAX_TOTAL_BYTES（清单侧同用字节配额）。
# 80KB 的预算依据（2026-09-14 实测）：file=gate_data 184,328 + 顶层/格式 32,200；
# 262,144 − 95,413（非 history 分量）− 64KB（narrow_tasks 自身设计上限，须预留）≈ 102KB
# ⟹ 取 80KB 留余量（≈10-11 臂 ≈3-4 轮 @3臂/轮）。实测 48KB 只能留 6 臂，窗口过窄。
# 2026-09-27（用户裁定「提配额+归档释放」）：80KB→96KB。背景=6 臂窗口（3 组×2）在 80KB 下
#   装不下第 6 臂（实测 5 臂 77,366 B，第 6 臂 ~15.9KB ⟹ 插入即被下方 pop(0) 当场淘汰，写回
#   ok 但零净增）；同批归档 gate_data.task_pipeline（13 条已决，−67.7KB）⟹ state 190,377 B，
#   余量足够容纳 96KB 的 history。
# 2026-10-26（owner 裁定「裁剪线抬到 128KB/196KB」）：96KB→128KB。
# 2026-11-02（owner 裁定「收紧 payload 配额」）：三腿各 **5% = 128KB**，合计 15%，
#   其余 85% 留给其它 key。依据：卫星片/冷侧车已承接 bulk；history 一窗只需
#   一轮（6 臂 × 16KB × 1.2 ≈ 118KB），不再按 10 轮 60 臂定价。
#   单源 = `gk_json_utils.HIST_MAX_BYTES`（本行为同值字面量，bash 不可 import；
#   漂移由 `scripts/test_gk_state_trim_lines.py` 逐值守）。
_HIST_MAX_BYTES=131072  # 128KB = STATE_SIZE_WALL * 5 // 100
# 逃生舱：「GK_STATE_TRIM_KB=196」把本腿裁剪线**显式覆盖**为 196KB（不改源码）
try:
  _kb=int(os.environ.get('GK_STATE_TRIM_KB') or 0)
  if _kb>0: _HIST_MAX_BYTES=_kb*1024
except Exception:  # noqa: BLE001 — 非法值回落到缺省
  pass
# C1②（ECC-0F1DAF8C787C，2026-09-28）：溢出条目**代数归档**（对齐 gk_finding.archive_closed 先例）
#   —— 原 hist.pop(0) 直接丢弃（不可回溯，与「提配额+归档释放」裁定相悖）；改为先把出窗条目
#   append 到旁挂 <state>.history-archive.jsonl（append-only，可回溯、不删），再出窗。
#   归档写失败**不阻断**（否则落库全失），但须留痕（stderr 由本段收尾重定向汇入 GK_DBG_LOG）。
#   ⚠ 变量名避开上方 JTI 的 _evicted（同名会串味）。
_hist_evicted=[]
while len(hist)>1 and len(json.dumps(hist,ensure_ascii=False).encode())>_HIST_MAX_BYTES:
  _hist_evicted.append(hist.pop(0))
if len(hist)>20:
  _hist_evicted+=hist[:-20]; hist[:]=hist[-20:]
if _hist_evicted:
  # P1 后续（c5 收敛，2026-10-06）：片写**收敛为调中枢** gk_satellite（禁第二直写者）。
  #   **按条入账**：每条以其**自身身份** (batch_id, arm=subagent_id) 落 per-arm 索引叶子
  #   （c5「片数==臂数」在**真实派发路径**成立；多条并成同一叶子会互相覆盖索引项）。
  #   本段在 dump_state **之前** ⟹ 索引**必须 in-tx 并入 gd**（传 gd），禁另起 state 写。
  try:
    import os as _os2
    sys.path.insert(0,_os2.environ['GK_PY_SCRIPTS'])
    import gk_satellite as _sat2
    for _e in _hist_evicted:
      if _e.get('spilled'):
        continue  # t4(a)：已在入库时全量落片 ⟹ 防同一条写两行
      _r2=_sat2.append(_os2.environ['GK_PY_STATE'],'history',[_e],
                       batch_id=(_e.get('batch_id') or 'history-overflow'),
                       arm=(_e.get('subagent_id') or 'state'), gd=gd)
      if not _r2.get('ok'):
        sys.stderr.write('HISTORY_ARCHIVE_FAILED n=1: %s\n' % (_r2.get('error'),))
  except Exception as _ax:
    sys.stderr.write('HISTORY_ARCHIVE_FAILED n=%d: %s\n' % (len(_hist_evicted), _ax))
gd['subagent_history']=hist
gd['subagent_last']=entry
# P1-Seal #2: plan-refinement output sealed to _sealed_agent_score
# Not written to monitor_scores — prevents human anchor bias during adjudicate
# T-c（2026-10-06，owner 裁定）：由**单槽覆盖**改为**同批臂间 running mean** ——
#   原实现令该槽 = 最后完成的那条臂（**单臂冒充 agent 侧**），adjudicate 的 divergence
#   基准随完成顺序漂移（实测本批 0.4471 = 某单臂 7 维均）。
#   merge_sealed_agent_score 保持返回形状不变（新增透明键 batch_id/arm_count/arm_ids）
#   ⟹ D10（gk_audit_state）/appeal/mediation 消费者零回归；单臂/跨批与旧语义逐字等价。
task_str=out.get('task','')
if 'plan-refinement' in task_str:
  import time as _ts
  gd['_sealed_agent_score']=merge_sealed_agent_score(
    gd.get('_sealed_agent_score') or {}, out, _batch_id, _ts.time())
if not dump_state(os.environ['GK_PY_STATE'], d):
  print(json.dumps({'ok':False,'error':'HISTORY_WRITE_FAILED','subagent_id':out.get('subagent_id','')}))
  sys.exit(3)
_lk.__exit__(None, None, None)
