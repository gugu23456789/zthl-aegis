#!/bin/bash
# Red-team: 2026-08-14 新增计划质询门禁节点覆盖
# 覆盖: ①bypass 分支 plan-refinement gate ②standard 路径 Gate A/B ③TAMPERED self-heal hint
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE）
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

# 写 standing 测试 state（checksum 由 CLI 下次写时更新）
write_standing() {
  python3 -c "
import json
d={
 'r_phase':'ECO-READ','stage':'ECO-READ','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing',
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4},
   'rejected_edits':[],'subagent_history':[]
 },
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
}

echo "==========================================="
echo "GATE-FIX RED-TEAM (2026-08-14 新增门禁节点)"
echo "==========================================="

echo ""
echo "=== G1: bypass 分支 plan-refinement gate — 无记录 BLOCK ==="
write_standing
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "requires plan-refinement subagent checkpoint"; then
  pass "G1: bypass 分支无 plan-refinement 记录被 BLOCK"
else
  vuln "G1: bypass 分支无记录未 BLOCK: $(echo "$r" | head -c 120)"
fi

echo ""
echo "=== G2: bypass 分支 plan-refinement gate — 有记录 PASS ==="
write_standing
# 注入 plan-refinement 记录（checksum 与 CLI 同构，避免误触发 TAMPERED）
python3 -c "
import json,hashlib
d=json.load(open('$SF'))
d['gate_data']['subagent_history']=[{'task':'plan-refinement: ECO-READ→ECO-EDIT 同构审查','guardrail':'passed','time':'2026-08-14T00:00:00'}]
gd=json.dumps(d['gate_data'],sort_keys=True)
d['_checksum']=hashlib.sha256(gd.encode()).hexdigest()[:16]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
# 通过点检 gate 后应进入后续 ECO 序列/熵检查（不再报 requires checkpoint）
if echo "$r" | rg -q "requires plan-refinement subagent checkpoint"; then
  vuln "G2: bypass 分支有 plan-refinement 记录仍被 BLOCK"
else
  pass "G2: bypass 分支有记录通过点检 gate（后续检查: $(echo "$r" | rg -o 'ECO sequential violation|appeal_required|"ok":true' | head -1)）"
fi

echo ""
echo "=== G3: bypass 分支 — 伪造非 plan-refinement subagent 记录应 BLOCK ==="
write_standing
python3 -c "
import json,hashlib
d=json.load(open('$SF'))
d['gate_data']['subagent_history']=[{'task':'RED-EXPLOIT: 尝试绕过','guardrail':'passed','time':'2026-08-14T00:00:00'}]
gd=json.dumps(d['gate_data'],sort_keys=True)
d['_checksum']=hashlib.sha256(gd.encode()).hexdigest()[:16]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "requires plan-refinement subagent checkpoint"; then
  pass "G3: 非 plan-refinement 记录（RED-EXPLOIT）被 BLOCK（只认 plan-refinement 任务）"
else
  vuln "G3: 非 plan-refinement 记录未被 BLOCK: $(echo "$r" | head -c 120)"
fi

echo ""
echo "=== G4: standard 路径 Gate A — subagent_history 空 → FAIL ==="
python3 -c "
import json
d={
 'r_phase':'ECO-READ','stage':'ECO-READ','branch':'feature/test',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standard',
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4},
   'rejected_edits':[],'subagent_history':[]
 },
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# standard 路径: monitor 层先拦截（score 0.0）。用 --force 绕过 monitor 层，测 structural Gate A。
r=$(bash "$CLI" advance ECO-EDIT --force 2>&1)
if echo "$r" | rg -q "requires plan-refinement subagent checkpoint"; then
  pass "G4: standard 路径 Gate A 空 subagent_history → BLOCK（--force 绕过 monitor 后命中）"
else
  fail "G4: standard 路径 Gate A 结果: $(echo "$r" | head -c 150)"
fi

echo ""
echo "=== G5: standard 路径 Gate A — 有 plan-refinement 记录 → 通过该 gate ==="
python3 -c "
import json,hashlib
d=json.load(open('$SF'))
d['gate_data']['subagent_history']=[{'task':'plan-refinement: standard 同构审查','guardrail':'passed','time':'2026-08-14T00:00:00'}]
gd=json.dumps(d['gate_data'],sort_keys=True)
d['_checksum']=hashlib.sha256(gd.encode()).hexdigest()[:16]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT --force 2>&1)
if echo "$r" | rg -q "requires plan-refinement subagent checkpoint"; then
  fail "G5: standard 路径 Gate A 有记录仍 BLOCK: $(echo "$r" | head -c 120)"
else
  pass "G5: standard 路径 Gate A 有记录通过（后续检查: $(echo "$r" | rg -o 'ECO sequential violation|gitnexus|"ok":true' | head -1)）"
fi

echo ""
echo "=== G6: STATE_FILE_TAMPERED self-heal hint 字段 ==="
write_standing
# 先由 CLI 写入合法 checksum（模拟正常写入），再篡改 gate_data 不更新 checksum
python3 -c "
import json,hashlib
d=json.load(open('$SF'))
gd=json.dumps(d['gate_data'],sort_keys=True)
d['_checksum']=hashlib.sha256(gd.encode()).hexdigest()[:16]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['fake_field']='tampered'
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
has_hint=$(echo "$r" | rg -c 'checksum-recalc|禁止直接改.*_checksum|STATE_FILE_TAMPERED' 2>/dev/null || echo 0)
if echo "$r" | rg -q "STATE_FILE_TAMPERED"; then
  if [ "$has_hint" -gt 0 ]; then
    pass "G6: TAMPERED 拦截 + self-heal hint 存在（checksum-recalc 提示）"
  else
    fail "G6: TAMPERED 拦截但缺 self-heal hint"
  fi
else
  vuln "G6: 篡改未触发 TAMPERED: $(echo "$r" | head -c 120)"
fi

echo ""
echo "=== G7: 直接改 _checksum 伪造绕过 → 应仍被检测（hint 明确禁止）==="
write_standing
python3 -c "
import json
d=json.load(open('$SF'))
d['_checksum']='0000000000000000'
d['gate_data']['fake_field']='tampered'
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "STATE_FILE_TAMPERED"; then
  pass "G7: 伪造 _checksum 被检测（计算值≠伪造值）"
else
  vuln "G7: 伪造 _checksum 未被检测: $(echo "$r" | head -c 120)"
fi

echo ""
echo "==========================================="
echo "GATE-FIX RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0
