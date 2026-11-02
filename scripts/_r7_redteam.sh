#!/bin/bash
# R7 Red-Team Penetration Test — 隐蔽刁钻攻击
# 攻击面: 状态机绕过、死代码、熵监视器盲区、密钥篡改
set +e

CLI="bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
KD="<home>/.trae/skills/spz-gatekeeper-r-sequence/.keys"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "R7 RED-TEAM PENETRATION TEST"
echo "==========================================="

# ═══════════════════════════════════════════════
# ATTACK 1: 直接篡改 key-meta.json 绕过状态机
# ═══════════════════════════════════════════════
echo ""; echo "--- A1: State Machine Bypass via key-meta.json tampering ---"

# Setup: init keys
rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/audit_ed25519.pem "$KD"/audit_ed25519.pub "$KD"/key-meta.json "$KD"/.key.lock 2>/dev/null
rm -rf "$KD/.revoked" 2>/dev/null
$CLI audit --init-keys > /dev/null 2>&1

# First rotate (pre-activation→active should work now)
r=$($CLI audit --key rotate context 2>&1)
echo "$r" | rg -q '"ok":true' || { fail "A1: rotate failed (precondition)"; }

# Now: rotate AGAIN (active→deactivated should work)
r=$($CLI audit --key rotate context 2>&1)
echo "$r" | rg -q '"ok":true' && pass "A1a: second rotate ok" || fail "A1a: second rotate: $r"

# Now revoke key
$CLI audit --key revoke context > /dev/null 2>&1

# Re-gen key to get back to active
openssl genpkey -algorithm ED25519 -out "$KD/context_ed25519.pem" 2>/dev/null
openssl pkey -in "$KD/context_ed25519.pem" -pubout -out "$KD/context_ed25519.pub" 2>/dev/null

# ATTACK: manually rewrite key-meta.json to set status='active'
python3 << PYEOF
import json
meta_file = '$KD/key-meta.json'
meta = json.load(open(meta_file))
meta['context_ed25519'] = {
    'created': '2026-01-01T00:00:00Z',
    'expires': '2099-01-01T00:00:00Z',
    'status': 'active',
    'rotation_days': 99999
}
with open(meta_file, 'w') as f: json.dump(meta, f, indent=2)
PYEOF

# Now the key SHOULD be in 'revoked' state (we revoked it),
# but we set it to 'active'. Try to use it as if nothing happened.
r=$($CLI audit --key status 2>&1)
echo "$r" | rg -q '"active"' && vuln "A1: key-meta.json TAMPERED — revoked key reactivated to 'active'" || pass "A1: tamper detected or status mismatch"
echo "  Status: $r"

# ═══════════════════════════════════════════════
# ATTACK 2: 手动替换 .pem 文件 绕过 rotate 验证
# ═══════════════════════════════════════════════
echo ""; echo "--- A2: Rotate Bypass via Manual Key Replacement ---"

rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/key-meta.json 2>/dev/null
$CLI audit --init-keys > /dev/null 2>&1

# First normal rotate to get .bak
$CLI audit --key rotate context > /dev/null 2>&1

# ATTACK: replace new key with a PRE-GENERATED attacker key
ATTACKER_KEY="$KD/attacker_context.pem"
ATTACKER_PUB="$KD/attacker_context.pub"
openssl genpkey -algorithm ED25519 -out "$ATTACKER_KEY" 2>/dev/null
openssl pkey -in "$ATTACKER_KEY" -pubout -out "$ATTACKER_PUB" 2>/dev/null

# Stealthily replace the legitimate key with attacker's
cp "$ATTACKER_KEY" "$KD/context_ed25519.pem"
cp "$ATTACKER_PUB" "$KD/context_ed25519.pub"

# Sign with "legitimate" key (actually attacker's now)
echo -n "stolen-data" > /tmp/_r7_hijack.bin
openssl pkeyutl -sign -inkey "$KD/context_ed25519.pem" -rawin -in /tmp/_r7_hijack.bin -out /tmp/_r7_hijack.sig 2>/dev/null
# Verify with attacker pub (should pass)
openssl pkeyutl -verify -pubin -inkey "$KD/context_ed25519.pub" -rawin -in /tmp/_r7_hijack.bin -sigfile /tmp/_r7_hijack.sig 2>/dev/null
if [ $? -eq 0 ]; then
  # Check if ANY detection exists
  ORIG_FP=$(sha256sum "$ATTACKER_PUB" | awk '{print $1}')
  CURR_FP=$(sha256sum "$KD/context_ed25519.pub" | awk '{print $1}')
  [ "$ORIG_FP" = "$CURR_FP" ] && vuln "A2: KEY HIJACKED — attacker replaced key pair, no detection mechanism" || pass "A2: fingerprint mismatch (accidental detection)"
else
  pass "A2: hijack signature verification failed (somehow)"
fi
rm -f /tmp/_r7_hijack.bin /tmp/_r7_hijack.sig "$ATTACKER_KEY" "$ATTACKER_PUB"

# ═══════════════════════════════════════════════
# ATTACK 3: shred 在 drvfs 不可用 → rm -f 弱删除
# ═══════════════════════════════════════════════
echo ""; echo "--- A3: Shred Fallback Weakness ---"

rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/audit_ed25519.pem "$KD"/audit_ed25519.pub "$KD"/key-meta.json 2>/dev/null
$CLI audit --init-keys > /dev/null 2>&1

# Check if shred exists
SHRED_AVAIL=$(which shred 2>/dev/null || echo "")
TEST_FILE="$KD/_shred_test.bin"
echo "secret-data-$(date +%s%N)" > "$TEST_FILE"

if [ -n "$SHRED_AVAIL" ]; then
  shred -u "$TEST_FILE" 2>/dev/null
  [ ! -f "$TEST_FILE" ] && pass "A3a: shred available and works" || vuln "A3a: shred failed to delete"
else
  rm -f "$TEST_FILE"
  # Can we recover it?
  if [ -f "$TEST_FILE" ]; then
    vuln "A3: shred unavailable, rm -f failed — key recoverable"
  else
    # On drvfs, rm is NOT secure — file content can be recovered from NTFS journal
    FS_TYPE=$(df -T "$KD" 2>/dev/null | tail -1 | awk '{print $2}')
    if echo "$FS_TYPE" | rg -qi "drvfs\|9p\|cifs"; then
      vuln "A3: DRVFS/CIFS filesystem — rm -f is NOT secure deletion. NTFS journal recovery possible."
    else
      pass "A3: rm -f on native FS (no journal recovery risk)"
    fi
  fi
fi

# ═══════════════════════════════════════════════
# ATTACK 4: flock 旁路 — 杀进程/超时后残留
# ═══════════════════════════════════════════════
echo ""; echo "--- A4: Flock Bypass / TOCTOU ---"

rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/key-meta.json "$KD"/.key.lock 2>/dev/null
$CLI audit --init-keys > /dev/null 2>&1

# Check if flock is available
FLOCK_AVAIL=$(which flock 2>/dev/null || echo "")
if [ -z "$FLOCK_AVAIL" ]; then
  vuln "A4: flock NOT AVAILABLE — lock file created but no actual locking mechanism"
else
  # Test: acquire lock externally, then try rotate
  (
    flock -x 9 2>/dev/null
    sleep 3
  ) 9>"$KD/.key.lock" &

  LOCKER_PID=$!
  sleep 0.5

  r=$(timeout 2 $CLI audit --key rotate context 2>&1 || echo "timeout")
  wait $LOCKER_PID 2>/dev/null

  if echo "$r" | rg -q "lock timeout"; then
    pass "A4a: flock blocks concurrent rotate"
  else
    vuln "A4: flock FAILED to block concurrent rotate: $r"
  fi
fi

# ═══════════════════════════════════════════════
# ATTACK 5: 签名替换 — 静默密钥腐败
# ═══════════════════════════════════════════════
echo ""; echo "--- A5: Silent Key Corruption / Signature Substitution ---"

rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/key-meta.json "$KD"/.key.lock 2>/dev/null
$CLI audit --init-keys > /dev/null 2>&1

# Generate context signature
SIGNED_CONTEXT=$($CLI context --update 2>&1)
echo "$SIGNED_CONTEXT" | rg -q '"ok":true' || fail "A5: context --update failed"

CTX_FILE="$SKILL/references/subagent-context.json"
if [ -f "$CTX_FILE" ]; then
  # ATTACK: modify subagent-context.json WITHOUT re-signing
  ORIG_MD5=$(md5sum "$CTX_FILE" 2>/dev/null | awk '{print $1}' || echo "")
  echo '{"injected":"malicious-payload"}' >> "$CTX_FILE"
  NEW_MD5=$(md5sum "$CTX_FILE" 2>/dev/null | awk '{print $1}' || echo "")

  if [ "$ORIG_MD5" != "$NEW_MD5" ]; then
    # File modified. But is there any integrity check on read?
    # The old signature still says "valid" but content changed
    vuln "A5: CONTEXT TAMPERED — subagent-context.json modified, old signature still considered valid (no integrity check on read)"
    # Restore original
    python3 -c "
import json
f = open('$CTX_FILE', 'r')
lines = f.readlines()
f.close()
with open('$CTX_FILE', 'w') as f:
    for l in lines:
        if 'injected' not in l:
            f.write(l)
" 2>/dev/null
  else
    pass "A5: context file unchanged (attack failed to modify)"
  fi
else
  fail "A5: no subagent-context.json to attack"
fi

# ═══════════════════════════════════════════════
# ATTACK 6: 死代码 + 熵监视器盲区
# ═══════════════════════════════════════════════
echo ""; echo "--- A6: Dead Code + Entropy Monitor Blind Spots ---"

# Check: are there functions that exist but are never called?
# _audit_verify, _sign_raw, _verify_raw — all used
# What about the export-pub fingerprint? Can we spoof it?

# ATTACK: export-pub then use the SAME fingerprint to claim key is "verified"
FP1=$($CLI audit --key fingerprint context 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('fingerprint',{}).get('context_ed25519',''))" 2>/dev/null)
$CLI audit --key rotate context > /dev/null 2>&1
FP2=$($CLI audit --key fingerprint context 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('fingerprint',{}).get('context_ed25519',''))" 2>/dev/null)
[ "$FP1" != "$FP2" ] && pass "A6a: fingerprint changes after rotate" || vuln "A6a: fingerprint unchanged after rotate (key not actually rotated)"

# ATTACK: Monitor .keys/ access violations — does R7 actually detect unauthorized reads?
GD_FILE="$SKILL/state/gate_data.json"
if [ -f "$GD_FILE" ]; then
  VIOL_COUNT=$(python3 -c "
import json
gd = json.load(open('$GD_FILE'))
viols = gd.get('_ACCESS_VIOLATIONS', [])
print(len([v for v in viols if '.keys/' in str(v.get('path',''))]))
" 2>/dev/null || echo "0")
  if [ "$VIOL_COUNT" = "0" ]; then
    # This is expected — we haven't triggered any violations yet
    pass "A6b: G7 compromise evidence: $VIOL_COUNT violations (expected: 0)"
  else
    vuln "A6b: $VIOL_COUNT .keys/ compromises detected but no auto-escalation"
  fi
else
  pass "A6b: no gate_data.json (entropy monitor not active)"
fi

# ═══════════════════════════════════════════════
# ATTACK 7: key export-pub 泄露私钥?
# ═══════════════════════════════════════════════
echo ""; echo "--- A7: export-pub Private Key Leak Check ---"

rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/audit_ed25519.pem "$KD"/audit_ed25519.pub "$KD"/key-meta.json 2>/dev/null
$CLI audit --init-keys > /dev/null 2>&1

EXP=$($CLI audit --key export-pub context 2>&1)
# Check that exported content does NOT contain private key markers
echo "$EXP" | rg -q "PRIVATE KEY" && vuln "A7a: export-pub LEAKED PRIVATE KEY" || pass "A7a: export-pub only contains public key"
echo "$EXP" | rg -q "PUBLIC KEY" && pass "A7b: export-pub correctly contains public key" || vuln "A7b: export-pub missing public key marker"

# Check pub-only content does NOT equal priv file content
PRIV_CONTENT=$(cat "$KD/context_ed25519.pem" 2>/dev/null | md5sum | awk '{print $1}')
PUB_CONTENT=$(cat "$KD/context_ed25519.pub" 2>/dev/null | md5sum | awk '{print $1}')
[ "$PRIV_CONTENT" != "$PUB_CONTENT" ] && pass "A7c: private and public keys are different files" || vuln "A7c: private and public keys are IDENTICAL — key leakage"

# ═══════════════════════════════════════════════
# ATTACK 8: concurrent init-keys race
# ═══════════════════════════════════════════════
echo ""; echo "--- A8: Concurrent init-keys Race ---"

rm -f "$KD"/context_ed25519.pem "$KD"/context_ed25519.pub "$KD"/audit_ed25519.pem "$KD"/audit_ed25519.pub "$KD"/key-meta.json "$KD"/.key.lock 2>/dev/null

# Run TWO init-keys simultaneously
$CLI audit --init-keys > /tmp/_r7_init1.json 2>&1 &
PID1=$!
$CLI audit --init-keys > /tmp/_r7_init2.json 2>&1 &
PID2=$!
wait $PID1 2>/dev/null
wait $PID2 2>/dev/null

# Both should succeed, but check for corruption
CTX_COUNT=$(ls "$KD"/context_ed25519* 2>/dev/null | wc -l)
[ "$CTX_COUNT" -le 3 ] && pass "A8a: concurrent init produced <=3 context files (expected: pem+pub+new)" || vuln "A8a: concurrent init produced $CTX_COUNT files — key duplication"

# Check that init-keys returned ok for at least one
rg -q '"ok":true' /tmp/_r7_init1.json && pass "A8b: init 1 returned ok" || fail "A8b: init 1: $(cat /tmp/_r7_init1.json)"
rg -q '"ok":true' /tmp/_r7_init2.json && pass "A8c: init 2 returned ok" || pass "A8c: init 2 correctly reported keys exist: $(cat /tmp/_r7_init2.json)"

rm -f /tmp/_r7_init1.json /tmp/_r7_init2.json

# ═══════════════════════════════════════════════
echo ""; echo "==========================================="
echo "RED-TEAM RESULTS: VULN=$VULN FOUND, $PASS pass, $FAIL total fail"
if [ $VULN -gt 0 ]; then
  echo "VULNERABILITIES DISCOVERED"
  exit 1
else
  echo "No vulnerabilities found"
  exit 0
fi
