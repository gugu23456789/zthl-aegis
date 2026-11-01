#!/bin/bash
# R7 NIST SP 800-57 密钥生命周期完整测试
# 阶段: 生成→分发→使用→轮换→吊销→销毁
set +e

CLI="bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
KEYS_DIR="<home>/.trae/skills/spz-gatekeeper-r-sequence/.keys"
PASS=0; FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== R7 NIST SP 800-57 Key Lifecycle Test ==="
echo ""

# Clean up any existing keys for fresh test
echo "[Setup] Removing old keys..."
rm -f "$KEYS_DIR"/context_ed25519.pem "$KEYS_DIR"/context_ed25519.pub \
      "$KEYS_DIR"/audit_ed25519.pem "$KEYS_DIR"/audit_ed25519.pub \
      "$KEYS_DIR"/key-meta.json "$KEYS_DIR"/.key.lock 2>/dev/null || true
rm -rf "$KEYS_DIR/.revoked" 2>/dev/null || true

# ═══════════════════════════════════════════════
# PHASE 1: Generation
# ═══════════════════════════════════════════════
echo "--- Phase 1: Key Generation ---"

r=$($CLI audit --init-keys 2>&1)
if echo "$r" | rg -q '"ok":true'; then pass "init-keys: both key pairs generated"; else fail "init-keys: $r"; fi

[ -f "$KEYS_DIR/context_ed25519.pem" ] && pass "gen: context_ed25519.pem exists" || fail "gen: context_ed25519.pem missing"
[ -f "$KEYS_DIR/context_ed25519.pub" ] && pass "gen: context_ed25519.pub exists" || fail "gen: context_ed25519.pub missing"
[ -f "$KEYS_DIR/key-meta.json" ] && pass "gen: key-meta.json exists" || fail "gen: key-meta.json missing"

# chmod 600 is WSL drvfs limitation — skip check on /mnt/c mounts
case "$KEYS_DIR" in /mnt/*) pass "gen: chmod skipped (WSL drvfs)";; *) CTX_PERM=$(stat -c '%a' "$KEYS_DIR/context_ed25519.pem" 2>/dev/null); [ "$CTX_PERM" = "600" ] && pass "gen: context key chmod 600" || fail "gen: context key chmod $CTX_PERM";; esac

# Verify pre-activation status
python3 << PYEOF
import json
meta = json.load(open('$KEYS_DIR/key-meta.json'))
ctx = meta['context_ed25519']
audit = meta['audit_ed25519']
assert ctx['status'] == 'pre-activation', f"Expected pre-activation, got {ctx['status']}"
assert audit['status'] == 'pre-activation', f"Expected pre-activation, got {audit['status']}"
print('  PASS: NIST pre-activation state verified')
PYEOF
[ $? -eq 0 ] && pass "gen: NIST pre-activation state" || fail "gen: NIST pre-activation state"

# ═══════════════════════════════════════════════
# PHASE 2: Distribution
# ═══════════════════════════════════════════════
echo "--- Phase 2: Key Distribution ---"

r=$($CLI audit --key fingerprint 2>&1)
if echo "$r" | rg -q '"ok":true'; then pass "distribution: fingerprint all"; else fail "distribution: $r"; fi
echo "$r" | rg -q 'context_ed25519' && pass "distribution: context fingerprint" || fail "distribution: context fingerprint missing"

r=$($CLI audit --key export-pub context 2>&1)
if echo "$r" | rg -q '"ok":true'; then pass "distribution: export-pub context"; else fail "distribution: $r"; fi
echo "$r" | rg -q 'BEGIN PUBLIC KEY' && pass "distribution: PEM in export" || fail "distribution: PEM missing"

# ═══════════════════════════════════════════════
# PHASE 3: Signing & Verification
# ═══════════════════════════════════════════════
echo "--- Phase 3: Signing & Verification ---"

TEST_MSG="NIST-test-$(date +%s)"
echo "$TEST_MSG" > /tmp/_r7_msg.txt

# Sign using openssl pkeyutl with Ed25519 (rawin requires -in file, not stdin pipe)
echo -n "$TEST_MSG" > /tmp/_r7_sign_in.bin
openssl pkeyutl -sign -inkey "$KEYS_DIR/context_ed25519.pem" -rawin -in /tmp/_r7_sign_in.bin -out /tmp/_r7_sign_out.bin 2>/dev/null
[ -s /tmp/_r7_sign_out.bin ] && pass "sign: context key signed message" || fail "sign: signing returned empty"

# Verify
openssl pkeyutl -verify -pubin -inkey "$KEYS_DIR/context_ed25519.pub" -rawin -in /tmp/_r7_sign_in.bin -sigfile /tmp/_r7_sign_out.bin 2>/dev/null
[ $? -eq 0 ] && pass "verify: signature valid" || fail "verify: signature validation failed"
rm -f /tmp/_r7_sign_in.bin /tmp/_r7_sign_out.bin

# ═══════════════════════════════════════════════
# PHASE 4: Rotation
# ═══════════════════════════════════════════════
echo "--- Phase 4: Key Rotation ---"

OLD_FP=$(sha256sum "$KEYS_DIR/context_ed25519.pub" | awk '{print $1}')

r=$($CLI audit --key rotate context 2>&1)
if echo "$r" | rg -q '"ok":true'; then pass "rotate: context key rotated"; else fail "rotate: $r"; fi

ls "$KEYS_DIR"/context_ed25519.pem.*.bak >/dev/null 2>&1 && pass "rotate: old key preserved as .bak" || fail "rotate: no .bak backup"

NEW_FP=$(sha256sum "$KEYS_DIR/context_ed25519.pub" | awk '{print $1}')
[ "$OLD_FP" != "$NEW_FP" ] && pass "rotate: new key different from old" || fail "rotate: key unchanged"

# New key must sign
echo -n "$TEST_MSG" > /tmp/_r7_rot_in.bin
openssl pkeyutl -sign -inkey "$KEYS_DIR/context_ed25519.pem" -rawin -in /tmp/_r7_rot_in.bin -out /tmp/_r7_rot_out.bin 2>/dev/null
[ -s /tmp/_r7_rot_out.bin ] && pass "rotate: new key signs" || fail "rotate: new key sign failed"
openssl pkeyutl -verify -pubin -inkey "$KEYS_DIR/context_ed25519.pub" -rawin -in /tmp/_r7_rot_in.bin -sigfile /tmp/_r7_rot_out.bin 2>/dev/null
[ $? -eq 0 ] && pass "rotate: new key verify ok" || fail "rotate: new key verify failed"
rm -f /tmp/_r7_rot_in.bin /tmp/_r7_rot_out.bin

# Check state transition
python3 << PYEOF
import json
meta = json.load(open('$KEYS_DIR/key-meta.json'))
assert meta['context_ed25519']['status'] == 'active', f"Expected active, got {meta['context_ed25519']['status']}"
print('  PASS: state pre-activation -> active')
PYEOF
[ $? -eq 0 ] && pass "rotate: NIST state transition" || fail "rotate: state transition"

# ═══════════════════════════════════════════════
# PHASE 5: State Machine Guards
# ═══════════════════════════════════════════════
echo "--- Phase 5: State Machine Guards ---"

# Revoke (active→revoked should work)
r=$($CLI audit --key revoke context 2>&1)
if echo "$r" | rg -q '"ok":true'; then pass "state-guard: active->revoked allowed"; else fail "state-guard: $r"; fi

# Rotate revoked (should fail)
r=$($CLI audit --key rotate context 2>&1)
if echo "$r" | rg -q '"ok":false'; then pass "state-guard: revoked->rotate blocked"; else fail "state-guard: revoked->rotate NOT blocked: $r"; fi

# Verify key shredded
[ ! -f "$KEYS_DIR/context_ed25519.pem" ] && pass "revoke: private key shredded" || fail "revoke: private key still exists"

# ═══════════════════════════════════════════════
# PHASE 6: Key Destruction
# ═══════════════════════════════════════════════
echo "--- Phase 6: Key Destruction ---"

# Re-gen context for destroy test
if [ ! -f "$KEYS_DIR/context_ed25519.pem" ]; then
  openssl genpkey -algorithm ED25519 -out "$KEYS_DIR/context_ed25519.pem" 2>/dev/null
  openssl pkey -in "$KEYS_DIR/context_ed25519.pem" -pubout -out "$KEYS_DIR/context_ed25519.pub" 2>/dev/null
fi

r=$($CLI audit --key destroy context 2>&1)
if echo "$r" | rg -q '"ok":true'; then pass "destroy: command ok"; else fail "destroy: $r"; fi

# ═══════════════════════════════════════════════
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ $FAIL -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "$FAIL FAILURES"; fi
exit $FAIL
