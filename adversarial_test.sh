#!/bin/bash
set -e

# Adversarial Penetration Test Script for SEC v1.0
# Probes the system boundaries and checks for common agent / cryptographical loopholes.

echo "=========================================================="
echo "      Adversarial Security Probe Suite - SEC v1.0         "
echo "=========================================================="

# Build binary
echo "[*] Building fresh binary..."
go build -o sec ./cmd/sec

# Setup fresh clean environment
export TEMP_HOME=$(mktemp -d -t sec-adversarial-XXXXXX)
export HOME=$TEMP_HOME
trap "rm -rf $TEMP_HOME" EXIT

echo "[*] Setting up default keypair..."
./sec init

# 1. TEST: KID Path Traversal / Public Key Poisoning
echo -n "[*] KID Path Traversal Probe... "
# Try to sign with a path traversal kid
if ./sec sign --objective "exploit" --allow "*" --kid "../default" 2>&1 | grep -q "invalid KID"; then
    echo "PASSED (KID path validation blocked sign)"
else
    echo "FAILED (KID path validation allowed sign)"
    exit 1
fi

# Try to verify using a manually crafted token containing a traversal kid
# We'll create a token where kid is "../default" to see if it bypasses public key resolution
TRAVERSAL_PAYLOAD='{"jti":"a6d1deb4-3b7d-4bad-9bdd-2b0d7b3dcb6d","kid":"../default","iat":1716681600,"exp":9999999999,"obj":"exploit","allow":["*"]}'
TRAVERSAL_PAYLOAD_B64=$(echo -n "$TRAVERSAL_PAYLOAD" | base64 | tr -d '=' | tr '/+' '_-')
# Signature doesn't even matter, we want to see if resolver blocks or throws SEC_KEY_NOT_FOUND vs path error
TRAVERSAL_TOKEN="${TRAVERSAL_PAYLOAD_B64}.SGVsbG8gd29ybGQ" # dummy signature

./sec verify --token "$TRAVERSAL_TOKEN" --action "api.github.com" 2>err.log || true
if grep -q "invalid KID" err.log; then
    echo "    -> Subtest PASSED (Verifier resolver blocked path traversal)"
else
    echo "    -> Subtest FAILED (Verifier resolver did not block path traversal). Log:"
    cat err.log
    exit 1
fi


# 2. TEST: SQL Injection in JTI
echo -n "[*] SQLite Injection Probe... "
SQLI_JTI="9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' OR '1'='1"
# JTI validation blocks non-UUID structures, so let's verify if Validate() catches this
SQLI_PAYLOAD="{\"jti\":\"${SQLI_JTI}\",\"iat\":1716681600,\"exp\":9999999999,\"obj\":\"exploit\",\"allow\":[\"*\"]}"
SQLI_PAYLOAD_B64=$(echo -n "$SQLI_PAYLOAD" | base64 | tr -d '=' | tr '/+' '_-')
SQLI_TOKEN="${SQLI_PAYLOAD_B64}.SGVsbG8gd29ybGQ"

./sec verify --token "$SQLI_TOKEN" --action "api.github.com" 2>err.log || true
if grep -q -e "jti must be a valid UUID" -e "SEC_INVALID_SIGNATURE" err.log; then
    echo "PASSED (SQL injection payload rejected securely)"
else
    echo "FAILED (SQL injection payload parsed as JTI). Log:"
    cat err.log
    exit 1
fi


# 3. TEST: Signature Tampering and Padding Modification
echo -n "[*] Signature Tampering Probe... "
TOKEN=$(./sec sign --objective "test" --allow "api.github.com/repos/*" --ttl 5m)

# Tamper with signature body (change middle characters to ensure bit alteration)
TAMPERED_SIG="${TOKEN%?????}XXXXX"
./sec verify --token "$TAMPERED_SIG" --action "api.github.com/repos/org/repo" 2>err.log || true
if grep -q "SEC_INVALID_SIGNATURE" err.log; then
    echo "PASSED (Tampered signature rejected)"
else
    echo "FAILED (Tampered signature accepted). Log:"
    cat err.log
    exit 1
fi


# 4. TEST: Glob Path Matching Bypass Probe
echo -n "[*] Glob Path Matching Bypass Probe... "
# The allow list contains a wildcard for repo scope: api.github.com/repos/The-17/agentsecrets/*
TOKEN_WILDCARD=$(./sec sign --objective "test" --allow "api.github.com/repos/The-17/agentsecrets/*" --ttl 5m)

# Attempt to match sibling repository (agentsecrets-other) which contains the prefix but is outside wildcard boundary
./sec verify --token "$TOKEN_WILDCARD" --action "api.github.com/repos/The-17/agentsecrets-other/pulls" 2>err.log || true
if grep -q "SEC_ACTION_NOT_PERMITTED" err.log; then
    echo "PASSED (Bypass blocked: sibling path rejected)"
else
    echo "FAILED (Bypass allowed: sibling path matched wildcard). Log:"
    cat err.log
    exit 1
fi


# 5. TEST: Concurrent Race Conditions (Double Verification Replay Check)
echo -n "[*] Concurrent Replay Attack Race Probe... "
TOKEN_REPLAY=$(./sec sign --objective "test" --allow "*" --ttl 5m)

# Spawn 10 parallel verification requests simultaneously in the background
for i in {1..10}; do
    ./sec verify --token "$TOKEN_REPLAY" --action "api.github.com" >out_$i.log 2>err_$i.log &
done

# Wait for all background verification requests to finish
wait

# We expect exactly ONE process to exit with status 0 (passed) and all others to fail (SEC_TOKEN_REPLAYED)
SUCCESS_COUNT=0
REPLAY_REJECTED_COUNT=0

for i in {1..10}; do
    if [ -f out_$i.log ] && grep -q "jti" out_$i.log; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
    if [ -f err_$i.log ] && grep -q "SEC_TOKEN_REPLAYED" err_$i.log; then
        REPLAY_REJECTED_COUNT=$((REPLAY_REJECTED_COUNT + 1))
    fi
done

if [ "$SUCCESS_COUNT" -eq 1 ] && [ "$REPLAY_REJECTED_COUNT" -eq 9 ]; then
    echo "PASSED (Atomic transaction guarantees first-insert-wins; 1 passed, 9 replayed)"
else
    echo "FAILED (Race condition allowed multiple verifications: Success=$SUCCESS_COUNT, ReplayRejections=$REPLAY_REJECTED_COUNT)"
    exit 1
fi


# 6. TEST: Action Path Traversal Bypass
echo -n "[*] Action Path Traversal Probe... "
TOKEN_TRAVERSAL=$(./sec sign --objective "test" --allow "api.github.com/repos/The-17/agentsecrets/*" --ttl 5m)

# Attempt to escape path using relative segments inside the action parameter
./sec verify --token "$TOKEN_TRAVERSAL" --action "api.github.com/repos/The-17/agentsecrets/../../other-org/other-repo" 2>err.log || true
if grep -q "SEC_ACTION_NOT_PERMITTED" err.log; then
    echo "PASSED (Action path traversal escape blocked)"
else
    echo "FAILED (Action path traversal escape succeeded). Log:"
    cat err.log
    exit 1
fi


echo "=========================================================="
echo "   ALL ADVERSARIAL SECURITY CHECKS PASSED SUCCESSFULLY    "
echo "=========================================================="
