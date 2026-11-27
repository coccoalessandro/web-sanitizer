#!/usr/bin/env bash
# End-to-end rehearsal of the professor's testing workflow (testing guide, sections 4-5),
# driven through the CLI. Run from the repository root:
#
#   ./scripts/demo.sh                 # full run
#   ./scripts/demo.sh --skip-tests    # skip `cargo test` (faster)
#
# Requirements: cargo, docker, curl, python3. The evil-origin image must be loaded
# (`docker load -i evil-origin.tar`) or the container must already exist.

set -u

PORT=3100
BASE="http://localhost:${PORT}"
OUT="demo_out"
LOG="${OUT}/run.log"
SKIP_TESTS=0
[ "${1:-}" = "--skip-tests" ] && SKIP_TESTS=1

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[32mOK\033[0m %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

for tool in cargo docker curl python3; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
[ -f Cargo.toml ] && [ -d engine ] && [ -d cli ] || fail "run this script from the repository root"

# ---------------------------------------------------------------- 1. build and tests
step "1. Release build"
cargo build --release --quiet || fail "cargo build --release"
ok "target/release/cli built"

if [ "$SKIP_TESTS" -eq 0 ]; then
    step "1b. Test suite"
    TEST_LOG=$(mktemp)
    if cargo test --workspace --quiet >"$TEST_LOG" 2>&1; then
        passed=$(grep -Eo '[0-9]+ passed' "$TEST_LOG" | awk '{s+=$1} END {print s}')
        ok "${passed} tests passed"
    else
        tail -30 "$TEST_LOG"; fail "cargo test --workspace"
    fi
    rm -f "$TEST_LOG"
fi

# ---------------------------------------------------------------- 2-3. evil-origin up
step "2. Starting evil-origin (guide 4.1-4.2)"
if docker ps --format '{{.Names}}' | grep -qx evil-origin; then
    ok "container already running"
elif docker ps -a --format '{{.Names}}' | grep -qx evil-origin; then
    docker start evil-origin >/dev/null || fail "docker start evil-origin"
    ok "existing container started"
elif docker image inspect evil-origin >/dev/null 2>&1; then
    docker run -d -p ${PORT}:${PORT} --name evil-origin evil-origin >/dev/null || fail "docker run"
    ok "container created from the loaded image"
else
    fail "image not loaded: run 'docker load -i evil-origin.tar' first"
fi

step "3. Health check (guide 4.3)"
health=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    health=$(curl -s --max-time 2 "${BASE}/health") && [ -n "$health" ] && break
    sleep 1
done
echo "    ${health}"
echo "$health" | grep -q '"status":"ok"' || fail "evil-origin is not answering on ${BASE}"
ok "evil-origin ready"

# ---------------------------------------------------------------- 4. catalogue
step "4. Scenario catalogue (guide 5.1)"
PATHS_FILE=$(mktemp)
curl -s "${BASE}/scenarios" | python3 -c '
import json, sys
for s in json.load(sys.stdin)["scenarios"]:
    print(s["path"])
' >"$PATHS_FILE" || fail "could not read ${BASE}/scenarios"
count=$(wc -l <"$PATHS_FILE" | tr -d ' ')
[ "$count" -gt 0 ] || fail "empty scenario list"
ok "${count} scenarios listed by the server"

# ---------------------------------------------------------------- 5. sanitise
step "5. Sanitising every scenario through the CLI (guide 5.2)"
rm -rf "$OUT"; mkdir -p "$OUT"
ARGS=()
while IFS= read -r p; do
    ARGS+=(-u "${BASE}${p}")
done <"$PATHS_FILE"
rm -f "$PATHS_FILE"

echo "    ./target/release/cli -u ... (${count} URLs) --trust-internal-host localhost -o ${OUT} -v"
./target/release/cli "${ARGS[@]}" \
    --trust-internal-host localhost \
    -o "$OUT" --report-file "${OUT}/report.json" -v >"$LOG" 2>&1
status=$?
ok "exit code ${status} (1 is expected: some inputs are refused by design)"

# ---------------------------------------------------------------- 6. summary
step "6. Summary"
cleaned=$(grep -c '^Status: Cleaned' "$LOG")
blocked=$(grep -c '^Status: BLOCKED' "$LOG")
errors=$(grep -c '^Error:' "$LOG")
printf '    cleaned: %s   refused: %s   errors: %s   (of %s)\n' "$cleaned" "$blocked" "$errors" "$count"
sed -n '/Batch Execution Summary/,/====/p' "$LOG" | sed 's/^/    /'
echo "    refused inputs:"
grep -B1 '^Status: BLOCKED' "$LOG" | grep '^Source:' | sed 's/^Source: /      - /'
[ "$errors" -eq 0 ] && ok "no scenario failed" || echo "    WARNING: ${errors} scenario(s) ended with an error, see ${LOG}"

# ---------------------------------------------------------------- 7. before / after
step "7. Before / after"
show_pair() {  # $1 = scenario path, $2 = file-name fragment (CLI names are cut at 40 chars)
    raw=$(curl -s --max-time 5 "${BASE}$1" | head -c 300)
    cleaned_file=$(ls "${OUT}"/*"$2"*.cleaned.* 2>/dev/null | head -1)
    echo "    --- $1"
    echo "    original : ${raw}"
    if [ -n "$cleaned_file" ]; then
        echo "    sanitised: $(head -c 300 "$cleaned_file")"
    else
        echo "    sanitised: (no .cleaned file: refused, see the .refused.txt)"
    fi
}
show_pair /html/script-tag     html_script_tag
show_pair /html/inline-handler html_inline_handl   # output names are cut at 40 characters

# ---------------------------------------------------------------- 8. security checks
step "8. Security checks on the sanitised outputs"
hits=$(grep -l -i -E '<script|javascript:|onerror=|169\.254\.169\.254|10\.0\.0\.1' "${OUT}"/*.cleaned.* 2>/dev/null)
if [ -z "$hits" ]; then
    ok "no active construct or internal address in any sanitised output"
else
    echo "$hits" | sed 's/^/    /'; fail "suspicious content found in the files above"
fi
if grep -i -q -E 'cookie|authorization' "${OUT}"/*echo_headers*.cleaned.* 2>/dev/null; then
    fail "echo-headers output contains Cookie/Authorization"
else
    ok "echo-headers: no Cookie/Authorization forwarded"
fi

step "Done"
echo "    full log : ${LOG}"
echo "    reports  : ${OUT}/report.json and ${OUT}/*.report.json"
echo "    outputs  : ${OUT}/*.cleaned.* and ${OUT}/*.refused.txt"