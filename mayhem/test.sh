#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# RUN upstream's own TAP unit tests for the fuzzed units (test/tap/tests/unit), built by build.sh
# with normal flags. Each prints a TAP plan "1..N" and one "ok"/"not ok" per assertion (known
# digests of known queries, parsed PROXY header fields). A binary whose plan is missing, whose
# assertion count differs from its plan, or that exits non-zero counts its missing assertions
# as failed.
TO="$SRC/mayhem/out/tests"
passed=0; failed=0
for t in c_tokenizer_unit-t pgsql_tokenizer_unit-t proxy_protocol_unit-t pgsql_digest_bounds_unit-t \
         mysql_resultset_framer_unit-t mysql_resultset_framer_traffic_unit-t \
         pgsql_response_framer_unit-t pgsql_response_framer_traffic_unit-t pgsql_command_complete_unit-t \
         gtid_set_unit-t gtid_trxid_interval_unit-t; do
  if [ ! -x "$TO/$t" ]; then echo "MISSING test binary $TO/$t (build.sh bug)" >&2; failed=$((failed+1)); continue; fi
  log="$(mktemp)"
  "$TO/$t" >"$log" 2>&1; rc=$?
  ok=$(grep -c '^ok ' "$log"); nok=$(grep -c '^not ok ' "$log")
  plan=$(sed -n 's/^1\.\.\([0-9][0-9]*\).*/\1/p' "$log" | head -1)
  missing=0
  if [ -z "$plan" ] || [ "$plan" -eq 0 ]; then missing=1
  elif [ $((ok + nok)) -lt "$plan" ]; then missing=$((plan - ok - nok)); fi
  [ "$rc" -ne 0 ] && [ "$nok" -eq 0 ] && [ "$missing" -eq 0 ] && missing=1
  echo "$t: rc=$rc plan=${plan:-none} ok=$ok not_ok=$nok missing=$missing"
  grep '^not ok ' "$log" | head -20
  passed=$((passed + ok)); failed=$((failed + nok + missing))
  rm -f "$log"
done
emit_ctrf "tap" "$passed" "$failed" 0
