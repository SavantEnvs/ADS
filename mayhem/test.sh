#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
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

UNIT="$SRC/build/test/AdsLibUnitTest/AdsLibUnitTest"
ADSTOOL="$SRC/build/test/AdsTool/adstool"
for b in "$UNIT" "$ADSTOOL"; do
  [ -x "$b" ] || { echo "missing $b — mayhem/build.sh must build it" >&2; emit_ctrf "fructose+golden" 0 1 0; exit 1; }
done

passed=0 failed=0

# 1) Upstream's offline unit tests (fructose: Frame, RingBuffer, SymbolEntry::Parse, the
#    notification parser, AmsAddr/IpV4). fructose is silent on success; a failed assertion prints
#    "Error: ..." / "Test driver failed" on stdout and main() returns the number of failures.
#    Counted as one CTRF test. (This part alone could not tell a no-op binary from a pass —
#    the golden output check below is what makes the oracle behavioral.)
out=$("$UNIT" 2>/dev/null); rc=$?
echo "$out"
if [ "$rc" -eq 0 ] && ! printf '%s\n' "$out" | grep -qE '^(Error: |Test driver failed)'; then
  passed=$((passed + 1))
else
  echo "AdsLibUnitTest failed (rc=$rc)" >&2
  failed=$((failed + 1))
fi

# 2) Golden round trip, as upstream's tools/91_test_AdsTool.sh does: `adstool registry verify`
#    parses a .reg file and re-serialises it; the output must equal the input byte for byte.
#    (No connection is made for `verify`; the target address is only a required argument.)
if "$ADSTOOL" 1.2.3.4.1.1 registry verify < "$SRC/tools/test-data/simple.reg" \
     | diff --text - "$SRC/tools/test-data/simple.reg"; then
  passed=$((passed + 1))
else
  echo "registry verify round trip differs from tools/test-data/simple.reg" >&2
  failed=$((failed + 1))
fi

emit_ctrf "fructose+golden" "$passed" "$failed" 0
