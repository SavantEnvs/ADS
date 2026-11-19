#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="fuzz_ams_connection fuzz_symbol_access fuzz_registry_verify fuzz_ads_file
fuzz_udp_discovery fuzz_rtime_access fuzz_registry_access fuzz_service_access"

# 1) AdsLib (standalone variant, upstream's CMake) with the sanitizer + DWARF-3 flags, so the
#    library code the harnesses reach is instrumented. build/ is gitignored upstream.
#    -fsanitize=fuzzer-no-link adds SanCov to the library only when the fuzzer engine is libFuzzer.
#    Two UBSan checks are relaxed; ASan and the rest of UBSan stay on and halting:
#    - `alignment`: AdsLib reads every AMS/AoE header field through references to members of
#      #pragma pack(1) structs (AmsHeader.h letoh(leLength), Frame::pop's reinterpret_cast), so the
#      check aborts on the first request of every input, before any reply is parsed.
#    - `nonnull-attribute`: Frame::prepend (AdsLib/Frame.cpp) calls memcpy(m_Pos, data, size)
#      unconditionally, and AdsLib passes data == nullptr, size == 0 for empty payloads:
#      AdsDevice::CloseFile -> ReadWriteReqEx2(..., 0, nullptr, ...) -> standalone/AdsLib.cpp
#      prepend(writeData, writeLength) on every AdsFile close, and
#      AdsSyncWriteControlReqEx(..., 0, nullptr) -> prepend(buffer, bufferLength). glibc declares
#      memcpy's pointers nonnull, so the check aborts on these benign zero-length copies.
RELAX="-fno-sanitize=alignment,nonnull-attribute"
FUZZ_CXXFLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
cmake -S . -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DSTANDALONE_ONLY=ON -DWITH_EXAMPLES=OFF -DWITH_TESTS=OFF -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_C_FLAGS="$FUZZ_CXXFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CXXFLAGS" \
      -DCMAKE_C_FLAGS_DEBUG="" -DCMAKE_CXX_FLAGS_DEBUG=""
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target AdsLib
LIBADS="$SRC/build/fuzz/AdsLib/libAdsLib.a"
INC="-I$SRC/AdsLib -I$SRC/AdsLib/standalone"

# 2) Harnesses: libFuzzer binary + standalone reproducer each, LSan off in both.
mkdir -p build/harness
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o build/harness/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/harness/standalone_main.o
for t in $TARGETS; do
  $CXX -std=c++17 $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link -D_GNU_SOURCE $INC \
      -c "$SRC/mayhem/harnesses/$t.cpp" -o "build/harness/$t.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/harness/$t.o" \
      build/harness/lsan_off.o "$LIBADS" -lpthread -o "/mayhem/$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "build/harness/$t.o" build/harness/standalone_main.o \
      build/harness/lsan_off.o "$LIBADS" -lpthread -o "/mayhem/$t-standalone"
done

# 3) Upstream's offline unit tests (AdsLibUnitTest, vendored fructose) and adstool, with the
#    project's NORMAL flags, for mayhem/test.sh.
cmake -S . -B build/test -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DSTANDALONE_ONLY=ON -DWITH_EXAMPLES=OFF -DWITH_TESTS=ON -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build/test -j"$MAYHEM_JOBS" --target AdsLibUnitTest AdsTool
