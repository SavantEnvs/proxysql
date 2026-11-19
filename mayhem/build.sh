#!/usr/bin/env bash
#
# mayhem/build.sh — ProxySQL fuzz harnesses + the upstream unit tests for the code they fuzz.
#
# ProxySQL's full build (make deps/lib/src) compiles ~25 vendored dependencies (openssl, libpq,
# mariadb client, curl, re2/abseil, ...) and takes well over an hour; the parsers fuzzed here are
# self-contained translation units of lib/ that need none of it:
#   lib/c_tokenizer.cpp        MySQL query digest tokenizer   (every client COM_QUERY)
#   lib/pgsql_tokenizer.cpp    PostgreSQL query digest tokenizer (every client 'Q'/Parse)
#   lib/proxy_protocol_info.cpp PROXY protocol v1 header parser + proxy_protocol_networks subnet matching
#   lib/MySQLResultsetFramer.cpp + MySQLProtocolUtils.cpp  MySQL backend response framing/OK/ERR/EOF
#   lib/PgSQLResponseFramer.cpp + PgSQLCommandComplete.cpp + PgSQLErrorFields.cpp  PgSQL backend messages
#   lib/proxysql_gtid.cpp      MySQL/MariaDB GTID and GTID-set parsing (backend session tracking)
# They are compiled from the tree with $SANITIZER_FLAGS, linked with mayhem/shim/unit_test_shim.cpp,
# which defines the per-thread digest settings MySQL_Thread.cpp/PgSQL_Thread.cpp own in the daemon.
#
# Outputs: /mayhem/fuzz_* (libFuzzer) + /mayhem/fuzz_*-standalone, /mayhem/afl_mysql_query_digest
# (upstream's AFL harness, test/afl_digest_test), and mayhem/out/tests/* (upstream unit tests from
# test/tap/tests/unit, built with normal flags) that mayhem/test.sh runs.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"          # gitignored by upstream's `out/` rule
mkdir -p "$OUT/fuzz" "$OUT/tests"
INC=(-I"$SRC/mayhem/shim" -I"$SRC/include" -I"$SRC/mayhem/harnesses")
CXXSTD=(-std=c++17 -w)

# 1) The project units, sanitized, with DWARF 3.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fno-omit-frame-pointer"
# lib/c_tokenizer.cpp:1389 computes `stage_2_st->pre_it_pos - (...) - 6` while pre_it_pos is still
# NULL on EVERY query (digit-grouping stage 2), and only compares the result; UBSan's
# pointer-overflow check halts on it before any input gets further, so that one check (and only it)
# is relaxed on that one file. ASan and every other UBSan check stay on and halting.
C_TOKENIZER_RELAX="-fno-sanitize=pointer-overflow"
# Fuzzer objects carry SanCov (-fsanitize=fuzzer-no-link); the standalone reproducers get their own
# objects without it, so they link with no libFuzzer/SanCov runtime (also with SANITIZER_FLAGS empty).
HARNESSES=(fuzz_mysql_query_digest.cpp fuzz_pgsql_query_digest.cpp fuzz_proxy_protocol.cpp
           fuzz_mysql_resultset_framer.cpp fuzz_pgsql_response_framer.cpp fuzz_gtid.cpp)
build_objs() {  # <dir> <extra flags>
  local dir="$OUT/$1" extra="$2" s o relax
  mkdir -p "$dir"
  for s in lib/c_tokenizer.cpp lib/pgsql_tokenizer.cpp lib/proxy_protocol_info.cpp \
           lib/MySQLProtocolUtils.cpp lib/MySQLResultsetFramer.cpp \
           lib/PgSQLResponseFramer.cpp lib/PgSQLCommandComplete.cpp lib/PgSQLErrorFields.cpp lib/proxysql_gtid.cpp \
           mayhem/shim/unit_test_shim.cpp mayhem/lsan_off.cc "${HARNESSES[@]/#/mayhem/harnesses/}"; do
    o="$dir/$(basename "${s%.*}").o"
    relax=""; [ "$s" = lib/c_tokenizer.cpp ] && [ -n "$SANITIZER_FLAGS" ] && relax="$C_TOKENIZER_RELAX"
    $CXX "${CXXSTD[@]}" $FUZZ_CFLAGS $extra $relax "${INC[@]}" -c "$s" -o "$o"
  done
}
build_objs fuzz "-fsanitize=fuzzer-no-link"
build_objs standalone ""
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone/standalone_main.o"
LIB="c_tokenizer.o pgsql_tokenizer.o proxy_protocol_info.o MySQLProtocolUtils.o MySQLResultsetFramer.o"
LIB="$LIB PgSQLResponseFramer.o PgSQLCommandComplete.o PgSQLErrorFields.o proxysql_gtid.o unit_test_shim.o lsan_off.o"

# 2) libFuzzer harnesses + standalone reproducers.
for h in "${HARNESSES[@]%.cpp}"; do
  (cd "$OUT/fuzz" && $CXX $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "$h.o" $LIB -o "$SRC/$h")
  (cd "$OUT/standalone" && $CXX $FUZZ_CFLAGS standalone_main.o "$h.o" $LIB -o "$SRC/$h-standalone")
done

# 3) Upstream's AFL persistent-mode harness (test/afl_digest_test), kept on AFL. Its own Makefile
#    is stale (no mysql.h on the include path); proxysql_utils.h needs mysql.h only for types, taken
#    from the apt libmariadb-dev headers. It defines the mysql_thread___ settings itself. Upstream's
#    Makefile used afl-g++-fast -fpermissive to accept the harness passing unsigned char* where the
#    tokenizer takes const char*; the base's AFL gcc plugin does not load, so it is built with
#    afl-clang-fast++ and mayhem/shim/afl_digest_compat.h supplies the pointer-converting overload.
AFLO="$OUT/afl"; mkdir -p "$AFLO"
AFL_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -pthread"
relax=""; [ -n "$SANITIZER_FLAGS" ] && relax="$C_TOKENIZER_RELAX"
afl-clang-fast++ "${CXXSTD[@]}" $AFL_FLAGS $relax -I"$SRC/include" -c lib/c_tokenizer.cpp -o "$AFLO/c_tokenizer.o"
afl-clang-fast++ "${CXXSTD[@]}" $AFL_FLAGS -c mayhem/lsan_off.cc -o "$AFLO/lsan_off.o"
afl-clang-fast++ "${CXXSTD[@]}" $AFL_FLAGS -I"$SRC/include" -I/usr/include/mariadb \
  -include "$SRC/mayhem/shim/afl_digest_compat.h" \
  test/afl_digest_test/afl_mysql_query_digest.cpp "$AFLO/c_tokenizer.o" "$AFLO/lsan_off.o" \
  -o "$SRC/afl_mysql_query_digest"

# 4) Upstream unit tests for these units (test/tap/tests/unit), NORMAL flags, no sanitizers.
TO="$OUT/tests"; TINC=(-I"$SRC/mayhem/shim" -I"$SRC/include" -I"$SRC/test/tap/tap")
TFLAGS="-O1 $COVERAGE_FLAGS"
TOBJS=()
for s in lib/c_tokenizer.cpp lib/pgsql_tokenizer.cpp lib/proxy_protocol_info.cpp \
         lib/MySQLProtocolUtils.cpp lib/MySQLResultsetFramer.cpp \
         lib/PgSQLResponseFramer.cpp lib/PgSQLCommandComplete.cpp lib/PgSQLErrorFields.cpp lib/proxysql_gtid.cpp \
         test/tap/tap/tap.cpp mayhem/shim/unit_test_shim.cpp; do
  o="$TO/$(basename "${s%.*}").o"
  $CXX "${CXXSTD[@]}" $TFLAGS "${TINC[@]}" -c "$s" -o "$o"
  TOBJS+=("$o")
done
UNIT_TESTS="c_tokenizer_unit-t pgsql_tokenizer_unit-t proxy_protocol_unit-t
  mysql_resultset_framer_unit-t mysql_resultset_framer_traffic_unit-t
  pgsql_response_framer_unit-t pgsql_response_framer_traffic_unit-t pgsql_command_complete_unit-t
  gtid_set_unit-t gtid_trxid_interval_unit-t"
# The framer tests are compiled out unless PROXYSQLFFTO is defined (upstream's PROXYSQL31 tier
# defines it; the framer sources themselves do not depend on it).
for t in $UNIT_TESTS; do
  $CXX "${CXXSTD[@]}" $TFLAGS -DPROXYSQLFFTO "${TINC[@]}" "test/tap/tests/unit/$t.cpp" "${TOBJS[@]}" -o "$TO/$t"
done
# This one #includes lib/pgsql_tokenizer.cpp itself.
$CXX "${CXXSTD[@]}" $TFLAGS "${TINC[@]}" test/tap/tests/unit/pgsql_digest_bounds_unit-t.cpp \
  "$TO/c_tokenizer.o" "$TO/tap.o" "$TO/unit_test_shim.o" -o "$TO/pgsql_digest_bounds_unit-t"
echo "build.sh: done"
