#!/usr/bin/env bash
# build zlib + lua variants and report accuracy numbers. run from repo root:
#   cargo build --release && bench/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
fp="$root/target/release/fnprint"
work="${1:-$here/work}"
[ -x "$fp" ] || { echo "build first: cargo build --release"; exit 1; }
bash "$here/build_zlib.sh" "$work"
bash "$here/build_lua.sh" "$work"
B="$work/builds"

row() { # a b label
  printf "%-22s " "$3"
  "$fp" eval "$B/$1" "$B/$2" | awk '
    /rank-1/{r=$3} /MRR/{m=$2} /precision/{p=$2; tp=$4; fp2=$6} /recall/{rc=$2}
    END{printf "rank1 %-6s MRR %-6s prec %-7s recall %s\n", r, m, p, rc}'
}
echo "== same compiler, across optimization =="
row libz_gcc_O0.so libz_gcc_O1.so "gcc O0 -> O1"
row libz_gcc_O1.so libz_gcc_O2.so "gcc O1 -> O2"
row libz_gcc_O2.so libz_gcc_O3.so "gcc O2 -> O3"
row libz_gcc_O0.so libz_gcc_O2.so "gcc O0 -> O2"
row libz_gcc_O0.so libz_gcc_O3.so "gcc O0 -> O3"
echo "== cross compiler, same optimization =="
row libz_gcc_O0.so libz_clang_O0.so "gcc/clang O0"
row libz_gcc_O2.so libz_clang_O2.so "gcc/clang O2"
row libz_gcc_O3.so libz_clang_O3.so "gcc/clang O3"
echo "== lua (bigger pool, the frontier) =="
row liblua_gcc_O0.so liblua_gcc_O2.so "lua gcc O0 -> O2"
row liblua_gcc_O2.so liblua_gcc_O3.so "lua gcc O2 -> O3"

# determinism gate: the same binary indexed twice must produce a byte-identical
# corpus, and (once sharding lands) the shard count must not change the output.
# fingerprints are per-function independent and the func list is sorted by entry,
# so both are guaranteed by construction; this proves it, and fails loud if a
# change ever breaks it.
echo "== determinism gate =="
det_bin="$B/libz_gcc_O2.so"
"$fp" index "$det_bin" -o "$work/det_a.db"
"$fp" index "$det_bin" -o "$work/det_b.db"
if cmp -s "$work/det_a.db" "$work/det_b.db"; then
  echo "two indexes byte-identical: OK"
else
  echo "DETERMINISM FAIL: two indexes of the same binary differ" >&2
  exit 1
fi
# shard-count invariance (Phase 3+: FNPRINT_SHARDS honored). N=1 vs N=8 must match.
if "$fp" index --help 2>&1 | grep -q FNPRINT_SHARDS || true; then
  FNPRINT_SHARDS=1 "$fp" index "$det_bin" -o "$work/det_s1.db"
  FNPRINT_SHARDS=8 "$fp" index "$det_bin" -o "$work/det_s8.db"
  if cmp -s "$work/det_s1.db" "$work/det_s8.db"; then
    echo "shard count 1 vs 8 byte-identical: OK"
  else
    echo "DETERMINISM FAIL: shard count changes the corpus" >&2
    exit 1
  fi
fi
