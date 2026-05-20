#!/usr/bin/env bash
# build zlib variants and report accuracy numbers. run from repo root:
#   cargo build --release && bench/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
fp="$root/target/release/fnprint"
work="${1:-$here/work}"
[ -x "$fp" ] || { echo "build first: cargo build --release"; exit 1; }
bash "$here/build_zlib.sh" "$work"
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
