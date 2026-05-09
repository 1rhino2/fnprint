#!/usr/bin/env bash
# build zlib at O0..O3 under gcc and clang so we have ground-truth pairs.
# the symbol table (function names) is the ground truth for accuracy.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:-$here/work}"
ver=1.3.1
mkdir -p "$work"
cd "$work"
if [ ! -d "zlib-$ver" ]; then
  if [ ! -f zlib.tgz ]; then
    curl -sSL "https://github.com/madler/zlib/archive/refs/tags/v$ver.tar.gz" -o zlib.tgz
  fi
  tar xzf zlib.tgz
fi
src="$work/zlib-$ver"
out="$work/builds"
mkdir -p "$out"
mapfile -t cfiles < <(ls "$src"/*.c | grep -vE 'example|minigzip|infcover|test|gzclose|gzlib|gzread|gzwrite')
for cc in gcc clang; do
  command -v "$cc" >/dev/null || { echo "skip $cc (not installed)"; continue; }
  for o in O0 O1 O2 O3; do
    "$cc" -shared -fPIC -"$o" -w -I"$src" "${cfiles[@]}" -o "$out/libz_${cc}_${o}.so"
    echo "built libz_${cc}_${o}.so"
  done
done
