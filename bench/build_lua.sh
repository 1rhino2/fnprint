#!/usr/bin/env bash
# build lua 5.4.6 as a shared lib at O0..O3 under gcc and clang. lua is a bigger,
# denser pool (~560 signal-bearing funcs) than zlib, so it stresses the matcher
# at scale. the symbol table is the accuracy ground truth, same as zlib.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:-$here/work}"
ver=5.4.6
mkdir -p "$work"
cd "$work"
if [ ! -d "lua-$ver" ]; then
  if [ ! -f lua.tgz ]; then
    curl -sSL "https://www.lua.org/ftp/lua-$ver.tar.gz" -o lua.tgz
  fi
  tar xzf lua.tgz
fi
src="$work/lua-$ver/src"
out="$work/builds"
mkdir -p "$out"
# every .c except the two with their own main(): lua.c (interpreter) and
# luac.c (bytecode compiler). the rest is the library we want to fingerprint.
mapfile -t cfiles < <(ls "$src"/*.c | grep -vE '/(lua|luac)\.c$')
for cc in gcc clang; do
  command -v "$cc" >/dev/null || { echo "skip $cc (not installed)"; continue; }
  for o in O0 O1 O2 O3; do
    "$cc" -shared -fPIC -"$o" -w -DLUA_USE_LINUX -I"$src" "${cfiles[@]}" -o "$out/liblua_${cc}_${o}.so"
    echo "built liblua_${cc}_${o}.so"
  done
done
