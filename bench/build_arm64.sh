#!/usr/bin/env bash
# build zlib + lua for aarch64 so the cross-arch pairs (x86-64 build vs arm64
# build of the same source) have ground truth. needs aarch64-linux-gnu-gcc; if
# it is not on the host, run the same commands in a container that has it, e.g.
#   docker run --rm -v "$PWD/bench/work:/w" -w /w debian:bookworm-slim sh -c \
#     'apt-get update -qq && apt-get install -y -qq gcc-aarch64-linux-gnu libc6-dev-arm64-cross >/dev/null && sh /w/../build_arm64.sh /w'
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:-$here/work}"
cc=aarch64-linux-gnu-gcc
command -v "$cc" >/dev/null || { echo "need $cc (see the comment at the top)"; exit 1; }
out="$work/builds"
mkdir -p "$out"
z="$work/zlib-1.3.1"
mapfile -t zc < <(ls "$z"/*.c | grep -vE 'example|minigzip|infcover|test|gzclose|gzlib|gzread|gzwrite')
l="$work/lua-5.4.6/src"
mapfile -t lc < <(ls "$l"/*.c | grep -vE '/(lua|luac)\.c$')
for o in O0 O2 O3; do
  "$cc" -shared -fPIC -"$o" -w -I"$z" "${zc[@]}" -o "$out/libz_arm64_${o}.so"
  echo "built libz_arm64_${o}.so"
  "$cc" -shared -fPIC -"$o" -w -DLUA_USE_LINUX -I"$l" "${lc[@]}" -o "$out/liblua_arm64_${o}.so"
  echo "built liblua_arm64_${o}.so"
done
