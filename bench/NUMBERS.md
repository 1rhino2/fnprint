# accuracy numbers

measured on this machine, gcc 15.3 / clang 21, aarch64-linux-gnu-gcc 14 (debian
bookworm cross), unicorn-tci 2.1.6. reproduce with:

    cargo build --release
    bench/build_arm64.sh     # optional, needs the cross gcc (or a container, see the script)
    bench/run.sh

two views per pair. **rank-1** is the print on its own: for each function in
build A (that has enough signal and also exists in B), rank every function in B
by fingerprint similarity, is the top hit the same function. MRR is the mean
reciprocal rank of the correct hit. **aligned** is what `query` and `match` do:
a global 1:1 assignment (best pair first, each function claimed once) rescored
with the call graph. acc is how often the assigned partner is right, prec/recall
are for the pairs it commits to at the 0.88 "same" line.

## zlib 1.3.1 (84 exported + static functions, ~45 with signal)

    pair                rank-1   MRR    | aligned acc   prec    recall
    gcc O0 -> O1         97.1%  0.985  |   97.1%    100.0%    85.3%
    gcc O1 -> O2         93.1%  0.949  |   93.1%    100.0%    86.2%
    gcc O0 -> O2         93.1%  0.949  |   93.1%    100.0%    72.4%
    gcc O0 -> O3         91.3%  0.936  |   87.0%    100.0%    65.2%
    gcc O2 -> O3         56.5%  0.651  |   63.0%     74.2%    50.0%
    gcc/clang O0         95.3%  0.977  |  100.0%    100.0%    93.0%
    gcc/clang O2         59.1%  0.654  |   63.6%     68.0%    38.6%
    gcc/clang O3         44.4%  0.541  |   92.6%    100.0%    92.6%

## lua 5.4.6 (~600 functions with signal, incl. statics)

    pair                rank-1   MRR    | aligned acc   prec    recall
    gcc O0 -> O2         58.6%  0.635  |   57.3%     95.1%    52.0%
    gcc O2 -> O3         82.6%  0.873  |   86.6%     98.7%    84.1%

## cross architecture, x86-64 gcc -> aarch64 gcc

    pair                rank-1   MRR    | aligned acc   prec    recall
    zlib O0 -> O0        97.7%  0.988  |   97.7%    100.0%    95.3%
    zlib O2 -> O2        71.1%  0.793  |   97.8%    100.0%    95.6%
    zlib O0 -> O2        93.1%  0.950  |   89.7%    100.0%    69.0%
    lua  O0 -> O0        89.8%  0.933  |   92.6%     99.9%    92.4%
    lua  O2 -> O2        80.4%  0.858  |   78.6%     99.6%    77.3%

## aarch64 only, across optimization

    pair                rank-1   MRR    | aligned acc   prec    recall
    zlib O0 -> O2        93.1%  0.950  |   93.1%    100.0%    72.4%
    lua  O0 -> O2        62.5%  0.681  |   62.2%     94.9%    55.5%

## reading these

the print alone (rank-1) is the same story as before: rich behavior on at least
one side lands in the 90s, both sides heavily optimized drops toward a coin
flip. what changed in 0.6 is the second column. the 1:1 assignment plus the
call graph is worth little where the print already wins and a lot where it
does not: gcc/clang O3 44% -> 93% at 100% precision, gcc O2 -> O3 56% -> 63%.
cross-arch is easier than cross-opt: the instruction set changes, the
behavior does not, and the call graph is the same graph.

recall at the same line is where the graph shows up most (zlib O0 -> O2 18% ->
72%, lua O2 -> O3 62% -> 84%), because a pair whose neighbours agree gets
lifted over it without the print having to be near-identical.

lua still shows pool size matters: rank-1 over 600 functions is a much harder
bar than over 45.

## stripped-binary spot checks

corpus built from a named build, target `strip --strip-all`, truth is the
unstripped symbol table. 0.6 also merges `.eh_frame` into discovery, so a
stripped `.so` gives up its static functions, not just its exports.

    corpus                 target (stripped)         thr   named  right
    zlib gcc O2            zlib gcc O0               0.6     27     27
    zlib gcc O0            zlib clang O2             0.5     11      9
    zlib gcc O0 (x86-64)   zlib gcc O0 (aarch64)     0.7     42     42
    lua  gcc O0            lua  gcc O2               0.7     59     52

the zlib gcc O0 -> stripped clang O2 row is the one the alignment fixed: 0.5
named 37 with 28 wrong, 27 of them the same `deflateStateCheck` (inlined into
every deflate*/inflate* entry at -O2, and the only thing junk input reaches).

## blanket execution (off by default)

`FNPRINT_BLANKET=4` restarts emulation at unexecuted code and unions the
result (import calls + syscalls only from the restarts). zlib -O2 mean coverage
49% -> 85%. on the bench, aligned acc: gcc O2 -> O3 63 -> 68, but gcc/clang O3
92.6 -> 61.1 and gcc O0 -> O2 93 -> 82. a restart at -O0 runs the helpers -O3
inlined, and unioned into one print that drifts. it needs to be a second print
with its own similarity; until then it stays opt-in.
