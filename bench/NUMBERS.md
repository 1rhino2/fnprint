# accuracy numbers

measured on this machine, gcc 15.3 / clang, unicorn 2.1.4. reproduce with:

    cargo build --release
    bench/run.sh

the metric is rank-1 accuracy: for each function in build A (that has enough
signal and also exists in B), rank every function in B by fingerprint
similarity and check whether the top hit is the same function. that is exactly
the "name a stripped function from a corpus" task. MRR is mean reciprocal rank
of the correct hit. precision@same is how often a >=0.88 "same" call is right.

## zlib 1.3.1 (84 exported functions)

    pair              rank-1   MRR     precision
    gcc O0 -> O1       97.1%   0.985    93.8%
    gcc O1 -> O2       93.1%   0.949    91.7%
    gcc O0 -> O2       93.1%   0.949    83.3%
    gcc O0 -> O3       91.3%   0.936   100.0%
    gcc O2 -> O3       56.5%   0.651    66.7%
    gcc/clang O0       97.7%   0.988    97.1%
    gcc/clang O2       59.1%   0.654    50.0%
    gcc/clang O3       44.4%   0.542    26.5%

## lua 5.4.6 (~560 functions with signal, incl. statics)

    pair              rank-1   notes
    gcc O0 -> O2       48.6%   harder: rank-1 over a ~560 function pool
    gcc O2 -> O3       72.2%

## reading these

the pattern is consistent: when at least one side carries behavioral richness
(anything involving O0/O1, or cross-compiler at O0) it lands 82-98%. when both
sides are heavily optimized (O2/O3, worse cross-compiler) the behavior we can
observe gets thin and collision-prone and it drops toward a coin flip. that is
the honest frontier for a training-free, single-pass behavioral matcher.

lua also shows pool size matters: rank-1 over 560 functions is a much harder
bar than over 84, so those numbers sit lower even though the tool is unchanged.

## stripped-binary spot check

corpus built from zlib gcc -O2 (named), queried against a fully stripped
(`strip --strip-all`, zero symbols) gcc -O0 build at threshold 0.6: it named 9
functions and all 9 were correct (adler32_z, compress2, inflateBackEnd,
_tr_tally, inflate_fast, crc32_z, _tr_stored_block, _tr_align, uncompress2).
low threshold on purpose: it withholds what it isn't sure about.
