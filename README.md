<p align="center">
  <img src="assets/wordmark.svg" alt="fnprint" width="440">
</p>

fnprint matches functions in binaries by what they *do*, not by what their bytes
or control-flow graphs look like. it runs each function in a tiny emulator with
made-up inputs, records the side effects it produces, and hashes that behavior
into a fingerprint. two functions that behave the same get similar fingerprints,
even if they were built by a differet compiler or at a different optimization
level.

the point of doing it this way: byte signatures (FLIRT, FunctionID) break the
moment code is recompiled, and CFG matchers (BinDiff, Diaphora) get shaky across
`-O0` vs `-O3`. behavior survives both a lot better.

x86-64 ELF only for now. see [limits](#what-it-is-bad-at) before you trust it.

## show me

point it at a stripped binary and a corpus of things you already have names for:

```
$ strip --strip-all mystery.so
$ nm mystery.so
nm: mystery.so: no symbols

$ fnprint index libz.so -o corpus.db          # a build you have symbols for
$ fnprint query mystery.so --corpus corpus.db
named 9 function(s):
  0x000022f9  100.0%  adler32_z
  0x00002a8d  100.0%  compress2
  0x0000ad5d  100.0%  inflateBackEnd
  0x0000adc4   86.7%  inflate_fast
  0x00002e67   80.5%  crc32_z
  ...
```

that run is a fully stripped `-O0` build named from an `-O2` corpus. different
optimization level, zero symbols left, and the names come back right. it names
what it is confident about and stays quiet about the rest.

the other thing it does is diff two builds and tell you which functions changed
behavior, which is handy when a vendor ships a new firmware and you want to know
what actually moved:

```
$ fnprint match old.so new.so
compared 84 functions present in both
  unchanged:  53
  changed:    1
  low-signal: 31 (too small to judge)

changed behavior (lowest similarity first):
   61.7%  deflate_stored
```

## how it works

for each function:

- map the binary and jump to the function with junk in the argument registers.
- any read from memory we did not set up returns a deterministic value and the
  page gets mapped on the fly. wild pointers never crash the run, and the same
  input always gives the same trace. this is Godefroid's microexecution trick.
- calls to other functions get stubbed (recorded, then skipped) so we never
  dive into libc and the run stays about *this* function.
- we log an arch-neutral stream of effects: which argument buffers and struct
  fields it reads and writes, what value classes it writes (a copy of an input,
  a small constant, a pointer), calls it makes, branches it takes, what it
  returns. absolute addresses are thrown away, only offsets and shapes are kept.
- that stream gets turned into shingles and a minhash signature. similarity is
  the fraction of matching minhash slots, which estimates how much two functions'
  behavior overlaps. an LSH band index keeps queries from comparing everything
  against everything.

no training data, no model. the same idea shows up in the literature as
Blanket Execution (Egele et al, USENIX Security 2014); fnprint is a practical,
maintained take on it with a CLI you can actually use.

## install

needs a rust toolchain and the unicorn + capstone libraries.

```
# debian/ubuntu/kali
sudo apt install libunicorn-dev libcapstone-dev

cargo install --path cli
# or just
cargo build --release   # binary at target/release/fnprint
```

## usage

```
fnprint index <binary> [-o out.db]      fingerprint every function, optionally to a db
fnprint match <a> <b>                   diff two binaries (or .db files) by behavior
fnprint query <target> --corpus <db>    name unknown functions from a corpus
fnprint eval <a> <b>                     accuracy metrics using symbol names as truth
fnprint dump <binary> <func>            print the recorded effect trace (debugging)
```

`match` and `query` take either an ELF or a `.db` you built with `index`, so you
can fingerprint a corpus once and reuse it.

## accuracy

rank-1 accuracy is: for a function in build A, rank every function in build B by
similarity, is the top hit the right one. that is exactly the stripped-naming
task. measured on zlib 1.3.1 (84 functions), reproducible with `bench/run.sh`:

| pair            | rank-1 | precision |
|-----------------|--------|-----------|
| gcc O0 -> O1    | 97.1%  | 93.8%     |
| gcc O0 -> O2    | 93.1%  | 83.3%     |
| gcc O0 -> O3    | 91.3%  | 100.0%    |
| gcc/clang O0    | 97.7%  | 97.1%     |
| gcc O2 -> O3    | 56.5%  | 66.7%     |
| gcc/clang O2    | 59.1%  | 50.0%     |

full table plus a second library (lua) in [bench/NUMBERS.md](bench/NUMBERS.md).

the honest read: when at least one side has some behavioral richness (anything
with `-O0`/`-O1`, or a cross-compiler pair at `-O0`) it lands in the 80-98%
range. when both sides are heavily optimized the behavior we can observe gets
thin and it drops toward a coin flip. that is the hard frontier for a single
pass, training-free matcher and this does not pretend otherwise.

## what it is bad at

- tiny functions. thunks and one-line accessors do not do enough to fingerprint,
  so it withholds them (that is the "low-signal" and "with enough signal" counts).
- pure compute. two checksums that both read a buffer and return a number look
  alike, because from the outside they nearly are.
- deep logic behind a real precondition. microexecution with junk input exercises
  a function's entry behavior. a change buried in a state we never reach with junk
  input will not show up in `match`. it catches structural and early-path changes,
  not every deep tweak.
- heavy optimization on both sides, as the numbers above show.
- heavy obfuscation (vm-based especially) will wreck it.

## prior art, and where this sits

- FLIRT / FunctionID / Lumina: byte signatures. exact, fast, break on recompile.
- BinDiff / Diaphora: graph structure. good, but fragile across opt and arch.
- Ghidra BSim: decompiler feature vectors. closer in spirit, single-arch-ish.
- Asm2Vec / SAFE / jTrans: learned embeddings. strong, but need training and do
  not generalize to architectures nobody trained on.
- microexecution (Godefroid, 2014) and Blanket Execution (Egele et al, 2014):
  the academic roots of this approach. no maintained tool shipped it.

fnprint is the training-free, behavior-first option. the effect model is already
architecture-neutral, which is the groundwork for matching across CPUs.

## roadmap

- arm64 and mips, so you can fingerprint a function on x86 and find it in a
  stripped router firmware. the effect model is already arch-neutral, this is
  mostly per-arch emulator plumbing.
- smarter path coverage. naive branch flipping is in the code (`explore_depth`,
  off by default) but it adds build-specific noise on impossible paths and hurt
  cross-build accuracy in testing, so it needs a path-consistency filter before
  it earns its keep.
- pe and mach-o loaders.
- ghidra / ida plugins that call the cli and rename matched functions in place.

## license

MIT. see [LICENSE](LICENSE).
