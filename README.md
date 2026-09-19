<p align="center">
  <img src="assets/wordmark.svg" alt="fnprint" width="440">
</p>

fnprint matches functions in binaries by what they *do*, not by what their bytes
or control-flow graphs look like. it runs each function in a tiny emulator with
made-up inputs, records the side effects it produces, and hashes that behavior
into a fingerprint. two functions that behave the same get similar fingerprints,
even if they were built by a different compiler, at a different optimization
level, or for a different CPU.

the point of doing it this way: byte signatures (FLIRT, FunctionID) break the
moment code is recompiled, and CFG matchers (BinDiff, Diaphora) get shaky across
`-O0` vs `-O3` and give up across architectures. behavior survives all of that
a lot better. no training data, no model, one static binary.

three things it does that the others dont:

- **it is safe to point at malware.** the emulator runs in a privilege-separated
  worker under a seccomp jail that forbids exec, sockets, file opens, and
  executable memory outright (unicorn is built as a no-JIT interpreter so it
  never needs one). a crafted binary that pops the emulator gets a process
  that can compute and nothing else. see [SECURITY.md](SECURITY.md). BinDiff,
  Diaphora, BSim, FLIRT and the ML matchers all parse hostile bytes in-process.
- **it matches across architectures.** index the x86-64 build you have
  symbols for, name the stripped aarch64 firmware. the effect model never sees
  the ISA. zlib x86-64 `-O0` vs aarch64 `-O0`: 97.7% of functions named right.
- **`triage` gives you a verdict, not a diff.** two corpora (known-vulnerable,
  patched), a margin, and a review queue of the functions that lean vulnerable.
  thats the n-day workflow as one command.

x86-64 and aarch64 ELF. see [limits](#what-it-is-bad-at) before you trust it.

## show me

<p align="center">
  <img src="assets/demo.gif" alt="fnprint naming functions in a stripped, differently-compiled binary" width="820">
</p>

point it at a stripped binary and a corpus of things you already have names for:

```
$ strip --strip-all mystery.so
$ nm mystery.so
nm: mystery.so: no symbols

$ fnprint index libz.so -o corpus.db          # a build you have symbols for
$ fnprint query mystery.so --corpus corpus.db --threshold 0.6
named 27 function(s):
  addr        sim    graph  name
  0x000022f9  100.0%     0%  adler32_z  (libz.so)
  0x00002a8d  100.0%     0%  compress2  (libz.so)
  0x00004500  100.0%     0%  deflateStateCheck  (libz.so)
  0x0000ad5d  100.0%     0%  inflateBackEnd  (libz.so)
  0x0000b69c  100.0%     0%  inflateStateCheck  (libz.so)
  0x00012f8c  100.0%     0%  _tr_tally  (libz.so)
  ...
```

that run is a fully stripped `-O0` build named from an `-O2` corpus. different
optimization level, zero symbols left, 27 names come back and all 27 are
right. it names what it is confident about and stays quiet about the rest.
(the gif above is from 0.5, which found 9; 0.6 also recovers the static
functions a stripped `.so` hides behind its exports.)

the same thing across CPUs. corpus from the x86-64 build, target is the
aarch64 build of the same source, symbols gone:

```
$ fnprint index libz_x86_64.so -o corpus.db
$ fnprint query libz_arm64_stripped.so --corpus corpus.db
named 42 function(s):
  addr        sim    graph  name
  0x00001af4  100.0%     0%  adler32_z  (libz_x86_64.so)
  0x0000263c  100.0%     0%  compress2  (libz_x86_64.so)
  0x00002958  100.0%   100%  x2nmodp  (libz_x86_64.so)
  0x00002a98  100.0%     0%  crc32_z  (libz_x86_64.so)
  0x000034c4  100.0%   100%  crc32_combine64  (libz_x86_64.so)
  ...
```

42 named, 42 right, from a corpus built for a different CPU.

the other thing it does is diff two builds and tell you which functions changed
behavior, which is handy when a vendor ships a new firmware and you want to know
what actually moved. it works with or without symbol names: with them it aligns
by name, without them it aligns the two builds on behavior plus the call graph,
so two fully stripped firmware images still diff:

```
$ fnprint match old.so new.so
aligned 38 function pairs by behavior + call graph (no symbol names needed)
  unchanged:  31
  changed:    7
  low-signal: 57 (too small to judge)

changed behavior (lowest similarity first):
   30.5%  compress_block
   43.0%  deflate_rle -> deflate_huff
   68.8%  deflate_slow
```

for actual n-day work there is `triage`. build one corpus from the known
vulnerable version of a function and one from the patched version, then rank an
unknown build against both. a function close to the vulnerable side and clearly
separated from the patched side is what you want in front of a human, not just a
single match score you have to interpret:

```
$ fnprint index vuln.so    -o vuln.db
$ fnprint index patched.so -o patched.db
$ fnprint triage mystery.so --vuln vuln.db --patched patched.db
43 functions triaged: 1 look vulnerable, 0 patched, 42 inconclusive

review queue (vuln-leaning, strongest first):
   addr         vuln%  patched%  margin  matches
   0x000022f9  100.0     27.3   +72.7  adler32_z vs crc32_z
```

the 42 functions that are identical in both versions come back inconclusive on
purpose, they can't be pinned to either side and shouldn't be flagged. `--margin`
and `--min-sim` control how hard the two sides have to separate before it commits.

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
- calls are named from the import table only (plt stubs, got slots), because
  that is the part that survives `strip`. internal calls are anonymous in the
  print and become call-graph edges instead, from a static sweep of the body.
- naming and diffing are a global 1:1 alignment, not a best-hit-per-function
  lookup: a corpus function can be claimed once, best pair first, then the
  assignment is rescored twice with a call-graph term (how many of a pair's
  paired callers and callees are paired with each other). that is what tells
  two behavioral twins apart, and what stops 27 `-O2` functions that all inline
  the same state check from all claiming it.

no training data, no model. the same idea shows up in the literature as
Blanket Execution (Egele et al, USENIX Security 2014); fnprint is a practical,
maintained take on it with a CLI you can actually use. the effect model is
arch-neutral by construction, which is why x86-64 and aarch64 prints of the
same source line up without anything learned.

## install

needs a rust toolchain, cmake, and a C toolchain. unicorn (the no-JIT fork)
and capstone are built from source by cargo, nothing to apt install.

```
cargo install --path cli
# or just
cargo build --release   # binary at target/release/fnprint
```

## usage

```
fnprint index <binary> [-o out.db]      fingerprint every function, optionally to a db
fnprint match <a> <b>                   diff two binaries (or .db files) by behavior
fnprint query <target> --corpus <db>    name unknown functions from a corpus
fnprint triage <t> --vuln <db> --patched <db>   rank a build against vuln vs patched corpora
fnprint eval <a> <b>                     accuracy metrics using symbol names as truth
fnprint dump <binary> <func>            print the recorded effect trace (debugging)
fnprint completions <shell>             print a shell completion script to stdout
```

`match` and `query` take either an ELF or a `.db` you built with `index`, so you
can fingerprint a corpus once and reuse it. `index -o` appends, so a corpus can
hold several binaries.

`match --align` forces the name-free alignment on a pair that has symbols, to
see what the behavior-only view says. `--graph-weight` (global, default 1.0)
sets how much a consistent call-graph neighbourhood lifts a pair when
aligning; `0` scores every function on its own behavior.

`match`, `query`, and `triage` take `--limit N` to cap how many rows the human
tables print (0 = all). `json` and `r2` output are never capped, so scripts get
everything.

`completions` writes a script for `bash`, `zsh`, `fish`, `powershell`, or
`elvish`, e.g.
`fnprint completions bash > ~/.local/share/bash-completion/completions/fnprint`.

piping any output into something that stops reading early (`| head`) exits
quietly, so the tables are safe to skim without `--limit`.

## machine output

every command takes a global `--format`:

```
fnprint query mystery.so --corpus corpus.db --format json > names.json
fnprint query mystery.so --corpus corpus.db --format r2   > fnprint.r2
```

`json` is a stable schema for scripts (and the Ghidra import stub in `contrib/`),
`r2` emits `afn` rename commands you run inside rizin/radare2 with `. fnprint.r2`.
symbol names from the target are sanitized before they hit either, so a crafted
name can't inject r2 commands. schemas and setup are in
[docs/integrations.md](docs/integrations.md).

indexing is single-process by default. `FNPRINT_SHARDS=N fnprint index ...` spreads
a large index across N jailed workers; the corpus is byte-identical whatever N is.
it only helps on big, function-rich binaries, so it's off unless you ask for it.

## accuracy

two numbers per pair. rank-1 is the print on its own: for a function in build
A, rank every function in B by similarity, is the top hit the right one.
aligned is what `query` and `match` actually do: the 1:1 assignment with the
call graph, how often the partner is right, and precision/recall of the pairs
it commits to at the "same" threshold. zlib 1.3.1 (84 functions) and lua 5.4.6
(~600 functions with signal), reproducible with `bench/run.sh`:

| pair                   | rank-1 | aligned acc | aligned prec |
|------------------------|--------|-------------|--------------|
| gcc O0 -> O1           | 97.1%  | 97.1%       | 100.0%       |
| gcc O0 -> O2           | 93.1%  | 93.1%       | 100.0%       |
| gcc O0 -> O3           | 91.3%  | 87.0%       | 100.0%       |
| gcc O2 -> O3           | 56.5%  | 63.0%       | 74.2%        |
| gcc/clang O0           | 95.3%  | 100.0%      | 100.0%       |
| gcc/clang O3           | 44.4%  | 92.6%       | 100.0%       |
| lua gcc O0 -> O2       | 58.6%  | 57.3%       | 95.1%        |
| lua gcc O2 -> O3       | 82.6%  | 86.6%       | 98.7%        |
| zlib x86-64 -> aarch64, O0 | 97.7% | 97.7%    | 100.0%       |
| zlib x86-64 -> aarch64, O2 | 71.1% | 97.8%    | 100.0%       |
| lua x86-64 -> aarch64, O0  | 89.8% | 92.6%    | 99.9%        |
| lua x86-64 -> aarch64, O2  | 80.4% | 78.6%    | 99.6%        |

full table in [bench/NUMBERS.md](bench/NUMBERS.md).

the honest read: when at least one side has some behavioral richness it lands
in the 90s. both sides heavily optimized on the same arch is the hard case for
the print alone (gcc O2 vs O3 is a coin flip on rank-1) and that is where the
1:1 assignment and the call graph earn their keep: gcc/clang O3 goes from 44%
to 93% aligned, at 100% precision. cross-arch is easier than cross-opt, the
instruction set changes but the behavior does not. it abstains (declines a
confident "same" call) on what it isn't sure about, which is why precision
stays high while recall at the same threshold is lower.

## what it is bad at

- tiny functions. thunks and one-line accessors do not do enough to fingerprint,
  so it withholds them (that is the "low-signal" and "with enough signal" counts).
- pure compute. two checksums that both read a buffer and return a number look
  alike, because from the outside they nearly are.
- deep logic behind a real precondition. microexecution with junk input exercises
  a function's entry behavior. a change buried in a state we never reach with junk
  input will not show up in `match`. it catches structural and early-path changes,
  not every deep tweak.
- heavy optimization on both sides, as the numbers above show. the call graph
  helps a lot but a function whose neighbours are all thunks gets no help.
- heavy obfuscation (vm-based especially) will wreck it.
- a statically linked target against a dynamically linked corpus: the calls
  that name as `memcpy` on one side are anonymous on the other.

## prior art, and where this sits

- FLIRT / FunctionID / Lumina / zignatures: byte signatures. exact, fast, break
  on recompile. run them first; fnprint is for what they did not name.
- BinDiff / Diaphora: graph structure, mature, in IDA. the 1:1 assignment and
  call-graph propagation here are the same idea applied on top of behavior
  instead of structure, so it holds across opt levels and across CPUs where
  CFG shape does not.
- Ghidra BSim: decompiler feature vectors over a real database. scales to
  millions of functions, which this does not try to. it needs Ghidra and
  postgres; this is one binary and a sqlite file.
- Asm2Vec / SAFE / jTrans: learned embeddings. strong, but need training and do
  not generalize to architectures nobody trained on.
- microexecution (Godefroid, 2014) and Blanket Execution (Egele et al, 2014):
  the academic roots of this approach. no maintained tool shipped it.

none of them run the analysis of a hostile file inside a jail.

## roadmap

- mips and arm32. aarch64 landed in 0.6; each arch is the register seeding,
  the call/ret/branch decode, and its plt shape.
- blanket execution as a second print. restarting emulation at unexecuted
  code is in (`FNPRINT_BLANKET=N`, coverage 49% -> 85% on zlib -O2) but off
  by default: unioned into the one print it drifts across opt levels (a
  restart at -O0 runs helpers -O3 inlined). it wants its own similarity,
  weighted in, not a union. the numbers are in `fnprint-emu`.
- pe and mach-o loaders.
- rizin/radare2 export ships (`--format r2`), and there is a ghidra script in
  `contrib/` that applies `query` names and shows the triage queue. a packaged
  extension is next.

## development

there's a `Makefile` with the common tasks. `make ci` runs the same gate as the
build-test CI job (fmt check, clippy, tests) before you push.

```
make build      # release binary
make test       # cargo test --all
make ci         # fmt-check + clippy -D warnings + test
make deny       # cargo deny (advisories, bans, licenses, sources)
make bench      # accuracy numbers (needs gcc/clang + zlib source)
```

release history is in [CHANGELOG.md](CHANGELOG.md).

## license

MIT. see [LICENSE](LICENSE).
