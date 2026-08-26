# fnprint security audit

Append-per-release audit record, oldest first. The 0.3.0 audit is below; the
0.3.2 exploitation-focused audit is at the end of the file.

# 0.3.0 audit (20-lane, 2026-08-22)

Full parallel audit of fnprint 0.3.0 (the shipped crates.io / main state) plus the
unicorn-engine-tci fork. 20 independent lanes, source-read only (no builds).
Written 2026-08-22.

## Verdict

No memory-safety bug, no sandbox escape, no injection, no info leak, no unsound
unsafe. The two load-bearing guarantees both hold and were each confirmed by two
separate lanes:

- the seccomp jail forbids host executable memory (PROT_EXEC deny + /proc/self/maps
  W^X check), no enumerated bypass survived (pkey_mprotect, memfd, shmat,
  remap_file_pages, mremap, io_uring, process_vm_writev all killed or EPERM);
- the TCI engine never needs an executable page at the C level (code buffer mapped
  RW-only, static RWX path dead, pure bytecode interpreter, hooks via C helpers).

SECURITY.md is honest and well-calibrated; every claim is backed by code, the
"9/10 not 10" residuals are all disclosed. The audit found nothing that lowers the
9. What it found is a set of hardening / DoS-containment / consistency items, none
of which is a memory-safety or escape defect.

## Findings, ranked (deduplicated; [lanes] = how many independent lanes agreed)

### 1. clone3 unconditionally allowed defeats the namespace block [lanes 1, 3; noted by 20] - the one posture item
SYS_clone3 is on the allowlist with no arg filter, while unshare/setns are killed
and clone is flag-gated to deny CLONE_NEWUSER. clone3's flags sit behind a pointer
BPF can't deref, so a popped worker can clone3(CLONE_NEWUSER) and get the
unprivileged userns everything else is wired to deny. Not a standalone escape
(filters + no_new_privs inherit across the clone), but userns creation is the
classic kernel-LPE entry gadget the jail tries to shut. Also contradicts a
fnprint-core comment claiming clone3 is forbidden after lockdown.
Fix: return Errno(ENOSYS) for clone3 (not EPERM). glibc pthread_create falls back
to the already-gated clone specifically on ENOSYS, so threads keep working while
the userns hole closes (systemd's approach). NEEDS a build to verify qemu's helper
threads fall back cleanly. If it holds, this closes one of the documented residuals.

### 2. emu read hook has no rep-string cap (write hook does) [lanes 8, 9] - CPU DoS
A crafted `rep scasb`/`lodsb`/`cmpsb` with RCX seeded huge is ONE instruction, so
it dodges instr_cap/visit_cap, and reads dedup so max_effects never fires. It scans
up to the 1GiB max segment one byte at a time (~1e9 hook dispatches), stopped only
by the wall-clock timeout or (hard floor) RLIMIT_CPU killing the whole worker.
Serialized behind EMU_LOCK, so a small binary with ~40 such functions burns a whole
index run. Availability only (fingerprints stay stable). Breaks the doc's
"deterministic, timeout-independent termination" claim.
Fix: mirror the write-hook guard with a raw read-iteration counter on Rec that
emu_stops past instr_cap*K.

### 3. parent sets no RLIMIT_AS but comments claim it does [lanes 12, 17] - self-DoS
main.rs:28 and db/lib.rs:138 justify the 128MiB MAX_REPLY cap by saying the reply
"stays bounded by the parent's own RLIMIT_AS" - but setrlimit only runs in the
child, never the parent. A popped worker's ~128MiB reply decodes to ~3GB transient
in the parent before validation. Relevant given this host's OOM-reboot history.
Fix: set Resource::As on the parent early, or lower MAX_REPLY, or stream-validate;
at minimum correct the two false comments.

### 4. CI apt-installs libunicorn-dev / libcapstone-dev [lane 16] - regression masking
Dead weight today (fork always builds from source, static), but if someone later
re-enables dynamic_linkage / default-features / swaps back to stock unicorn, a
prebuilt system JIT lib in the CI image would link and CI stays green, silently
reintroducing the exec code buffer. Fix: drop both apt packages so a regression
fails loudly.

### 5. fork ships a dynamic_linkage feature [lanes 14, 16] - runtime footgun (non-default)
With dynamic_linkage the crate links dylib=unicorn; the fork keeps upstream soname
libunicorn.so.2 and sets no rpath, so on a host with stock libunicorn installed,
ld.so resolves to the system JIT build at runtime, voiding no-JIT. fnprint uses the
static default so it's not exposed. Fix: delete dynamic_linkage from this security
fork (or compile_error! it / set rpath + distinct soname).

### Low / hardening
- Loader discover() clones symbol names uncapped: crafted huge symtab is an F^2
  input->alloc amplification (~1.5MB file past RLIMIT_AS). Jail-contained. [lane 7]
- Db::candidates() lacks the MAX_TEXT length guard Db::all() has; only the
  index --out / test path, not the jailed runtime path. [lane 6]
- New mount API (fsopen/fsconfig/fsmount/move_mount/open_tree) soft-denies (EPERM)
  instead of hitting the KILL tripwire mount/chroot/pivot_root use. Contained. [lane 3]
- cli ELF fs::read has no size pre-check the corpus path has; huge operator file
  OOMs the parent before the worker cap. Self-inflicted. [lane 13]
- band_keys(r) panics on r==0 (chunks(0)); every caller passes BAND_ROWS=4, not
  data-reachable. Add r.max(1) / debug_assert. [lanes 11, 17]
- i386/int 0x80 kill rides on seccompiler's arch-prologue KILL; add a comment +
  a regression test firing int 0x80 so a dep swap can't silently downgrade it. [lane 4]
- prctl allowed with all subcommands; no_new_privs makes it non-loosening, but
  arg0-gating to PR_SET_NAME is more minimal. [lanes 1, 20]

### Cleanup / docs
- Remove the dead pkg-config build-dep still in the fork's Cargo.toml. [lanes 14, 16]
- Trim 5 unused license entries in deny.toml. [lane 16]
- row_to_rec i64 as u32 raw cast: cosmetic, use try_from().unwrap_or(0). [lane 18]
- SECURITY.md: one line distinguishing guest Prot::ALL (emulated) from host pages. [lane 20]
- Doc: library API index_to_db stores its `binary` arg verbatim; CLI passes a
  basename but a downstream consumer could embed a full path in a shared corpus. [lane 19]
- Fork: the Windows code-buffer alloc path still maps RWX with no interpreter
  guard, so the no-exec guarantee is Linux/POSIX-specific (fine, jail is Linux). [lane 15]

## Fixed in 0.3.1

- clone3 -> ENOSYS (finding 1). clone3 kept in the allow set so the allow filter
  yields ALLOW, plus a dedicated stacked filter forces it to ENOSYS; glibc falls
  back to the flag-gated clone. Two new jail tests: threads still spawn, and a raw
  clone3(CLONE_NEWUSER) comes back ENOSYS (not success, not EPERM). This closes the
  userns-via-clone3 entry gadget the "9 not 10" framing listed as a residual.
- New mount API (open_tree/move_mount/fsopen/fsconfig/fsmount/fspick) moved from
  soft-deny to the hard-kill set, matching the legacy mount syscalls (finding, low).
- emu read-hook rep flood (finding 2). Added a deterministic per-run mem-op ceiling
  (instr_cap * 64) enforced in both mem hooks + a rep_read_flood_is_capped test, so
  a pure-read rep no longer depends on the wall-clock timeout. Config doc corrected.
- parent reply-amplification comment (finding 3). Corrected the false "bounded by
  the parent's own RLIMIT_AS" claim in cli and left the honest residual documented;
  no parent RLIMIT_AS added (would risk false-killing a large corpus build).
- CI (finding 4): dropped libunicorn-dev/libcapstone-dev so a regression off the
  from-source TCI build fails loudly instead of linking a system JIT lib.
- loader symbol-name amplification (low): function count and per-name length capped.
- Db::candidates() MAX_TEXT guard added to match all() (low).
- band_keys(0) guarded with r.max(1) (low, latent).
- cli ELF reads routed through read_input() with a metadata size pre-check (low).
- i386/int-0x80 arch-prologue kill documented in the jail (low).
- row_to_rec i64->u32 uses try_from (cosmetic).
- SECURITY.md: clone3 residual rewritten, mount API + guest-vs-host Prot noted.

Deferred (not shipped in 0.3.1): dropping the fork's dynamic_linkage feature and
its dead pkg-config dep (fork-git hygiene, non-exposed, not worth a permanent
crates.io fork version bump now); deny.toml unused-license trim (removing allow
entries risks a future transitive dep failing CI). The fork's Windows RWX alloc
path is Linux-irrelevant (the jail is Linux-only).

## Confirmed sound (not just "no finding")
unsafe FFI shim (sqlite3_deserialize copy); corpus db parsing (no SQLi, clean
errors); loader segment + eh_frame paths; integer/arithmetic across the untrusted
path; x32 tripwire (full coverage table verified vs live kernel); determinism (Vec
order, FNV, fixed seeds, EMU_LOCK); info-leak posture (basename only, hermetic emu);
supply chain (cargo audit + cargo deny clean, exact pins + lock checksums);
panic surface (no parent-process panic reachable from crafted input).

# 0.3.2 audit (exploitation-focused deep audit, 2026-08-23)

Where the 0.3.0 audit was breadth-first ("find anything"), this one was told to
keep hunting until it found a valid, patchable vuln, then a full pre-publish
review. It found the headline forgery plus a cluster of crafted-input DoS bugs.
Fixed and shipped in 0.3.2; both mandatory reviews cleared the diff; accuracy is
byte-identical to bench/NUMBERS.md (the matching path is untouched).

## The headline: fingerprint forgery (documented hard residual, NOT fixed)

A fingerprint is behavior observed on one microexecution path, and that path is
attacker-influenceable. A crafted function can gate its real behavior behind a
branch microexecution never takes (e.g. a guard comparing an argument against a
value the emulator fabricates, since the arg registers and input buffers are
seeded from fixed public constants), so the print reflects only a benign decoy.
Confirmed by direct repro: a `victim` whose real memcpy sat behind such a guard
printed as pure-decoy.

Two mitigations were built, measured, and REJECTED:
- Forced branch exploration (also run the not-taken side, union its effects).
  Defeats the decoy but dropped cross-optimization rank-1 accuracy 25-44 points
  (gcc O0->O3 91% -> 47%): forcing impossible paths injects build-specific noise,
  and "targeted" is impossible because under microexecution every input is
  fabricated, so there is no clean subset to flip. Not shipped.
- Hard coverage gate (refuse a verdict when too little of the body ran). Rejected
  because the functions that matter most for n-day work are large input-driven
  state machines (zlib inflate/deflate) that legitimately execute ~none of their
  body on junk input (coverage 0.00-0.01), so a gate would refuse verdicts on
  exactly the crown-jewel CVE functions. Low coverage cannot discriminate forgery
  from legitimate complexity.

Shipped instead: an ADVISORY coverage signal. Every print records the fraction of
the function body microexecution observed (emu -> EffectTrace.coverage ->
IndexedFunc.coverage); triage shows it per lead and flags low ones with `!`. It is
observational only, never gates a verdict, never changes a fingerprint (matching
accuracy is provably unchanged). Residual: it flags the large-hidden-payload shape
but a small payload behind a decoy that keeps coverage high can still forge, and
the advisory relies on a human reading it. This is fundamental to a single-pass
behavioral matcher. See SECURITY.md.

## DoS / correctness findings (all fixed, all accuracy-neutral)

- PT_LOAD segment-count flood (confirmed). The loader capped segment size but not
  count; a few-hundred-KB ELF with thousands of tiny segments stayed under the
  byte caps yet became a qemu memory-region flood the softmmu pays super-linear
  cost on. Fixed: MAX_LOAD_SEGS = 256, plus the same count cap on .eh_frame FDEs.
- Crafted-db view -> vtab reachability (view path confirmed; memory-corruption via
  the stale bundled SQLite 3.45.0 plausible, not reproduced). A corpus .db could
  name `funcs` a VIEW whose body reaches fts/rtree vtab modules and schema SQL
  functions. Fixed: open_image sets DEFENSIVE, TRUSTED_SCHEMA=off, ENABLE_VIEW=off
  before deserialize, so the reader only sees a plain table. (The SQLite version
  bump itself is deferred; the reachable path is closed.)
- Parent-hang + fork-bomb (confirmed). The parent blocked on read/wait forever if
  the worker wedged, and RLIMIT_NPROC is unclamped. Fixed: the parent runs the
  worker in its own process group with a wall-clock deadline scaled above the
  worker's RLIMIT_CPU (so the CPU bound fires first for legit work), and SIGKILLs
  the whole group past it. Kill-before-reap (reader-thread recv_timeout +
  reap_bounded) so there is no pid-reuse window. Uses rustix, cli stays
  unsafe-forbid.
- Timeout truncation didn't set capped: a run stopped by the wall-clock backstop
  looked like a clean complete run. Fixed: anything that stops off the return
  sentinel is marked capped.
- Nondeterministic candidate order (HashSet iteration) + first-seen tie-break.
  Fixed: sorted candidates + a total (name, binary) tie-break, so the same query
  names the same twin every run.

## Review findings (both mandatory reviewers, all Low/nit, all addressed)

pid-reuse TOCTOU in the first watchdog design -> restructured to kill-before-reap;
wall deadline vs RLIMIT_CPU on a many-core host -> scaled the deadline with thread
count; untrusted worker-reply coverage not range-validated -> clamped; a
serde(default) that is a no-op over postcard -> comment corrected. No High/Medium
in either review.

## Confirmed sound (0.3.2 delta)
coverage tracking is observational only (not in Effect/token/complexity/the
signature, cannot move a fingerprint); the caps sit before the expensive passes;
the sqlite db-configs are the right knobs in the right order; coverage is advisory
everywhere (no hidden gate); the worker restructure kills only before reaping and
bounds both the read phase and the post-reply wait.

# 0.4.2 audit (external audit intake + fix, 2026-08-26)

An external security audit of 0.4.1 (commit 7d892e47) reported 11 confirmed
findings (1 High, 8 Medium, 2 Low). All 11 were fixed in 0.4.2 and each fix was
re-reviewed by two independent mandatory reviewers (source-read, per-finding
verification). Both reviewers returned clean: no memory-safety, escape, injection,
or panic-on-untrusted-value defect; determinism (byte-identical corpus across runs
and shard counts) preserved; fail-closed throughout. Written 2026-08-26.

## Findings and fixes

### FNP-001 (High): cross-process kill / cpu-pin primitives in the allow set
`tgkill` and `sched_setaffinity` were on the seccomp allowlist. Both take a target
pid/tid as a runtime arg BPF can't pin to self, so a popped worker could SIGKILL
the trusted parent (or any same-uid process) or pin any process's CPU. Fixed: both
dropped from the allow set, so they soft-deny to EPERM (not in the kill set, so no
tripwire kill). abort()/panic=abort still terminates without tgkill (falls through
to _exit); rayon only reads sched_getaffinity, which stays allowed.

### FNP-002 / FNP-006 (Medium): ambient authority the seccomp filter can't express
The worker inherited the parent's full environment and every fd above std{in,out,
err}, and nothing killed an orphaned worker whose parent died mid-run. Fixed:
`env_clear()` on the worker spawn (no LD_PRELOAD / proxy / locale carried in); a new
`harden_worker_preinput()` that runs as the worker's FIRST action (before the jail,
before any input) and closes fds >= 3 in one `close_range`, arms
`PR_SET_PDEATHSIG=SIGKILL`, and re-checks getppid to bail on the parent-already-died
race. Fail-closed: any failure aborts before untrusted bytes are read.

### FNP-003 (Medium): stale bundled SQLite (CVE-2025-3277)
rusqlite 0.31 bundled SQLite 3.45.0, before the 3.49.1 fix for CVE-2025-3277
(integer overflow in concat_ws). We parse untrusted corpus images with sqlite.
Fixed: rusqlite 0.31 -> 0.37, bundling SQLite 3.50.2; a build-time test asserts the
linked version is >= 3.49.1 so a future dep downgrade fails the build. (This closes
the "SQLite version bump deferred" note from the 0.3.2 record.)

### FNP-004 (Medium): TOCTOU + non-regular file in the input read
`read_input` stat'd the path then re-opened it to read (a symlink-swap window), and
a device/fifo (e.g. /dev/zero, len 0 then streams forever) sailed past the size
check. Fixed: open once, fstat and read through the SAME handle, reject non-regular
files (is_file()), and bound the read with File::take(MAX_INPUT+1).

### FNP-005 (Medium): weak physical-schema check on the untrusted corpus image
open_image trusted that `funcs` had the expected shape. A crafted image could
declare it a virtual/shadow table, or an ordinary table with generated/hidden
columns or affinity-shifting declared types. Fixed: `verify_funcs_schema` runs after
deserialize (before any row read) and requires funcs be an ordinary 'table' via
pragma_table_list, with EXACTLY the 9 expected columns in order, matching declared
types, and hidden==0 via pragma_table_xinfo. Plus octet_length (byte, not char)
WHERE guards, a Rust byte recheck, and aggregate row/byte budgets that fail closed.

### FNP-007 (Medium): per-writer full-ELF copy + unbounded sharded footprint
run_worker deep-copied the whole ELF per worker (input.to_vec()), so the sharded
path held N copies in the parent at once, and input_len * shard_count was unbounded.
Fixed: run_worker takes Arc<Vec<u8>>; the writer clones the Arc handle, not the
bytes. Shard count is trimmed so input_len * shards stays under a 2 GiB aggregate
budget (never below 1; output is byte-identical at any shard count, so this only
trades parallelism).

### FNP-008 (Medium): emu region flood + swallowed map errors + overlapping segments
ensure_pages fell back to one mem_map per page and ignored map errors (`let _ =`),
and the loader accepted overlapping PT_LOADs, which fragment the map. Fixed: the
loader rejects byte-overlapping PT_LOAD ranges (sorted by vaddr; page-boundary
sharing between byte-disjoint segments is still allowed); ensure_pages coalesces
maximal runs of still-unmapped pages into one mem_map each, propagates real errors
via `?`, and caps setup runs (MAX_SETUP_RUNS) so a pathological layout fails to a
capped trace instead of marching toward qemu's region-count abort.

### FNP-009 (Medium): symbol map deep-cloned per run
The full symbol map was cloned into every Rec (once per force-path per function).
Fixed: the map is built once and wrapped in Arc before the per-function loop, so the
per-run clone is a refcount bump. Read-only after construction, shared across the
rayon workers; identical contents, determinism preserved.

### FNP-010 (Low): CPU rlimit + wall deadline scaled unbounded with cores
The worker RLIMIT_CPU and the parent's wall deadline both scaled with the machine
core count, so a bigger box granted a wedged-but-busy worker a proportionally larger
runaway window (hours on a 128-core server). Fixed: the thread multiplier is clamped
to 16 in both places, so the backstop is a bounded ceiling regardless of machine
size; the deadline stays strictly above RLIMIT_CPU (both compute 120*min(threads,16);
deadline adds +300), so the CPU bound still fires first for legit work. The emu's
per-function 3s hang guard already bounds per-function time.

### FNP-011 (Low): file paths printed unescaped
Symbol names were escaped, but file paths in human/error output were not, so a
crafted filename could smuggle terminal escapes. Fixed: esc() now wraps every path
in the error and human output (read_input messages, corpus open, match a/b labels,
the "wrote -> path" line).

## Reviewer verdict (both mandatory reviewers, source-read, per-finding)
No High/Medium/Low defect in either review. Both independently confirmed: the
close_range FFI is the only new unsafe in the sandbox lib and is sound (integer
args, keeps 0/1/2); the pdeathsig race handling is complete; the schema verifier
cannot be bypassed (single main db, unqualified funcs resolves to the checked
table, checks run before any row read); read_input closes the TOCTOU; the
deadline > RLIMIT_CPU ordering holds on all machine sizes; determinism is preserved
(no HashSet iteration feeds output; segment sort is a no-op for well-formed ELFs).

## Residuals (honest, not defects)
- close_range needs kernel >= 5.9; on older kernels harden bails, so the worker
  fails closed (safe). The jail already requires modern seccomp/clone3, so the
  effective kernel floor did not move in practice. Target (Kali, 7.x) is fine.
- PR_SET_CHILD_SUBREAPER could let an orphan reparent to a subreaper (ppid != 1)
  and pass the getppid check, but pdeathsig already fired on the real parent's
  death, so the worker still dies. fnprint has no subreaper; theoretical.
- Pointing the tool at a FIFO blocks at File::open before the is_file() reject
  (open waits for a writer). Pre-existing (old fs::read blocked identically),
  operator-self-inflicted, not a memory-safety issue.
