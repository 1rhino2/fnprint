# fnprint 0.3.0 security audit (20-lane)

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
