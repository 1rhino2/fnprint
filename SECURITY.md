# Security

fnprint parses and micro-executes untrusted binaries: malware, firmware, samples
you did not build. The input is hostile by definition, so the loader and
emulator are written to treat every field in a file as attacker-controlled.

## Threat model

- Input is a byte blob on disk. All of it is untrusted: ELF headers, program and
  section headers, symbol and string tables, `.eh_frame`, function bytes.
- The goal is that no input, however crafted, makes fnprint panic, hang, or run
  the machine out of memory. Malformed input degrades to an error or a partial
  result.
- Micro-executed code runs inside unicorn with instruction, visit, time, and
  effect caps. It is emulated, not run natively, and it is bounded. unicorn is
  built no-JIT (the TCG tiny code interpreter, `CONFIG_TCG_INTERPRETER`): guest
  code is interpreted, never compiled to host machine code, so the emulator never
  needs an executable page. That is what lets the jail forbid executable memory
  outright (see below).
- The real assumption: unicorn/qemu and capstone are large C libraries fed
  attacker bytes, and qemu has a CVE history. So we assume a crafted input can
  eventually corrupt memory inside one of them, and we contain that rather than
  pretend it can't happen.

What is not in the model: fnprint is an analysis tool. The sandbox below makes a
compromise of the emulator inert, it does not make the C libraries bug-free, and
it does not turn fnprint into something you should point at a live target you
can't afford to have the emulator crash on.

## Hardening in place

- Sizes taken from headers (`p_memsz`, section sizes) are capped and refused past
  the limit, so a crafted header can't force a huge allocation.
- Arithmetic on file-derived offsets is overflow-safe (`checked_`/`saturating_`),
  so a hostile `vaddr`/`offset`/`size` can't wrap into a panic or a bad index.
- The loader has adversarial tests for truncated files, past-EOF offsets,
  overflowing sizes, and absurd `p_memsz`. Fuzz targets live in `fuzz/`.
- Attacker-controlled symbol names are escaped before they are printed, so a
  crafted name can't smuggle terminal escape sequences into your terminal.
- The bundled C libraries (capstone, sqlite) are compiled with
  `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, and `-fPIE`, so the biggest
  native attack surface has per-object stack canaries and fortified libc calls,
  not just RELRO/PIE on the final link. See `.cargo/config.toml`.

## Sandbox (Linux)

The part that touches the untrusted binary runs privilege-separated. When you
run `fnprint index/match/query/eval/triage/dump` on an ELF, the cli re-execs
itself as a hidden worker, hands the file bytes to it over a pipe, and gets
fingerprints back over a pipe. Before the worker reads a single input byte it
jails itself:

- `PR_SET_NO_NEW_PRIVS`, no core dumps, bounded CPU, and an `RLIMIT_AS` backstop.
  The CPU backstop scales with the worker thread count (`RLIMIT_CPU` sums CPU
  across threads and the index runs in parallel), so it stays a consistent
  wall-time runaway ceiling rather than a flat total that would falsely kill a
  large binary on a many-core box.
- Before installing any filter, the worker reads `/proc/self/maps` and refuses to
  run if a writable-and-executable page already exists. There should never be one
  (the no-JIT emulator is not even instantiated yet), so this is a fail-closed
  tripwire behind the `PROT_EXEC` deny below.
- Two stacked seccomp filters, applied to every thread (rayon and qemu spawn
  threads, and the emulation runs on them). The catastrophic syscalls, `execve`,
  `ptrace`, the whole socket family, module/kexec/bpf, mount/chroot/namespace,
  the setuid family, and the async-io/fault primitives (`io_uring`,
  `userfaultfd`, `pidfd_getfd`) hard-kill the process. Anything else not on a small allow
  set fails soft with `EPERM`. So `open`/`openat` return `EPERM`: a popped worker
  can't read a file off your disk or open a socket, but qemu's best-effort probes
  of `/sys` and `/proc` degrade to an error instead of taking the run down.
  `clone` is allowed for thread creation but only with no `CLONE_NEW*` flag, so a
  popped worker can spawn threads but not create a namespace. `clone3` can't be
  flag-filtered (its flags sit behind a pointer BPF can't read), so it is turned
  into `ENOSYS`: glibc's `pthread_create` tries `clone3` first and falls back to
  the flag-gated `clone` on `ENOSYS`, so threads still work while a
  `clone3(CLONE_NEWUSER)` cannot create a namespace either. The legacy and the
  new mount API (`fsopen`/`fsmount`/`move_mount`/`open_tree`/...) both hard-kill.
- `mmap` and `mprotect` are allowed only without `PROT_EXEC` (the bit is checked
  in the prot argument, the same masked-arg trick used for the `clone` flags).
  Because unicorn is built no-JIT, nothing legitimate ever needs an executable
  page, so a popped worker cannot map new executable memory or flip an existing
  page to executable. Combined with the `/proc/self/maps` check above, there is
  no writable-executable memory in the worker at any point. (The emulator maps the
  guest's own pages `Prot::ALL` inside unicorn's software MMU; that is emulated
  guest permission the interpreter reads, not a host page, so it creates no host
  executable memory.)

The result: a memory-corruption exploit that lands inside unicorn from a crafted
input can still compute in its own address space, but it cannot run code it
generates (no executable page exists or can be made), and it can't exec a shell,
open a file, or reach the network. The trusted parent does the terminal output;
it never runs the emulator.

Reading a corpus `.db` (for `match`, `query`, `triage`) is jailed the same way.
SQLite is another large C library fed attacker bytes when the corpus is one you
did not build, so the parse runs behind the jail, not in the trusted parent. The
parent reads the file into memory as a raw byte blob (a plain `read()`, no SQLite
involved) and hands those bytes to a worker over the pipe, exactly like the ELF
path. The worker jails itself, then parses the image entirely in memory with
`sqlite3_deserialize` (read-only) and returns the decoded fingerprint rows. No
file is opened for the parse: the whole SQLite surface (b-tree pages, cell and
record decoding, overflow pages) only ever touches that in-memory buffer, under
the same seccomp filters that jail the emulator. The parent then rebuilds the LSH
band index from the returned rows in safe Rust and runs the comparison; it never
runs SQLite on the untrusted image. The corpus path is also defended against SQL
injection (every value is a bound parameter) and against malformed rows (a bad
row is a clean error, not a crash), and the parent revalidates each returned row
(a well-formed `SIG_LEN` signature) since a popped worker controls its reply.

Fail-closed: if the jail won't install, the worker refuses to process input.
`--no-sandbox` is an explicit, loud opt-out for a platform that can't jail (the
sandbox is Linux-only) or for debugging. It runs the emulator in-process and
reads the corpus with in-process SQLite, no containment, so only use it when you
trust the input.

What is still not jailed: `index --out corpus.db` opens the output database with
in-process SQLite in the parent to write rows into it. That is a corpus you are
building, not one you were handed; if you point `--out` at an existing `.db` from
someone you don't trust, that file is parsed unjailed. Build your own corpora.

### Known residuals

These are understood and accepted, not oversights:

- `clone3` and the namespace surface. `clone3`'s flags live in a struct behind a
  pointer a seccomp BPF filter cannot dereference, so unlike `clone` it can't be
  flag-filtered to forbid `CLONE_NEWUSER`. Rather than allow it unconditionally
  (which would leave userns creation reachable), it is turned into `ENOSYS`. glibc
  falls back to the flag-gated `clone` specifically on `ENOSYS` (not on `EPERM`),
  so thread creation still works, qemu's post-lockdown helper threads included,
  while `clone3(CLONE_NEWUSER)` returns `ENOSYS` instead of making a namespace.
  The jail tests assert both halves (threads still spawn; a raw
  `clone3(CLONE_NEWUSER)` comes back `ENOSYS`, not success and not `EPERM`). The
  residual that remains is the ordinary one: this is defense against a userns
  entry gadget, not a claim that the kernel's namespace code is unreachable by
  other means; `unshare`/`setns`/flagged `clone` are all killed or denied too.
- x32 ABI. The kill list now covers the x32 form of every catastrophic syscall
  (the `0x40000000` bit set, plus the dedicated x32 numbers for the struct-passing
  calls like `execve`/`ptrace`/the `*msg` family), so an x32 escape attempt
  hard-kills (`SIGSYS`) the same as its native counterpart, not just soft-denies.
  The worker is native x86-64 and issues no x32 calls of its own, so this only
  sharpens the tripwire. The i386/`int 0x80` compat gate is hard-killed too.
- One `unsafe` FFI block exists, in `fnprint-db::owned_from_bytes`. `deserialize`
  takes ownership of a buffer SQLite will later free, so the buffer must come from
  `sqlite3_malloc`; there is no safe constructor for it from a `&[u8]`. The block
  is a length-checked copy into a freshly allocated block, dereferences no
  attacker data, and NULL-checks the allocation. Two crates are `deny` (not
  `forbid`) with one scoped `#[allow]` each: `fnprint-db` for that FFI shim, and
  `fnprint-sandbox` only for its `jailbreak_probe` test binary, which issues raw
  `mmap`/`mprotect` to prove the `PROT_EXEC` deny (there is no safe-Rust way to
  request an executable page). The `fnprint-sandbox` library itself has zero
  `unsafe`; every other crate stays `forbid`.
- Resource limits are a backstop, not a fence. `RLIMIT_NPROC` is deliberately
  not clamped (it would break qemu's helper threads), so a popped worker could
  fork more jailed copies; each is still fully jailed, and OOM handling is the
  host's job. `RLIMIT_CPU` bounds CPU but there is no wall-clock bound on a
  syscall that just blocks.
- The no-JIT guarantee needs a unicorn built with `CONFIG_TCG_INTERPRETER`,
  which upstream unicorn does not ship. So the emulator comes from a small fork,
  `unicorn-engine-tci` + `unicorn-engine-sys-tci` (GPL-2.0), pinned to `=2.1.5`
  and published from github.com/1rhino2/unicorn-tci. It is the stock unicorn
  2.1.5 / QEMU 5.0.1 tree with the interpreter re-introduced (provenance and the
  upstream commit SHAs are in that repo's README) and the code buffer mapped
  `PROT_READ|PROT_WRITE` only. It always builds from source, so there is no
  ambient system `libunicorn` to trust. The residual is the usual one for any
  fork: you are trusting that tree until the interpreter lands back upstream.

## Reporting

Found an input that panics, hangs, or OOMs it, or a way past the bounds above?
Open an issue with the smallest file that reproduces it (or a script that builds
one). That is exactly the kind of bug this project cares about.
