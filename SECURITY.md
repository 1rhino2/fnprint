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
  effect caps. It is emulated, not run natively, and it is bounded.
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

## Sandbox (Linux)

The part that touches the untrusted binary runs privilege-separated. When you
run `fnprint index/match/query/eval/triage/dump` on an ELF, the cli re-execs
itself as a hidden worker, hands the file bytes to it over a pipe, and gets
fingerprints back over a pipe. Before the worker reads a single input byte it
jails itself:

- `PR_SET_NO_NEW_PRIVS`, no core dumps, bounded CPU, and an `RLIMIT_AS` backstop.
- Two stacked seccomp filters, applied to every thread (rayon and qemu spawn
  threads, and the emulation runs on them). The catastrophic syscalls, `execve`,
  `ptrace`, the whole socket family, module/kexec/bpf, mount/chroot/namespace,
  the setuid family, hard-kill the process. Anything else not on a small allow
  set fails soft with `EPERM`. So `open`/`openat` return `EPERM`: a popped worker
  can't read a file off your disk or open a socket, but qemu's best-effort probes
  of `/sys` and `/proc` degrade to an error instead of taking the run down.
  `clone` is allowed for thread creation but only with no `CLONE_NEW*` flag, so a
  popped worker can spawn threads but not create a namespace.

The result: a memory-corruption exploit that lands inside unicorn from a crafted
input can still compute in its own address space, but it can't exec a shell, open
a file, or reach the network. The trusted parent does the database and terminal
output; it never runs the emulator.

Fail-closed: if the jail won't install, the worker refuses to process input.
`--no-sandbox` is an explicit, loud opt-out for a platform that can't jail (the
sandbox is Linux-only) or for debugging. It runs the emulator in-process with no
containment, so only use it when you trust the input.

What the sandbox does not cover yet: reading a corpus `.db` (for `match`,
`query`, `triage`) parses that SQLite file in the trusted parent, not in the
jail. Treat a `.db` you did not build as untrusted input too, and don't point
those subcommands at a corpus from someone you don't trust until that path is
jailed as well. The corpus path is defended against SQL injection (every value
is a bound parameter) and against malformed rows (a bad row is a clean error,
not a crash), but it is not jailed.

### Known residuals

These are understood and accepted, not oversights:

- `clone3` is allowed unconditionally. Its flags live in a struct behind a
  pointer that a seccomp BPF filter cannot dereference, so unlike `clone` it
  can't be flag-filtered, and a popped worker could create a user namespace
  through it. This is not a jail escape: the seccomp filters and `no_new_privs`
  are inherited across the namespace change, so every catastrophic syscall stays
  killed and everything unlisted stays `EPERM` inside the new namespace. The
  residual is that userns-dependent kernel attack surface stays reachable. We
  keep `clone3` open because denying it breaks thread creation on current glibc.
- x32 ABI. The kill-list tripwire matches native x86-64 syscall numbers; an x32
  call (syscall bit `0x40000000`) misses both lists and lands on the allow
  filter's `EPERM` default. So x32 catastrophic calls are still contained (they
  fail), but they return `EPERM` rather than `SIGSYS`, so a monitor keying on
  `SIGSYS` won't see them. The i386/`int 0x80` compat gate is hard-killed.
- Resource limits are a backstop, not a fence. `RLIMIT_NPROC` is deliberately
  not clamped (it would break qemu's helper threads), so a popped worker could
  fork more jailed copies; each is still fully jailed, and OOM handling is the
  host's job. `RLIMIT_CPU` bounds CPU but there is no wall-clock bound on a
  syscall that just blocks.

## Reporting

Found an input that panics, hangs, or OOMs it, or a way past the bounds above?
Open an issue with the smallest file that reproduces it (or a script that builds
one). That is exactly the kind of bug this project cares about.
