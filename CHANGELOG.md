# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims for [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are the tag dates. Older entries are summarized from the release commits.

## [Unreleased]

### Fixed
- Piping human or json output into a reader that closes early (`fnprint query
  ... | head`) now exits 0 quietly. It used to abort with a panic banner because
  `println!` panics on a broken pipe and release builds are `panic = "abort"`.
  0.5.0 had guarded only `completions`.
- `--help` examples column is aligned, and the completion example installs
  per-user instead of into `/etc`.

## [0.5.0] - 2026-09-14

### Added
- `fnprint completions <shell>` prints a shell completion script (bash, zsh,
  fish, powershell, elvish) to stdout.
- `--limit N` on `match`, `query`, and `triage` caps how many rows the human
  tables print (0 = all). `json` and `r2` output are never capped, so scripts
  and plugins still get the full set.
- `--help` now shows a short examples block.
- `Db::insert_all`, a bulk-insert API that writes a batch of prints under one
  transaction.

### Changed
- `index -o` writes the whole corpus in a single transaction instead of one
  commit per function, which is much faster on large, function-rich binaries.
  The corpus content is unchanged (same rows and bands); only the SQLite file
  header, e.g. its change counter, differs from the old per-row output.

## [0.4.3] - 2026-09-09

### Changed
- Bumped goblin to 0.10 and gimli to 0.34, refreshed dependencies.
- `index` reports the mean coverage of the signal-carrying prints, a warning
  when the fingerprints rest on little observed behavior.

## [0.4.2] - 2026-08-29

### Security
- Fixed 11 findings from the external audit of 0.4.1. See `SECURITY-AUDIT.md`.

## [0.4.1] - 2026-08-24

### Changed
- Deterministic `match` output: a stable tiebreak on equal-similarity rows so
  the table and json order no longer depend on hash-map iteration.

## [0.4.0] - 2026-08-23

### Added
- `--format json` on every command and `--format r2` (rizin/radare2 rename
  script) for `query` and `triage`. Symbol names are sanitized for both.
- Opt-in index sharding across jailed worker processes (`FNPRINT_SHARDS=N`).
  The corpus is byte-identical whatever the shard count.

## [0.3.4] - 2026-08-23

### Added
- Crate metadata for discoverability.

## [0.3.3] - 2026-08-23

### Added
- crates.io metadata: keywords, categories, description, docs link.

## [0.3.2] - 2026-08-22

### Security
- DoS-hardening from the deep audit.

### Added
- Coverage advisory signal surfaced next to results.

## [0.3.1] - 2026-08-22

### Security
- Closed a clone3 user-namespace gadget, bounded the worker read reply, and
  more audit hardening.

## [0.3.0] - 2026-08-22

### Changed
- No-JIT (TCI) emulator built from the interpreter-only unicorn fork, so the
  seccomp jail can forbid executable memory outright. See `SECURITY.md`.

## [0.2.5] - 2026-08-21

### Security
- x32 kill tripwire, x86-only unicorn build, capstone 0.14.

## [0.2.4] - 2026-08-21

### Security
- The corpus `.db` is parsed inside the jail (in-memory sqlite, no file open).
- Indexing is deterministic; hardened the build.

## [0.2.3] - 2026-08-21

### Security
- Hostile-input hardening: loader allocation bomb, emulator write flood,
  sandbox clone flags, privilege-separated output.

## [0.2.2] - 2026-08-20

### Changed
- Dropped postcard default features (avoids an unmaintained transitive dep).

## [0.2.1] - 2026-08-20

### Changed
- Swapped bincode for postcard on the worker wire format.

## [0.2.0] - 2026-08-20

First tagged release. Builds on the initial behavioral-fingerprinting engine
(`index` / `match` / `query` / `eval`, microexecution plus minhash/LSH).

### Added
- `triage`: rank a build against known-vulnerable and patched corpora and call
  which side each function leans to, with a `--margin` / `--min-sim` gate.
- `eval` reports recall@3 / recall@5 and an abstention rate.

### Security
- Sandboxed the emulator, hardened the build.

[Unreleased]: https://github.com/1rhino2/fnprint/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/1rhino2/fnprint/releases/tag/v0.5.0
[0.4.3]: https://github.com/1rhino2/fnprint/releases/tag/v0.4.3
[0.4.2]: https://github.com/1rhino2/fnprint/releases/tag/v0.4.2
[0.4.1]: https://github.com/1rhino2/fnprint/releases/tag/v0.4.1
[0.4.0]: https://github.com/1rhino2/fnprint/releases/tag/v0.4.0
[0.3.4]: https://github.com/1rhino2/fnprint/releases/tag/v0.3.4
[0.3.3]: https://github.com/1rhino2/fnprint/releases/tag/v0.3.3
[0.3.2]: https://github.com/1rhino2/fnprint/releases/tag/v0.3.2
[0.3.1]: https://github.com/1rhino2/fnprint/releases/tag/v0.3.1
[0.3.0]: https://github.com/1rhino2/fnprint/releases/tag/v0.3.0
[0.2.5]: https://github.com/1rhino2/fnprint/releases/tag/v0.2.5
[0.2.4]: https://github.com/1rhino2/fnprint/releases/tag/v0.2.4
[0.2.3]: https://github.com/1rhino2/fnprint/releases/tag/v0.2.3
[0.2.2]: https://github.com/1rhino2/fnprint/releases/tag/v0.2.2
[0.2.1]: https://github.com/1rhino2/fnprint/releases/tag/v0.2.1
[0.2.0]: https://github.com/1rhino2/fnprint/releases/tag/v0.2.0
