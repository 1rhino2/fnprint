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

What is not in the model: fnprint is an analysis tool, not a sandbox you should
point at something and trust blindly on a production box. Run it where you run
your other RE tooling.

## Hardening in place

- Sizes taken from headers (`p_memsz`, section sizes) are capped and refused past
  the limit, so a crafted header can't force a huge allocation.
- Arithmetic on file-derived offsets is overflow-safe (`checked_`/`saturating_`),
  so a hostile `vaddr`/`offset`/`size` can't wrap into a panic or a bad index.
- The loader has adversarial tests for truncated files, past-EOF offsets,
  overflowing sizes, and absurd `p_memsz`. Fuzz targets live in `fuzz/`.

## Reporting

Found an input that panics, hangs, or OOMs it, or a way past the bounds above?
Open an issue with the smallest file that reproduces it (or a script that builds
one). That is exactly the kind of bug this project cares about.
