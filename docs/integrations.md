# Integrations and machine output

fnprint 0.4.0 adds a `--format` flag (global) so its output can drive scripts and
disassemblers, not just a terminal.

    --format human   readable tables (default, unchanged)
    --format json    stable machine schema, one JSON object per run
    --format r2      a rizin/radare2 script (query and triage only)

## rizin / radare2 (supported, no install)

The lowest-friction integration. `query`/`triage` with `--format r2` emit `afn`
rename commands you run inside r2/rizin on the same target:

    fnprint query target.so --corpus corpus.db --threshold 0.7 --format r2 > fnprint.r2
    # then in r2/rizin on target.so:
    [0x00000000]> . fnprint.r2

Every emitted name is sanitized to `fnp.<ident>` (only `[A-Za-z0-9_.]`), so a
crafted symbol name in a corpus can't inject r2 commands.

## Ghidra (experimental)

The `--format json` output IS the Ghidra contract. `contrib/fnprint_import.py` is
a Jython starting point (run from Ghidra's Script Manager): it reads a
`query --format json` file and renames matched functions that still have default
names. It is experimental, not a packaged plugin yet.

    fnprint query target.so --corpus corpus.db --threshold 0.7 --format json > names.json

## JSON schemas

Every object carries `schema_version` (currently 1), independent of the
fingerprint format. Keys are emitted sorted; arrays are in the pipeline's own
deterministic order. All symbol names and labels are terminal-escaped before they
enter a JSON string, so a crafted name is inert even in a downstream viewer.

- `index`: `{schema_version, binary, functions, named, with_signal, wrote,
  funcs:[{entry,name,source,complexity,shingles,capped,coverage}]}`
- `match`: `{schema_version, compared, unchanged, changed:[{name,similarity}],
  low_signal, only_a:[...], only_b:[...]}`
- `query`: `{schema_version, threshold, named:[{entry,guess,from_binary,similarity}]}`
- `eval`: `{schema_version, scored, rank1_acc, recall_at_3, recall_at_5, mrr,
  precision, recall, abstain_rate, tp, fp, abstained}`
- `triage`: `{schema_version, counts:{vulnerable,patched,inconclusive},
  hits:[{entry,verdict,vuln_sim,vuln_name,patched_sim,patched_name,margin,coverage}]}`
- `dump`: `{schema_version, func, lines:[...]}`

`entry` is a hex string (`0x...`); similarities and coverage are floats in [0,1].
