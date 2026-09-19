# Integrations and machine output

fnprint has a global `--format` flag so its output can drive scripts and
disassemblers, not just a terminal. Fields added in 0.6 (`graph`, `score`,
`mode`, `entry_a`/`entry_b`, the `align_*` eval block) are additions, the
schema version stays 1.

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

## Ghidra (script, GUI or headless)

`contrib/ghidra_scripts/FnprintImport.java` runs fnprint on the current program
and brings the result in. Point Ghidra's Script Manager at that directory (or
copy the file into your `ghidra_scripts`), run it, answer the prompts.

- `query` mode renames every matched function that still has a default name
  (`FUN_...`), never one you named yourself, and leaves a plate comment with the
  similarity, the call-graph score, and the corpus binary it came from.
- `triage` mode bookmarks every vuln-leaning function (category `fnprint`)
  with its margin and twins, adds a pre-comment, and prints the review queue.

Headless works too, which is how it is tested (Ghidra 12.1.2):

    analyzeHeadless <proj_dir> <proj> -import target.so \
      -scriptPath /path/to/fnprint/contrib/ghidra_scripts \
      -postScript FnprintImport.java /path/to/fnprint query corpus.db 0.7
    analyzeHeadless <proj_dir> <proj> -import target.so \
      -scriptPath /path/to/fnprint/contrib/ghidra_scripts \
      -postScript FnprintImport.java /path/to/fnprint triage vuln.db patched.db

fnprint's entries are ELF virtual addresses; the script tries image base +
entry (a PIE/.so) and then the raw entry (ET_EXEC). Ghidra refuses a project
path with a dot-directory in it, keep `<proj_dir>` plain.

## JSON schemas

Every object carries `schema_version` (currently 1), independent of the
fingerprint format. Keys are emitted sorted; arrays are in the pipeline's own
deterministic order. All symbol names and labels are terminal-escaped before they
enter a JSON string, so a crafted name is inert even in a downstream viewer.

- `index`: `{schema_version, binary, functions, named, with_signal, wrote,
  funcs:[{entry,name,source,complexity,shingles,capped,coverage}]}`
- `match`: `{schema_version, mode, compared, unchanged,
  changed:[{name,similarity,entry_a,entry_b}], low_signal, only_a:[...], only_b:[...]}`.
  `mode` is `name` (aligned by symbol name) or `aligned` (behavior + call
  graph, used when either side is stripped or with `--align`); in aligned mode
  `name` is the a-side name, `a -> b` when they differ, or `0x.. -> 0x..` when
  neither side has one, and `entry_a`/`entry_b` say where the pair sits.
- `query`: `{schema_version, threshold, named:[{entry,guess,from_binary,similarity,graph,score}]}`.
  `similarity` is the behavioral number, `graph` the call-graph consistency of
  the pair in [0,1], `score` what the assignment ranked on (similarity lifted
  by graph, at most 1) and what `threshold` applies to.
- `eval`: `{schema_version, scored, rank1_acc, recall_at_3, recall_at_5, mrr,
  precision, recall, abstain_rate, tp, fp, abstained, align_acc,
  align_precision, align_recall, align_tp, align_fp, align_paired}`
- `triage`: `{schema_version, counts:{vulnerable,patched,inconclusive},
  hits:[{entry,verdict,vuln_sim,vuln_name,patched_sim,patched_name,margin,coverage}]}`
- `dump`: `{schema_version, func, lines:[...]}`

`entry` is a hex string (`0x...`); similarities and coverage are floats in [0,1].

## Parallel indexing (opt-in)

`index` can shard across several jailed worker processes. It is off by default:
each worker reloads the whole ELF and runs its own interpreter (TCI) VM, so on
typical binaries the per-worker load plus cache contention across many VMs cancels
the parallelism (measured neutral on small binaries, slower on a mid-size lib). It
only pays off on large, function-rich corpora, so the default stays single-process
and produces the same corpus content as older releases (the rows and bands are
identical; the SQLite file header can differ, e.g. its change counter).

    FNPRINT_SHARDS=8 fnprint index big-corpus.so -o corpus.db

The output is byte-identical regardless of shard count (functions are statically
assigned by position and the merge is re-sorted), so sharding never changes the
corpus, only how the work is spread.
