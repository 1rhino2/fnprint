# fnprint_import.py  (EXPERIMENTAL, Ghidra Jython)
#
# Reads the JSON emitted by `fnprint query --format json` and renames the matched
# functions in the current Ghidra program. Run it from Ghidra's Script Manager
# (it uses the Jython interpreter Ghidra ships).
#
# This is the Ghidra side of the `--format json` contract documented in
# docs/integrations.md. The rizin path (`fnprint query --format r2`) is the
# supported, no-install integration; this is a starting point for a Ghidra plugin.
#
# Usage:
#   1. fnprint query target.so --corpus corpus.db --threshold 0.7 --format json > names.json
#   2. In Ghidra: run this script, pick names.json when prompted.
#
# It only renames functions whose entry address matches and whose current name
# looks defaulted (FUN_/SUB_/no symbol); it will not clobber names you set.

import json

# @category fnprint

def run():
    f = askFile("fnprint names.json", "Import")  # noqa: F821 (Ghidra builtin)
    with open(f.getAbsolutePath()) as fh:
        data = json.load(fh)

    if data.get("schema_version") != 1:
        printerr("unexpected schema_version: %r" % data.get("schema_version"))  # noqa: F821
        return

    fm = currentProgram.getFunctionManager()  # noqa: F821
    base = currentProgram.getImageBase()       # noqa: F821
    renamed = 0
    for row in data.get("named", []):
        entry = int(row["entry"], 16)
        guess = row["guess"]
        addr = base.getAddress(entry)
        fn = fm.getFunctionAt(addr)
        if fn is None:
            continue
        cur = fn.getName()
        # don't overwrite a real, analyst-given name
        if cur and not (cur.startswith("FUN_") or cur.startswith("SUB_")):
            continue
        try:
            fn.setName("fnp_" + guess, ghidra.program.model.symbol.SourceType.USER_DEFINED)  # noqa: F821
            renamed += 1
        except Exception as e:  # noqa: BLE001
            printerr("could not rename %s: %s" % (row["entry"], e))  # noqa: F821
    println("fnprint: renamed %d function(s)" % renamed)  # noqa: F821


run()
