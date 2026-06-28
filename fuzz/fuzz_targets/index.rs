#![no_main]
// end to end: parse + micro-execute whatever we're handed. wild pointers,
// junk code, infinite loops all have to degrade, not hang or crash.
use libfuzzer_sys::fuzz_target;
use fnprint_emu::Config;

fuzz_target!(|data: &[u8]| {
    // small caps so the fuzzer stays fast
    let cfg = Config { instr_cap: 2000, max_effects: 48, ..Config::default() };
    let _ = fnprint_core::index_bytes(data, cfg);
});
