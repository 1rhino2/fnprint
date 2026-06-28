#![no_main]
// the loader eats attacker-controlled bytes, so it must never panic. run with:
//   cargo +nightly fuzz run loader
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fnprint_loader::load(data);
});
