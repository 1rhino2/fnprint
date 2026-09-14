# common dev tasks. `make` on its own prints this list.
# building the bundled C libs (unicorn/capstone/sqlite) needs cmake and a working
# C/C++ toolchain, same as CI. see README install for the system packages.

CARGO ?= cargo

.PHONY: help build debug test fmt fmt-check lint ci bench fuzz-loader fuzz-index deny audit install completions clean

help:
	@echo "targets:"
	@echo "  build         release build (target/release/fnprint)"
	@echo "  debug         debug build"
	@echo "  test          cargo test --all"
	@echo "  fmt           format the tree"
	@echo "  fmt-check     check formatting (what CI runs)"
	@echo "  lint          clippy --all-targets -D warnings"
	@echo "  ci            fmt-check + lint + test (mirrors the CI build-test job)"
	@echo "  deny          cargo deny check (advisories, bans, licenses, sources)"
	@echo "  audit         cargo audit (RUSTSEC)"
	@echo "  bench         release build + bench/run.sh (needs gcc/clang + zlib source)"
	@echo "  fuzz-loader   cargo +nightly fuzz run loader"
	@echo "  fuzz-index    cargo +nightly fuzz run index"
	@echo "  install       cargo install --path cli"
	@echo "  completions   write bash completion to ./fnprint.bash"
	@echo "  clean         cargo clean"

build:
	$(CARGO) build --release

debug:
	$(CARGO) build

test:
	$(CARGO) test --all

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets -- -D warnings

# same gate as the CI build-test job, run it before pushing
ci: fmt-check lint test

deny:
	$(CARGO) deny check

audit:
	$(CARGO) audit

bench: build
	bash bench/run.sh

# fuzz targets live in fuzz/ and need nightly + cargo-fuzz (cargo install cargo-fuzz)
fuzz-loader:
	$(CARGO) +nightly fuzz run loader

fuzz-index:
	$(CARGO) +nightly fuzz run index

install:
	$(CARGO) install --path cli

completions: build
	./target/release/fnprint completions bash > fnprint.bash
	@echo "wrote fnprint.bash (source it, or drop in your bash-completion dir)"

clean:
	$(CARGO) clean
