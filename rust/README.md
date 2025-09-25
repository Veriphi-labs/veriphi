# Rust Workspace (`rust/`)

The Rust workspace hosts the core cryptographic engine and the language-specific bindings that wrap it.

## Crates
- `veriphi-core` – core library and FFI surface consumed by every binding.
- `veriphi-core-py` – Python extension module powered by PyO3 / maturin.
- `veriphi-core-wasm` – WebAssembly target for use from browsers or bundlers.
- `veriphi-sdk` - Rust high-level SDK

## Building
Compile everything in release mode:
```bash
cargo build --release
```
To build a single crate:
```bash
cargo build --release -p veriphi-core        # core library
cargo build --release -p veriphi-core-py     # Python binding (emits cdylib)
cargo build --release -p veriphi-core-wasm   # wasm-bindgen output
```

## Tests
```bash
cargo test                     # all crates
cargo test -p veriphi-core     # just the core library
```

## Binding-Specific Notes
- Python: final wheels are generated via `maturin` (see `python/README.md`).
- WASM: build with `wasm-pack build rust/veriphi-core-wasm --release --target bundler` to populate `pkg/`.

## Repository Integration
The Node and Python packages pull compiled artifacts from these crates during their build pipelines. Keep the workspace in sync with the instructions outlined in the top-level `README.md`.
