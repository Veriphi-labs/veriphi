# veriphi

## Overview
> _TODO: Add a high-level description of the Veriphi project, core capabilities, and primary use cases._

## Repository Layout
- `rust/` – Rust workspace containing the core engine (`veriphi-core`), Python extension crate (`veriphi-core-py`), and WebAssembly build (`veriphi-core-wasm`).
- `node/` – Node.js bindings: the native N-API addon lives in `veriphi-core-node`, while the TypeScript wrapper and high-level APIs are in `veriphi_core`.
- `python/` – Python package that exposes the core functionality via the Rust extension module.
- `notebooks/` – Interactive examples for both the Node and Python stacks.

## Prerequisites
- [Rust toolchain](https://rustup.rs/) (nightly not required; stable is sufficient)
- [Node.js 18+](https://nodejs.org/) and npm
- Python 3.9+ with `pip` (for the bindings and notebooks)

## Building
### Rust crates
```bash
cd rust
cargo build --release -p veriphi-core
```
This produces the native Rust library that all other bindings wrap. The Python extension and WebAssembly artifacts require their own build tooling (see below).

### Node.js bindings and TypeScript package
```bash
cd node/veriphi_core
npm install
npm run build:native   # builds the napi addon in ../veriphi-core-node
npm run build          # compiles TypeScript sources into dist/
```
The workspace root (`package.json`) is configured to treat `node/veriphi_core` as a workspace member, so `npm install` at the repo root will also install dependencies.

### Python bindings
The Python wheel is produced via [maturin](https://github.com/PyO3/maturin). Install it once:
```bash
pip install maturin
```
Then build and install the bindings in editable mode:
```bash
maturin develop -m rust/veriphi-core-py/Cargo.toml --release
```
This command must be run from the repository root so relative paths resolve correctly.

### WebAssembly package
Install [wasm-pack](https://rustwasm.github.io/wasm-pack/) if it is not already available, then run:
```bash
wasm-pack build rust/veriphi-core-wasm --release --target bundler
```
The build artifacts are emitted into `rust/veriphi-core-wasm/pkg/` for publishing or direct consumption.

## Testing
- **Rust** – Run `cargo test` inside `rust/` (or target a crate with `cargo test -p veriphi-core`).
- **Node.js / TypeScript** – From `node/veriphi_core` execute `npm test`. This compiles the TypeScript sources, builds the native addon, and runs the Node test suite located under `node/veriphi_core/tests/`.
- **Python** – After running `maturin develop`, invoke `pytest python/veriphi_core/tests`. The suite mirrors the Node tests to validate encryption primitives and packet handling.

## Notebooks
Interactive walkthroughs are in the `notebooks/` directory:
- `node_start.ipynb` – Demonstrates using the Node.js APIs.
- `py_start.ipynb` – Demonstrates the Python bindings.

For the TypeScript notebook, install and enable [tslab](https://github.com/yunabe/tslab):
```bash
npm install -g tslab
tslab install --version=$(node -p "require('tslab/package.json').version")
```
Activate the desired virtual environment or kernel before opening the notebooks so they can resolve the freshly built packages.

## License
This project is offered under a **dual license** model:

- **Community License:** [GNU AGPL v3.0](./LICENSE)  
  Free for open-source use under strong copyleft terms. Any modifications
  or services built on this code must also be open-sourced under the same license.

- **Commercial License:** [MIT-Style License](./COMMERCIAL_LICENSE.md)  
  For organizations that prefer permissive terms, we offer a commercial license
  that allows proprietary and closed-source use without AGPL obligations.

**Patent Notice:** Certain techniques implemented in this project are
covered by patent applications (patent pending).  
- Community users are free to use this software under AGPL.  
- Commercial licenses provide full rights, including coverage for relevant patents.

If you are a company or startup interested in commercial licensing,
please contact us at hello@veriphilabs.com.
