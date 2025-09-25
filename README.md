# Veriphi

## Overview
Veriphi codes for protecting against agent mis-alignment by enforcing authorisation graphs with distributed encryption of tools. 

Agents equipped with tools, such as executables, passwords or credentials, can 
 - Leak the tool to an attacked
 - Use the tool without consent
 - Use the tool correctly, but out of scope in an undesired context

To prevent this, Veriphi allows for fully decentralised and secure enforcement of workflows.

Define the conditions and domains that your Agent must obey, including
 - Which tools are used by which Agent
 - Which targets are permissible by which Agent
 - Which tools and targets require consent from an outside party (such as a human)

To explore simple examples, see out interactive [demo builder](https://www.veriphi.co.uk/demo.html).  For more complex examples, directly call the SDK for implementation, or get in touch here for a [free consultation](hello@veriphilabs.com) (example code coming soon!)

The **Veriphi SDK** provides a unified toolkit across multiple environments:

- **Rust** — core implementation and high-level SDK
- **Python** — bindings built via [maturin](https://github.com/PyO3/maturin)
- **Node.js** — native addon (N-API via [napi-rs](https://napi.rs/)) and a TypeScript wrapper
- **WebAssembly** — browser/JS bindings compiled with [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/)
- **Notebooks** — runnable examples in Python and Node

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
please contact us at hello@veriphilabs.com.  We will offer **very permissive** commercial terms

## Prerequisites

You’ll need the following installed, depending on which interfaces you want to use:

- **Rust toolchain**  
  - `rustup`, `cargo`, (install from [here](https://www.rust-lang.org/tools/install))
  - Nightly toolchain for WASM multithreading:
    ```bash
    rustup install nightly
    rustup target add wasm32-unknown-unknown --toolchain nightly
    rustup default stable
    ```

- **Node.js + npm**  
  - Node.js 20+ recommended (install from [here](https://nodejs.org/en/download))
      - This is the bit most likely to cause issues down the line.  Chatbots are your friend.
  - Install napi for rust bindings
    ```bash
    npm install -g @napi-rs/cli
    ```
  - TypeScript (`tsc`) and Vitest will be installed per-package

- **Python**  
  - Python 3.10+  (install python from [here](https://www.python.org/downloads/))
  - Create a new virtual environment from the repo-root
    ```bash
    python -m venv .venv
    ```
  - Activate the virtual environment
  - [maturin](https://github.com/PyO3/maturin) for building Rust Python bindings  
    ```bash
    pip install maturin pytest
    ```

- **WASM**  (not yet supported for windows)
  - [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)  
    ```bash
    cargo install wasm-pack
    ```
- **You made need to install `make` to be able to use the `Makefile`**

## Repository Layout
```text
.
├── rust/
│   ├── veriphi-sdk/         # Rust SDK (public API layer, re-exports core)
│   ├── veriphi-core/        # Low-level cryptographic routines
│   ├── veriphi-core-py/     # Python bindings (maturin)
│   └── veriphi-core-wasm/   # WASM crate (wasm-bindgen, wasm-pack)
│
├── node/
│   ├── veriphi-core-node/   # Node native addon (napi-rs)
│   └── veriphi_core/        # Node TypeScript wrapper (exports unified API)
│
├── wasm/
│   └── veriphi_core/        # WASM TypeScript wrapper (built from wasm-pack output)
│
├── python/                  # Python package entry point and tests
│
├── notebooks/               # Example notebooks (Python + Node)
│
├── Makefile                 # Unified build/test pipeline
└── ...
```
## Building

The repository uses a **unified Makefile** in the root to orchestrate builds and tests.

To build everything, use general commands below.  Note that antiviruses may interfere with installation of some packages.

### Clean builds
```bash
make clean

# Build everything

make build

# Run all tests

make test

# Full pipeline (clean → build → test)

make all

# CI pipeline

make ci
```

## Makefile Targets

For building specific interfaces, follow the relevant instructions below

### Cleaning
	•	make clean-rust → remove Rust build artifacts
	•	make clean-python → remove Python caches & dist
	•	make clean-node → remove Node build artifacts
	•	make clean-wasm → remove WASM build artifacts
	•	make clean → run all of the above

### Building
	•	make build-rust → build Rust SDK (cargo build --release)
	•	make build-python → build Python bindings (maturin develop)
	•	make build-node → build Node native addon (NAPI + TS)
	•	make build-ts → build Node + WASM TypeScript packages
	•	make build-wasm → build WASM crate via wasm-pack
	•	make build → build everything

### Testing
	•	make test-rust → run Rust unit tests
	•	make test-python → run Python tests (pytest)
	•	make test-node → run Node tests (vitest)
	•	make test-wasm → run WASM tests (vitest)
	•	make test → run all tests

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

## Notes
### WASM
	•	Uses nightly Rust for multithreading.
	•	Ensure the wasm32-unknown-unknown target is installed:

### Python
	•	The bindings are in rust/veriphi-core-py/ but installed into your active Python environment via maturin develop.

### Notebooks
	•	Python + Node usage examples live in notebooks/.


