# `@veriphi/veriphi_core_wasm`

## Overview
WASM build using nightly rust toolchain (see [toolshain](../rust/veriphi-core-wasm/rust-toolchain.toml) and [cargo config](../rust/veriphi-core-wasm/.cargo/config.toml)).  Uses unstable features and is very sensitive (in particular use of `getrandom`)
## Installation
The package expects the Rust WASM artifacts under `rust/veriphi-core-wasm/pkg`. After building those (see below), install dependencies:
```bash
cd wasm/veriphi_core
npm install
```

## Building the WASM Artifact
Use `wasm-pack` from the repository root:
```bash
wasm-pack build rust/veriphi-core-wasm --release --target bundler
```
This populates `rust/veriphi-core-wasm/pkg/`, which is linked into this package via `package.json`.

## Tests
Tests run with [Vitest](https://vitest.dev/):
```bash
npm run test
```
The test setup initialises WebCrypto and a minimal worker-like environment for the wasm-bindgen rayon helpers. If you add new tests that touch the WASM APIs, call `await initVeriphiWasm()` before using the exported functions.

## Usage
```ts
import { initVeriphiWasm, encryptAESCTR } from '@veriphi/veriphi_core_wasm';

await initVeriphiWasm();
const [ciphertext, nonce] = await encryptAESCTR(keyBytes, dataBytes);
```

## Notes
- The build targets bundler environments (`--target bundler`). Adjust the wasm-pack command if you need `web` or `node` outputs.
- The project reuses the shared TypeScript utilities under `src/` to provide a typed API over the wasm-bindgen exports.
