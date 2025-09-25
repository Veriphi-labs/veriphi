# `@veriphi/veriphi_core` (TypeScript API)

## Overview
Node routines for Veriphi agentic guardrails.  Designed to implement arbitrary and decentralised authorisation graphs.  For examples, see the [node_start.ipynb](../../notebooks/node_start.ipynb) file to implement a simple passing of a JSON.  
## Installation
This package is managed as part of the top-level npm workspace. From the repo root:
```bash
npm install
```
To work inside this package directly:
```bash
cd node/veriphi_core
npm install
```

## Build
Compile the native addon and TypeScript wrapper:
```bash
npm run build:native   # builds ../veriphi-core-node via napi-rs
npm run build          # emits dist/*.js and *.d.ts
```

## Tests
```bash
npm test
```
The test script triggers `build:native`, compiles TypeScript, emits `dist-tests/`, and runs the Node test suite.

## Usage
After building, consumers can import the CommonJS bundle:
```ts
const veriphi = require('@veriphi/veriphi_core');
const { encryptAESCTR } = require('@veriphi/veriphi_core/utils');
```
Type declarations are published alongside the JS artifacts for TypeScript support.

## Notes
- The package uses the sibling native addon located in `node/veriphi-core-node` (see below).
- Distribution assets live in `dist/`; remember to rebuild when editing source files under `src/`.


# `@veriphi/veriphi-core-node` (N-API Addon)

## Overview
N-API bindings for rust to ts.  Binds essential functions, whilst a high-level interface is provided in [index.ts](../veriphi_core/src/index.ts)
## Prerequisites
- Rust toolchain (`cargo`, `rustc`)
- Node.js 18+
- `napi` CLI is installed automatically via devDependencies during npm install.

## Build
From `veriphi-core-node` directory:
```bash
npm install
npm run build        # release build (napi build --release)
npm run build:debug  # debug build
```
The compiled addon is emitted as `index.node` in the package root and consumed by `@veriphi/veriphi_core`.

## Tests
The addon has no standalone tests. It is exercised indirectly through the TypeScript package (`npm test` in `node/veriphi_core`)

## Publishing Notes
`package.json` lists the files that should ship (`index.node`, `index.d.ts`). Ensure release builds run on the target platforms when cutting new versions.

