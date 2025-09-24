import './vitest.worker-shim';

if (!('crypto' in globalThis)) {
  const { webcrypto } = await import('node:crypto');
  (globalThis as any).crypto = webcrypto as unknown as Crypto;
}


import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

import initWasm from '../../rust/veriphi-core-wasm/pkg/veriphi_core_wasm.js';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Point directly at the compiled wasm binary
const wasmPath = path.resolve(
  __dirname,
  '../../rust/veriphi-core-wasm/pkg/veriphi_core_wasm_bg.wasm'
);

// Read the bytes and initialize wasm-bindgen
const bytes = fs.readFileSync(wasmPath);
await initWasm(bytes);

// Optional sanity marker you can assert in tests if you want
(globalThis as any).__VERIPHI_WASM_READY__ = true;