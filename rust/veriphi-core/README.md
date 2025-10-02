# veriphi-core (Rust)

`veriphi-core` implements the cryptographic primitives that power every Veriphi binding. It provides deterministic key derivation, condition preparation, packet obfuscation, and reversible transforms that can be invoked from Rust or exported to other runtimes via FFI.

## Features
- Deterministic key generation and validation utilities.
- AES-based packet encryption/decryption.
- Conditional hashing and involution routines for authorisation workflows.
- Embedding and reconstruction primitives for stream encryption and decryption.
- Parallel-friendly implementations using `rayon` and constant-time zeroisation where appropriate.

## Crate Layout
- `encrypt.rs` / `decrypt.rs` – streaming cipher helpers and authenticated packaging.
- `involute.rs` – reversible transforms used to obscure condition payloads.
- `utils.rs` – key derivation, condition preparation, and shared helpers.

## Building
```bash
cargo build --release -p veriphi-core
```

## Testing
```bash
cargo test -p veriphi-core
```

## License
Licensed under the AGPL-3.0-only. Commercial licensing is available; see the project root for details.
