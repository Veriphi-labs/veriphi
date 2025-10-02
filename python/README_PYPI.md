# Veriphi Core Python Bindings

## Overview
Veriphi Core exposes cryptographic guardrail primitives for orchestrating agent authorisation graphs. The Python bindings wrap the Rust implementation via PyO3 so you can generate keys, prepare conditional envelopes, and obfuscate packets from Python without managing the underlying Rust toolchain.

## Installation
Once published, install directly from PyPI:

```bash
pip install veriphi-core
```

For local development inside the repository, install in editable mode with maturin:

```bash
pip install maturin
maturin develop --release
```

## Quickstart

```python
import numpy as np
from veriphi_core import interface

example_data = np.random.rand(1000)   # Generate some test data
byte_data    = example_data.tobytes() # Input data should be bytes

public_data, private_data = interface.setup_node(byte_data, 0, 1000, True) # Setup the encryption for conditions between 0, 1000

class_0, class_1 = interface.distribute_data(public_data, 'E', 2) # Distribute packets to 2 different classes

party_c0 = interface.encrypt_node(class_0,"class0_member")

party_c1 = interface.encrypt_node(class_1,"class1_member") # Each party independently processes the public data for their class

decrypted = interface.decrypt_node(private_data, 500, True, party_c0, party_c1) # recover the packet with the private data, a valid condition, and data from each class

recovered_example = np.frombuffer(decrypted, dtype=np.float64)

print(np.all(example_data == recovered_example))


```

Refer to [`notebooks/py_start.ipynb`](https://github.com/Veriphi-labs/veriphi/blob/main/notebooks/py_start.ipynb) in the full repository for a complete walkthrough.

## Supported Platforms
- macOS universal2 (`x86_64`/`arm64`), Python 3.10+
- manylinux2014 `x86_64` and `aarch64`, Python 3.10+

The project also ships a source distribution so unsupported platforms can build from source if a compatible Rust toolchain is available.

## Building Release Wheels Locally
1. **macOS universal build**
   ```bash
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   maturin build --release --strip --target universal2-apple-darwin -m rust/veriphi-core-py/Cargo.toml --out dist
   ```
2. **Linux manylinux (run from the repo root)**
   ```bash
   docker run --rm --platform=linux/arm64 -v "$ROOT":/io \
      ghcr.io/pyo3/maturin:latest build --release --strip \
      -m /io/rust/veriphi-core-py/Cargo.toml --out /io/dist --manylinux 2014
   
   docker run --rm --platform=linux/amd64 -v "$ROOT":/io \
      ghcr.io/pyo3/maturin:latest build --release --strip \
      -m /io/rust/veriphi-core-py/Cargo.toml --out /io/dist --manylinux 2014
   ```
4. **Source distribution**
   ```bash
   maturin sdist -m rust/veriphi-core-py/Cargo.toml --out dist
   ```

After each build, install the resulting wheel in a clean environment and run `pytest` to validate the artefact.
