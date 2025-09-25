# Python Bindings (`python/veriphi_core`)

## Overview
Python routines for Veriphi agentic guardrails.  Designed to implement arbitrary and decentralised authorisation graphs for AI agents equipped with tools.  For examples, see the [py_start.ipynb](../../notebooks/py_start.ipynb) file to implement a simple passing of a JSON.  

## Installation / Build
1. Make sure the Rust toolchain is installed (`rustup` recommended) and Python 3.9+ is active.
2. Install [maturin](https://github.com/PyO3/maturin):
   ```bash
   pip install maturin
   ```
3. From the repository root, build and install the extension module in editable mode:
   ```bash
   maturin develop -m rust/veriphi-core-py/Cargo.toml --release
   ```
4. Verify the package imports:
   ```python
   >>> from veriphi_core import interface
   >>> interface.__all__
   ```

## Tests
After running `maturin develop`, execute the pytest suite:
```bash
pytest python/veriphi_core/tests
```
The tests mirror the Node suite to ensure the AES helpers and packet pipeline behave consistently.

## Notebooks
`notebooks/py_start.ipynb` demonstrates the Python API end to end. Launch it from the same environment where you installed the bindings so the kernel can import `veriphi_core`.

## Packaging Notes
- The wheel metadata is driven by `pyproject.toml` at the repo root.
- Rebuild with `maturin build -m rust/veriphi-core-py/Cargo.toml` if you need distributable wheels.
