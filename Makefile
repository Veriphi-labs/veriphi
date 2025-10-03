# ===== Veriphi unified build/test Makefile =====

SHELL := /bin/bash
.ONESHELL:

# --- Paths (adjust if yours differ) ---
RUST_WS           := rust/veriphi-sdk/Cargo.toml
PY_BINDING_TOML   := rust/veriphi-core-py/Cargo.toml
NODE_NATIVE_DIR   := node/veriphi-core-node
NODE_TS_DIR       := node/veriphi_core
WASM_RS_DIR       := rust/veriphi-core-wasm
WASM_TS_DIR       := wasm/veriphi_core

# --- Phony ---
.PHONY: clean clean-node clean-python clean-rust clean-wasm \
        build build-rust build-python build-node build-wasm build-ts \
        test test-rust test-python test-node test-wasm all ci

# ---------- CLEAN ----------
clean: clean-rust clean-python clean-node clean-wasm

clean-rust:
	@echo "==> Clean Rust workspace"
	cargo clean --manifest-path $(RUST_WS) || true

clean-python:
	@echo "==> Clean Python artifacts"
	rm -rf python/**/__pycache__ python/**/.pytest_cache python/**/build python/**/dist python/**/*.egg-info || true
	rm -rf python/**/veriphi_core_py* || true
	rm -rf .pytest_cache || true

clean-node:
	@echo "==> Clean Node artifacts"
	rm -rf ./node_modules  package-lock.json || true
	rm -rf $(NODE_NATIVE_DIR)/target $(NODE_NATIVE_DIR)/index.node  || true
	rm -rf $(NODE_NATIVE_DIR)/package-lock.json $(NODE_NATIVE_DIR)/node_modules $(NODE_NATIVE_DIR)/cargo.lock 
	rm -rf $(NODE_TS_DIR)/node_modules $(NODE_TS_DIR)/dist $(NODE_TS_DIR)/package-lock.json || true

clean-wasm:
	@echo "==> Clean WASM artifacts"
	rm -rf $(WASM_RS_DIR)/pkg || true
	rm -rf $(WASM_TS_DIR)/node_modules $(WASM_TS_DIR)/dist $(WASM_TS_DIR)/package-lock.json || true

# ---------- BUILD ----------
build: build-rust build-python build-node build-wasm build-ts

build-rust:
	@echo "==> Build Rust core (release)"
	cargo build --release --manifest-path $(RUST_WS)

build-python:
	@echo "==> Build Python bindings with maturin (release, develop)"
	maturin develop -m $(PY_BINDING_TOML) --release

build-node:
	@echo "==> Build Node native addon (napi-rs)"
	npm --prefix $(NODE_NATIVE_DIR) install
	npm --prefix $(NODE_NATIVE_DIR) run build
	npm install

build-ts:
	@echo "==> Build TS packages"
	npm --prefix $(NODE_TS_DIR) install
	npm --prefix $(NODE_TS_DIR) run build
	npm --prefix $(WASM_TS_DIR) install
	npm --prefix $(WASM_TS_DIR) run build

build-wasm:
	@echo "==> Build WASM crate (wasm-pack bundler)"
	wasm-pack build --release --target web --out-dir pkg $(WASM_RS_DIR)

# ---------- TEST ----------
test: test-rust test-python test-node test-wasm

test-rust:
	@echo "==> Test Rust workspace"
	cargo test --manifest-path $(RUST_WS)

test-python:
	@echo "==> Test Python (pytest)"
	pytest -q

test-node:
	@echo "==> Test Node TS (vitest)"
	npm --prefix $(NODE_TS_DIR) run test

test-wasm:
	@echo "==> Test WASM TS (vitest)"
	npm --prefix $(WASM_TS_DIR) run test

# ---------- FULL PIPELINE ----------
all: clean build test
ci:  all
