# Bitcoin Transaction Visualizer

Rust tool to parse and visualize raw Bitcoin transactions, with CLI and Web UI.

## Summary
Parses legacy and SegWit transactions, detects script types, derives addresses, and reports metrics like size, vsize, weight, and fees. Outputs in JSON, pretty text, summary, or ASCII.

## How to Run

### CLI
```bash
cargo build --release -p btc-tx-cli
./target/release/btc-tx-inspector <raw_tx_hex>
```

### Web UI
```bash
cargo install wasm-pack
cd crates/btc-tx-wasm
wasm-pack build --target web --out-dir ../../web/pkg
cd ../../web && python -m http.server 8080
```
Open http://localhost:8080.

## Libraries Used
- **btc-tx-parser**: core transaction parsing and validation.
- **btc-tx-cli**: CLI interface for parsing and output formatting.
- **btc-tx-wasm**: WebAssembly bindings for the browser UI.
- **wasm-pack**: builds Rust to WebAssembly for the web frontend.


