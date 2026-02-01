# Bitcoin Transaction Visualizer

Rust tool to parse and visualize raw Bitcoin transactions, with CLI and Web UI.

## Summary
Parses legacy and SegWit transactions, detects script types, derives addresses, and reports metrics like size, vsize, weight, and fees. Outputs in JSON, pretty text, summary, or ASCII.

## Live Demo
GitHub Pages build: https://harshaaaaaaaaaa.github.io/btc-tx-visualizer/

## How Parsing Works
- Varint parsing: input/output counts, script sizes, and witness stack sizes are varint encoded. Values 0x00-0xfc are single byte, 0xfd reads 2 bytes LE, 0xfe reads 4 bytes LE, and 0xff reads 8 bytes LE.
- SegWit detection: after the version, the parser peeks for marker 0x00 and flag 0x01. If present, it parses inputs/outputs normally, then reads witness stacks for each input after outputs.
- Fees: fee is computed only when input values are provided (CLI `--input-values`). The parser sums input values and subtracts total output; if any input value is missing, fee stays unset.
- Output fields (per output): `index` is the output position, `value`/`value_btc` is the amount, `script_pubkey` holds hex/asm/size, `script_type` is the detected type (P2PKH/P2WPKH/etc), and `address` includes derived mainnet/testnet strings when possible.

## Example Output (Summary)
```text
Transaction: 2b3a...9f12
	Version: 2, SegWit: true
	1 input(s), 2 output(s)
	Size: 222 bytes, vSize: 141 vbytes
	Total output: 0.01500000 BTC (1500000 sats)

Outputs:
	#0: 0.01000000 BTC -> bc1q... (P2WPKH)
	#1: 0.00500000 BTC -> bc1p... (P2TR)
```

## Performance (Sample)
Build once, then measure parse time on a large raw transaction. Replace `<RAW_TX_HEX>` with real input and paste your results.
```bash
cargo build --release -p btc-tx-cli
hyperfine './target/release/btc-tx-inspector --output summary <RAW_TX_HEX>'
```
```text
Time (mean ± σ): <paste your measured output here>
```

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

## Releases
- Each release publishes the web UI to GitHub Pages for easy sharing. 
    Happy learning :)



