//! WebAssembly bindings for Bitcoin transaction parser

use wasm_bindgen::prelude::*;
use btc_tx_parser::Transaction;
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}
#[wasm_bindgen]
pub fn parse_transaction(hex: &str) -> Result<JsValue, JsValue> {
    let tx = Transaction::from_hex(hex)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    serde_wasm_bindgen::to_value(&tx)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}
#[wasm_bindgen]
pub fn parse_transaction_json(hex: &str) -> Result<String, JsValue> {
    let tx = Transaction::from_hex(hex)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    serde_json::to_string_pretty(&tx)
        .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))
}

// Get simplified transaction summary
#[wasm_bindgen]
pub fn get_transaction_summary(hex: &str) -> Result<TransactionSummary, JsValue> {
    let tx = Transaction::from_hex(hex)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    let vsize = tx.vsize();

    Ok(TransactionSummary {
        txid: tx.txid.clone(),
        version: tx.version,
        is_segwit: tx.is_segwit,
        input_count: tx.inputs.len(),
        output_count: tx.outputs.len(),
        total_output_btc: tx.total_output_btc,
        size_bytes: tx.raw_size,
        vsize_bytes: vsize,
        weight: tx.weight,
    })
}

// JavaScript-accessible transaction summary
#[wasm_bindgen]
pub struct TransactionSummary {
    txid: String,
    version: i32,
    is_segwit: bool,
    input_count: usize,
    output_count: usize,
    total_output_btc: f64,
    size_bytes: usize,
    vsize_bytes: usize,
    weight: usize,
}

#[wasm_bindgen]
impl TransactionSummary {
    #[wasm_bindgen(getter)]
    pub fn txid(&self) -> String {
        self.txid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> i32 {
        self.version
    }

    #[wasm_bindgen(getter)]
    pub fn is_segwit(&self) -> bool {
        self.is_segwit
    }

    #[wasm_bindgen(getter)]
    pub fn input_count(&self) -> usize {
        self.input_count
    }

    #[wasm_bindgen(getter)]
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    #[wasm_bindgen(getter)]
    pub fn total_output_btc(&self) -> f64 {
        self.total_output_btc
    }

    #[wasm_bindgen(getter)]
    pub fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    #[wasm_bindgen(getter)]
    pub fn vsize_bytes(&self) -> usize {
        self.vsize_bytes
    }

    #[wasm_bindgen(getter)]
    pub fn weight(&self) -> usize {
        self.weight
    }
}

// Validate hex string
#[wasm_bindgen]
pub fn validate_transaction(hex: &str) -> bool {
    Transaction::from_hex(hex).is_ok()
}

// Extract TXID without full parsing
#[wasm_bindgen]
pub fn get_txid(hex: &str) -> Result<String, JsValue> {
    let tx = Transaction::from_hex(hex)
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;
    Ok(tx.txid)
}
