use serde::{Deserialize, Serialize};
use crate::script::ScriptType;

// Bitcoin transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    // version
    pub version: i32,
    // segwit flag
    pub is_segwit: bool,
    // inputs
    pub inputs: Vec<TxInput>,
    // outputs
    pub outputs: Vec<TxOutput>,
    // locktime
    pub locktime: u32,
    // txid (hex)
    pub txid: String,
    // wtxid (hex)
    pub wtxid: String,
    // raw size in bytes
    pub raw_size: usize,
    // weight units
    pub weight: usize,
    // total outputs in satoshis
    pub total_output_satoshis: u64,
    // total outputs in BTC
    pub total_output_btc: f64,
    // fee in satoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_satoshis: Option<u64>,
    // fee in BTC
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_btc: Option<f64>,
}

// Transaction input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    // input index
    pub index: usize,
    // previous txid
    pub txid: String,
    // previous output index
    pub vout: u32,
    // scriptSig
    pub script_sig: Script,
    // sequence
    pub sequence: u32,
    // witness stack
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<String>>,
    // input value (satoshis)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    // coinbase flag
    pub is_coinbase: bool,
}

// Transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    // output index
    pub index: usize,
    // value in satoshis
    pub value: u64,
    // value in BTC
    pub value_btc: f64,
    // scriptPubKey
    pub script_pubkey: Script,
    // script type
    pub script_type: ScriptType,
    // derived address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressInfo>,
}

// Script data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Script {
    // hex bytes
    pub hex: String,
    // asm
    pub asm: String,
    // size in bytes
    pub size: usize,
}

// Address info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    // mainnet address
    pub mainnet: String,
    // testnet address
    pub testnet: String,
    // address type
    pub address_type: String,
}

impl Transaction {
    // convert satoshis to BTC
    pub fn satoshis_to_btc(satoshis: u64) -> f64 {
        satoshis as f64 / 100_000_000.0
    }
}
