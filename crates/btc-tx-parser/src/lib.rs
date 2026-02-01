// BTC Transaction Parser Library
mod error;
mod parser;
mod script;
mod address;
mod types;

#[cfg(test)]
mod tests;

pub use error::ParseError;
pub use types::*;
pub use script::ScriptType;
pub use address::Network;

use parser::Parser;

impl Transaction {
    pub fn from_hex(hex_str: &str) -> Result<Self, ParseError> {
        let bytes = hex::decode(hex_str.trim())?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut parser = Parser::new(bytes);
        parser.parse_transaction()
    }

    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    pub fn calculate_fee(&self) -> Option<u64> {
        let total_input: Option<u64> = self.inputs.iter()
            .map(|i| i.value)
            .try_fold(0u64, |acc, v| v.map(|val| acc + val));

        total_input.map(|input| input.saturating_sub(self.total_output_value()))
    }

    pub fn size(&self) -> usize {
        self.raw_size
    }

    pub fn vsize(&self) -> usize {
        if self.is_segwit {
            (self.weight + 3) / 4
        } else {
            self.raw_size
        }
    }
}
