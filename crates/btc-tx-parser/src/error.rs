//! Bitcoin transaction parsing error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("Unexpected end of data at position {position}, expected {expected} bytes")]
    UnexpectedEof {
        position: usize,
        expected: usize,
    },

    #[error("Invalid varint encoding at position {0}")]
    InvalidVarInt(usize),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Invalid script: {0}")]
    InvalidScript(String),

    #[error("Invalid witness data: {0}")]
    InvalidWitness(String),

    #[error("Unsupported transaction version: {0}")]
    UnsupportedVersion(i32),

    #[error("Data remaining after parsing: {0} bytes")]
    TrailingData(usize),
}
