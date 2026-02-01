//Tests for btc-tx-parser crate

use crate::{Transaction, ScriptType};
use crate::address::{hash160, sha256d};
use crate::parser::Parser;
use crate::script::detect_script_type;

// ============================================================================
// Transaction Parsing Tests
// ============================================================================

#[test]
fn test_parse_legacy_tx() {
    let hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    let tx = Transaction::from_hex(hex);
    assert!(tx.is_ok(), "Failed to parse legacy transaction: {:?}", tx.err());

    let tx = tx.unwrap();
    assert_eq!(tx.version, 1);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2);
    assert!(!tx.is_segwit);
}

#[test]
fn test_parse_segwit_tx() {
    let hex = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502e8030101ffffffff0200f2052a0100000016001496ba8ba89947e739cd4e48507f9d26f47ed31c4e0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";

    let tx = Transaction::from_hex(hex);
    assert!(tx.is_ok(), "Failed to parse segwit transaction: {:?}", tx.err());

    let tx = tx.unwrap();
    assert_eq!(tx.version, 2);
    assert!(tx.is_segwit);
}

// ============================================================================
// Parser Tests
// ============================================================================

#[test]
fn test_varint_parsing() {
    // Single byte
    let mut parser = Parser::new(&[0x42]);
    assert_eq!(parser.read_varint().unwrap(), 0x42);

    // Two bytes (0xfd prefix)
    let mut parser = Parser::new(&[0xfd, 0x00, 0x01]);
    assert_eq!(parser.read_varint().unwrap(), 256);

    // Four bytes (0xfe prefix)
    let mut parser = Parser::new(&[0xfe, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(parser.read_varint().unwrap(), 65536);
}

#[test]
fn test_hash_reading() {
    let hash_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let mut parser = Parser::new(&hash_bytes);
    let hash = parser.read_hash().unwrap();
    assert_eq!(hash, "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201");
}

// ============================================================================
// Script Type Detection Tests
// ============================================================================

#[test]
fn test_detect_p2pkh() {
    let script = hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
    assert_eq!(detect_script_type(&script), ScriptType::P2PKH);
}

#[test]
fn test_detect_p2sh() {
    let script = hex::decode("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87").unwrap();
    assert_eq!(detect_script_type(&script), ScriptType::P2SH);
}

#[test]
fn test_detect_p2wpkh() {
    let script = hex::decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
    assert_eq!(detect_script_type(&script), ScriptType::P2WPKH);
}

#[test]
fn test_detect_p2wsh() {
    let script = hex::decode("002089abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
    assert_eq!(detect_script_type(&script), ScriptType::P2WSH);
}

#[test]
fn test_detect_p2tr() {
    let script = hex::decode("512089abcdefabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
    assert_eq!(detect_script_type(&script), ScriptType::P2TR);
}

#[test]
fn test_detect_op_return() {
    let script = hex::decode("6a0b68656c6c6f20776f726c64").unwrap();
    assert_eq!(detect_script_type(&script), ScriptType::OpReturn);
}

// ============================================================================
// Address Encoding Tests
// ============================================================================

#[test]
fn test_hash160() {
    let data = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    let hash = hash160(&data);
    assert_eq!(hex::encode(hash), "751e76e8199196d454941c45d1b3a323f1433bd6");
}

#[test]
fn test_sha256d() {
    let data = b"hello";
    let hash = sha256d(data);
    assert_eq!(hash.len(), 32);
}
