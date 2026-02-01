use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use crate::script::ScriptType;
use crate::types::AddressInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
        }
    }

    fn p2sh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet => 0xc4,
        }
    }

    fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
        }
    }
}

// Derived addresses from scriptPubKey for all supported script types
pub fn derive_address(script: &[u8], script_type: &ScriptType) -> Option<AddressInfo> {
    match script_type {
        ScriptType::P2PKH => {
            if script.len() >= 23 {
                let hash = &script[3..23];
                Some(AddressInfo {
                    mainnet: encode_base58check(hash, Network::Mainnet.p2pkh_version()),
                    testnet: encode_base58check(hash, Network::Testnet.p2pkh_version()),
                    address_type: "P2PKH".to_string(),
                })
            } else {
                None
            }
        }
        ScriptType::P2SH => {
            if script.len() >= 22 {
                let hash = &script[2..22];
                Some(AddressInfo {
                    mainnet: encode_base58check(hash, Network::Mainnet.p2sh_version()),
                    testnet: encode_base58check(hash, Network::Testnet.p2sh_version()),
                    address_type: "P2SH".to_string(),
                })
            } else {
                None
            }
        }
        ScriptType::P2WPKH => {
            if script.len() >= 22 {
                let hash = &script[2..22];
                Some(AddressInfo {
                    mainnet: encode_bech32(hash, Network::Mainnet, 0).unwrap_or_default(),
                    testnet: encode_bech32(hash, Network::Testnet, 0).unwrap_or_default(),
                    address_type: "P2WPKH".to_string(),
                })
            } else {
                None
            }
        }
        ScriptType::P2WSH => {
            if script.len() >= 34 {
                let hash = &script[2..34];
                Some(AddressInfo {
                    mainnet: encode_bech32(hash, Network::Mainnet, 0).unwrap_or_default(),
                    testnet: encode_bech32(hash, Network::Testnet, 0).unwrap_or_default(),
                    address_type: "P2WSH".to_string(),
                })
            } else {
                None
            }
        }
        ScriptType::P2TR => {
            if script.len() >= 34 {
                let pubkey = &script[2..34];
                Some(AddressInfo {
                    mainnet: encode_bech32m(pubkey, Network::Mainnet).unwrap_or_default(),
                    testnet: encode_bech32m(pubkey, Network::Testnet).unwrap_or_default(),
                    address_type: "P2TR".to_string(),
                })
            } else {
                None
            }
        }
        ScriptType::P2PK => {
            let pubkey_len = script[0] as usize;
            if script.len() > pubkey_len {
                let pubkey = &script[1..1 + pubkey_len];
                let hash = hash160(pubkey);
                Some(AddressInfo {
                    mainnet: encode_base58check(&hash, Network::Mainnet.p2pkh_version()),
                    testnet: encode_base58check(&hash, Network::Testnet.p2pkh_version()),
                    address_type: "P2PK (derived P2PKH)".to_string(),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(sha256_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

// Double SHA256 for txid/wtxid calculation
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

fn encode_base58check(data: &[u8], version: u8) -> String {
    let mut payload = vec![version];
    payload.extend_from_slice(data);

    // Add checksum (first 4 bytes of double SHA256)
    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);

    bs58::encode(payload).into_string()
}

fn encode_bech32(data: &[u8], network: Network, witness_version: u8) -> Option<String> {
    use bech32::{segwit, Hrp, Fe32};

    let hrp = Hrp::parse(network.bech32_hrp()).ok()?;
    let version = Fe32::try_from(witness_version).ok()?;

    segwit::encode(hrp, version, data).ok()
}

fn encode_bech32m(data: &[u8], network: Network) -> Option<String> {
    use bech32::{segwit, Hrp, Fe32};

    let hrp = Hrp::parse(network.bech32_hrp()).ok()?;
    let version = Fe32::try_from(1u8).ok()?;

    segwit::encode(hrp, version, data).ok()
}
