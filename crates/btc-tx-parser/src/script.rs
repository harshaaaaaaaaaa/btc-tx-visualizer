/*!
Bitcoin script type detection and ASM disassembly
*/

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptType {
    #[serde(rename = "p2pkh")]
    P2PKH,
    #[serde(rename = "p2sh")]
    P2SH,
    #[serde(rename = "p2wpkh")]
    P2WPKH,
    #[serde(rename = "p2wsh")]
    P2WSH,
    #[serde(rename = "p2tr")]
    P2TR,
    #[serde(rename = "p2pk")]
    P2PK,
    #[serde(rename = "multisig")]
    Multisig,
    #[serde(rename = "op_return")]
    OpReturn,
    #[serde(rename = "witness_unknown")]
    WitnessUnknown,
    #[serde(rename = "nonstandard")]
    NonStandard,
}

impl std::fmt::Display for ScriptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptType::P2PKH => write!(f, "P2PKH (Pay to Public Key Hash)"),
            ScriptType::P2SH => write!(f, "P2SH (Pay to Script Hash)"),
            ScriptType::P2WPKH => write!(f, "P2WPKH (Pay to Witness Public Key Hash)"),
            ScriptType::P2WSH => write!(f, "P2WSH (Pay to Witness Script Hash)"),
            ScriptType::P2TR => write!(f, "P2TR (Pay to Taproot)"),
            ScriptType::P2PK => write!(f, "P2PK (Pay to Public Key)"),
            ScriptType::Multisig => write!(f, "Bare Multisig"),
            ScriptType::OpReturn => write!(f, "OP_RETURN (Data)"),
            ScriptType::WitnessUnknown => write!(f, "Witness Unknown"),
            ScriptType::NonStandard => write!(f, "Non-standard"),
        }
    }
}

#[allow(dead_code)]
pub mod opcodes {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_RESERVED: u8 = 0x50;
    pub const OP_1: u8 = 0x51;
    pub const OP_2: u8 = 0x52;
    pub const OP_3: u8 = 0x53;
    pub const OP_4: u8 = 0x54;
    pub const OP_5: u8 = 0x55;
    pub const OP_6: u8 = 0x56;
    pub const OP_7: u8 = 0x57;
    pub const OP_8: u8 = 0x58;
    pub const OP_9: u8 = 0x59;
    pub const OP_10: u8 = 0x5a;
    pub const OP_11: u8 = 0x5b;
    pub const OP_12: u8 = 0x5c;
    pub const OP_13: u8 = 0x5d;
    pub const OP_14: u8 = 0x5e;
    pub const OP_15: u8 = 0x5f;
    pub const OP_16: u8 = 0x60;
    pub const OP_NOP: u8 = 0x61;
    pub const OP_VER: u8 = 0x62;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_VERIF: u8 = 0x65;
    pub const OP_VERNOTIF: u8 = 0x66;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_RETURN: u8 = 0x6a;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
}

use opcodes::*;

pub fn detect_script_type(script: &[u8]) -> ScriptType {
    if script.is_empty() {
        return ScriptType::NonStandard;
    }

    if script.len() == 25
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == 0x14
        && script[23] == OP_EQUALVERIFY
        && script[24] == OP_CHECKSIG
    {
        return ScriptType::P2PKH;
    }

    if script.len() == 23
        && script[0] == OP_HASH160
        && script[1] == 0x14
        && script[22] == OP_EQUAL
    {
        return ScriptType::P2SH;
    }

    if script.len() == 22
        && script[0] == OP_0
        && script[1] == 0x14
    {
        return ScriptType::P2WPKH;
    }

    if script.len() == 34
        && script[0] == OP_0
        && script[1] == 0x20
    {
        return ScriptType::P2WSH;
    }

    if script.len() == 34
        && script[0] == OP_1
        && script[1] == 0x20
    {
        return ScriptType::P2TR;
    }

    if (script.len() == 35 || script.len() == 67)
        && (script[0] == 0x21 || script[0] == 0x41)
        && script[script.len() - 1] == OP_CHECKSIG
    {
        return ScriptType::P2PK;
    }

    if !script.is_empty() && script[0] == OP_RETURN {
        return ScriptType::OpReturn;
    }

    if script.len() >= 2 && script[0] >= OP_1 && script[0] <= OP_16 {
        let push_size = script[1] as usize;
        if script.len() == 2 + push_size && push_size >= 2 && push_size <= 40 {
            return ScriptType::WitnessUnknown;
        }
    }

    if is_multisig(script) {
        return ScriptType::Multisig;
    }

    ScriptType::NonStandard
}

fn is_multisig(script: &[u8]) -> bool {
    if script.len() < 3 {
        return false;
    }

    if script[script.len() - 1] != OP_CHECKMULTISIG {
        return false;
    }

    let first = script[0];
    if first < OP_1 || first > OP_16 {
        return false;
    }

    let n_byte = script[script.len() - 2];
    if n_byte < OP_1 || n_byte > OP_16 {
        return false;
    }

    true
}

pub fn script_to_asm(script: &[u8]) -> String {
    if script.is_empty() {
        return String::new();
    }

    let mut asm = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];

        match opcode {
            0x01..=0x4b => {
                let n = opcode as usize;
                if i + 1 + n <= script.len() {
                    let data = &script[i + 1..i + 1 + n];
                    asm.push(hex::encode(data));
                    i += 1 + n;
                } else {
                    asm.push(format!("[error: push {} bytes past end]", n));
                    break;
                }
            }
            OP_PUSHDATA1 => {
                if i + 2 <= script.len() {
                    let n = script[i + 1] as usize;
                    if i + 2 + n <= script.len() {
                        let data = &script[i + 2..i + 2 + n];
                        asm.push(hex::encode(data));
                        i += 2 + n;
                    } else {
                        asm.push("[error: PUSHDATA1 past end]".to_string());
                        break;
                    }
                } else {
                    break;
                }
            }
            OP_PUSHDATA2 => {
                if i + 3 <= script.len() {
                    let n = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    if i + 3 + n <= script.len() {
                        let data = &script[i + 3..i + 3 + n];
                        asm.push(hex::encode(data));
                        i += 3 + n;
                    } else {
                        asm.push("[error: PUSHDATA2 past end]".to_string());
                        break;
                    }
                } else {
                    break;
                }
            }
            OP_PUSHDATA4 => {
                if i + 5 <= script.len() {
                    let n = u32::from_le_bytes([
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                        script[i + 4],
                    ]) as usize;
                    if i + 5 + n <= script.len() {
                        let data = &script[i + 5..i + 5 + n];
                        asm.push(hex::encode(data));
                        i += 5 + n;
                    } else {
                        asm.push("[error: PUSHDATA4 past end]".to_string());
                        break;
                    }
                } else {
                    break;
                }
            }
            _ => {
                asm.push(opcode_name(opcode));
                i += 1;
            }
        }
    }

    asm.join(" ")
}

fn opcode_name(opcode: u8) -> String {
    match opcode {
        0x00 => "OP_0".to_string(),
        0x4c => "OP_PUSHDATA1".to_string(),
        0x4d => "OP_PUSHDATA2".to_string(),
        0x4e => "OP_PUSHDATA4".to_string(),
        0x4f => "OP_1NEGATE".to_string(),
        0x50 => "OP_RESERVED".to_string(),
        0x51 => "OP_1".to_string(),
        0x52 => "OP_2".to_string(),
        0x53 => "OP_3".to_string(),
        0x54 => "OP_4".to_string(),
        0x55 => "OP_5".to_string(),
        0x56 => "OP_6".to_string(),
        0x57 => "OP_7".to_string(),
        0x58 => "OP_8".to_string(),
        0x59 => "OP_9".to_string(),
        0x5a => "OP_10".to_string(),
        0x5b => "OP_11".to_string(),
        0x5c => "OP_12".to_string(),
        0x5d => "OP_13".to_string(),
        0x5e => "OP_14".to_string(),
        0x5f => "OP_15".to_string(),
        0x60 => "OP_16".to_string(),
        0x61 => "OP_NOP".to_string(),
        0x62 => "OP_VER".to_string(),
        0x63 => "OP_IF".to_string(),
        0x64 => "OP_NOTIF".to_string(),
        0x65 => "OP_VERIF".to_string(),
        0x66 => "OP_VERNOTIF".to_string(),
        0x67 => "OP_ELSE".to_string(),
        0x68 => "OP_ENDIF".to_string(),
        0x69 => "OP_VERIFY".to_string(),
        0x6a => "OP_RETURN".to_string(),
        0x6b => "OP_TOALTSTACK".to_string(),
        0x6c => "OP_FROMALTSTACK".to_string(),
        0x6d => "OP_2DROP".to_string(),
        0x6e => "OP_2DUP".to_string(),
        0x6f => "OP_3DUP".to_string(),
        0x70 => "OP_2OVER".to_string(),
        0x71 => "OP_2ROT".to_string(),
        0x72 => "OP_2SWAP".to_string(),
        0x73 => "OP_IFDUP".to_string(),
        0x74 => "OP_DEPTH".to_string(),
        0x75 => "OP_DROP".to_string(),
        0x76 => "OP_DUP".to_string(),
        0x77 => "OP_NIP".to_string(),
        0x78 => "OP_OVER".to_string(),
        0x79 => "OP_PICK".to_string(),
        0x7a => "OP_ROLL".to_string(),
        0x7b => "OP_ROT".to_string(),
        0x7c => "OP_SWAP".to_string(),
        0x7d => "OP_TUCK".to_string(),
        0x7e => "OP_CAT".to_string(),
        0x7f => "OP_SUBSTR".to_string(),
        0x80 => "OP_LEFT".to_string(),
        0x81 => "OP_RIGHT".to_string(),
        0x82 => "OP_SIZE".to_string(),
        0x83 => "OP_INVERT".to_string(),
        0x84 => "OP_AND".to_string(),
        0x85 => "OP_OR".to_string(),
        0x86 => "OP_XOR".to_string(),
        0x87 => "OP_EQUAL".to_string(),
        0x88 => "OP_EQUALVERIFY".to_string(),
        0x89 => "OP_RESERVED1".to_string(),
        0x8a => "OP_RESERVED2".to_string(),
        0x8b => "OP_1ADD".to_string(),
        0x8c => "OP_1SUB".to_string(),
        0x8d => "OP_2MUL".to_string(),
        0x8e => "OP_2DIV".to_string(),
        0x8f => "OP_NEGATE".to_string(),
        0x90 => "OP_ABS".to_string(),
        0x91 => "OP_NOT".to_string(),
        0x92 => "OP_0NOTEQUAL".to_string(),
        0x93 => "OP_ADD".to_string(),
        0x94 => "OP_SUB".to_string(),
        0x95 => "OP_MUL".to_string(),
        0x96 => "OP_DIV".to_string(),
        0x97 => "OP_MOD".to_string(),
        0x98 => "OP_LSHIFT".to_string(),
        0x99 => "OP_RSHIFT".to_string(),
        0x9a => "OP_BOOLAND".to_string(),
        0x9b => "OP_BOOLOR".to_string(),
        0x9c => "OP_NUMEQUAL".to_string(),
        0x9d => "OP_NUMEQUALVERIFY".to_string(),
        0x9e => "OP_NUMNOTEQUAL".to_string(),
        0x9f => "OP_LESSTHAN".to_string(),
        0xa0 => "OP_GREATERTHAN".to_string(),
        0xa1 => "OP_LESSTHANOREQUAL".to_string(),
        0xa2 => "OP_GREATERTHANOREQUAL".to_string(),
        0xa3 => "OP_MIN".to_string(),
        0xa4 => "OP_MAX".to_string(),
        0xa5 => "OP_WITHIN".to_string(),
        0xa6 => "OP_RIPEMD160".to_string(),
        0xa7 => "OP_SHA1".to_string(),
        0xa8 => "OP_SHA256".to_string(),
        0xa9 => "OP_HASH160".to_string(),
        0xaa => "OP_HASH256".to_string(),
        0xab => "OP_CODESEPARATOR".to_string(),
        0xac => "OP_CHECKSIG".to_string(),
        0xad => "OP_CHECKSIGVERIFY".to_string(),
        0xae => "OP_CHECKMULTISIG".to_string(),
        0xaf => "OP_CHECKMULTISIGVERIFY".to_string(),
        0xb0 => "OP_NOP1".to_string(),
        0xb1 => "OP_CHECKLOCKTIMEVERIFY".to_string(),
        0xb2 => "OP_CHECKSEQUENCEVERIFY".to_string(),
        0xb3 => "OP_NOP4".to_string(),
        0xb4 => "OP_NOP5".to_string(),
        0xb5 => "OP_NOP6".to_string(),
        0xb6 => "OP_NOP7".to_string(),
        0xb7 => "OP_NOP8".to_string(),
        0xb8 => "OP_NOP9".to_string(),
        0xb9 => "OP_NOP10".to_string(),
        0xba => "OP_CHECKSIGADD".to_string(),
        _ => format!("OP_UNKNOWN_{:02x}", opcode),
    }
}
