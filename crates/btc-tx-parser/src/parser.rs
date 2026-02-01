//! Bitcoin transaction parser
use crate::address::{derive_address, sha256d};
use crate::error::ParseError;
use crate::script::{detect_script_type, script_to_asm};
use crate::types::*;


pub struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.pos >= self.data.len() {
            return Err(ParseError::UnexpectedEof {
                position: self.pos,
                expected: 1,
            });
        }
        let byte = self.data[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn read_u16_le(&mut self) -> Result<u16, ParseError> {
        if self.pos + 2 > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                position: self.pos,
                expected: 2,
            });
        }
        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        if self.pos + 4 > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                position: self.pos,
                expected: 4,
            });
        }
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i32_le(&mut self) -> Result<i32, ParseError> {
        if self.pos + 4 > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                position: self.pos,
                expected: 4,
            });
        }
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self) -> Result<u64, ParseError> {
        if self.pos + 8 > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                position: self.pos,
                expected: 8,
            });
        }
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ];
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn read_varint(&mut self) -> Result<u64, ParseError> {
        let first = self.read_u8()?;
        match first {
            0..=0xfc => Ok(first as u64),
            0xfd => Ok(self.read_u16_le()? as u64),
            0xfe => Ok(self.read_u32_le()? as u64),
            0xff => self.read_u64_le(),
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, ParseError> {
        if self.pos + n > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                position: self.pos,
                expected: n,
            });
        }
        let bytes = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(bytes)
    }

    pub(crate) fn read_hash(&mut self) -> Result<String, ParseError> {
        let bytes = self.read_bytes(32)?;
        let reversed: Vec<u8> = bytes.into_iter().rev().collect();
        Ok(hex::encode(reversed))
    }

    // Main transaction parsing function
    pub fn parse_transaction(&mut self) -> Result<Transaction, ParseError> {
        let start_pos = self.position();

        let version = self.read_i32_le()?;

        let (is_segwit, marker_flag_size) = self.check_segwit()?;

        // Number of inputs
        let input_count = self.read_varint()?;
        if input_count == 0 && !is_segwit {
            return Err(ParseError::InvalidTransaction(
                "Transaction has no inputs".to_string(),
            ));
        }

        // Parse inputs
        let mut inputs = Vec::with_capacity(input_count as usize);
        for i in 0..input_count {
            inputs.push(self.parse_input(i as usize)?);
        }

        // Number of outputs
        let output_count = self.read_varint()?;
        if output_count == 0 {
            return Err(ParseError::InvalidTransaction(
                "Transaction has no outputs".to_string(),
            ));
        }

        // Parse outputs
        let mut outputs = Vec::with_capacity(output_count as usize);
        for i in 0..output_count {
            outputs.push(self.parse_output(i as usize)?);
        }

        // Parse witness data if SegWit
        if is_segwit {
            for input in &mut inputs {
                input.witness = Some(self.parse_witness()?);
            }
        }

        let locktime = self.read_u32_le()?;

        // Calculate transaction IDs
        let raw_size = self.position() - start_pos;
        let tx_data = &self.data[start_pos..self.position()];

        // Calculate txid
        let txid = self.calculate_txid(tx_data, is_segwit, version, &inputs, &outputs, locktime);

        // wtxid is hash of full serialization
        let wtxid_hash = sha256d(tx_data);
        let wtxid: String = wtxid_hash.iter().rev().map(|b| format!("{:02x}", b)).collect();

        let weight = if is_segwit {
            let base_size = raw_size - marker_flag_size - self.witness_size(&inputs);
            base_size * 3 + raw_size
        } else {
            raw_size * 4
        };

        let total_output_satoshis = outputs.iter().map(|o| o.value).sum();
        let total_output_btc = Transaction::satoshis_to_btc(total_output_satoshis);

        Ok(Transaction {
            version,
            is_segwit,
            inputs,
            outputs,
            locktime,
            txid,
            wtxid,
            raw_size,
            weight,
            total_output_satoshis,
            total_output_btc,
            fee_satoshis: None,
            fee_btc: None,
        })
    }

    fn check_segwit(&mut self) -> Result<(bool, usize), ParseError> {
        // Save position
        let saved_pos = self.pos;
        if self.remaining() >= 2 {
            let marker = self.read_u8()?;
            let flag = self.read_u8()?;

            if marker == 0x00 && flag == 0x01 {
                return Ok((true, 2));
            }
        }
        self.pos = saved_pos;
        Ok((false, 0))
    }

    // Parse single transaction input
    fn parse_input(&mut self, index: usize) -> Result<TxInput, ParseError> {
        let txid = self.read_hash()?;
        let vout = self.read_u32_le()?;
        let script_len = self.read_varint()? as usize;
        let script_bytes = self.read_bytes(script_len)?;
        let sequence = self.read_u32_le()?;

        // Check if this is a coinbase input
        let is_coinbase = txid == "0000000000000000000000000000000000000000000000000000000000000000"
            && vout == 0xffffffff;

        let script_sig = Script {
            hex: hex::encode(&script_bytes),
            asm: if is_coinbase {
                format!("[coinbase] {}", hex::encode(&script_bytes))
            } else {
                script_to_asm(&script_bytes)
            },
            size: script_bytes.len(),
        };

        Ok(TxInput {
            index,
            txid,
            vout,
            script_sig,
            sequence,
            witness: None,
            value: None,
            is_coinbase,
        })
    }

    // Parse single transaction output
    fn parse_output(&mut self, index: usize) -> Result<TxOutput, ParseError> {
        let value = self.read_u64_le()?;

        // ScriptPubKey length and data
        let script_len = self.read_varint()? as usize;
        let script_bytes = self.read_bytes(script_len)?;

        // Detect script type
        let script_type = detect_script_type(&script_bytes);

        let address = derive_address(&script_bytes, &script_type);

        let script_pubkey = Script {
            hex: hex::encode(&script_bytes),
            asm: script_to_asm(&script_bytes),
            size: script_bytes.len(),
        };

        Ok(TxOutput {
            index,
            value,
            value_btc: Transaction::satoshis_to_btc(value),
            script_pubkey,
            script_type,
            address,
        })
    }

    fn parse_witness(&mut self) -> Result<Vec<String>, ParseError> {
        let stack_items = self.read_varint()? as usize;
        let mut witness = Vec::with_capacity(stack_items);

        for _ in 0..stack_items {
            let item_len = self.read_varint()? as usize;
            let item = self.read_bytes(item_len)?;
            witness.push(hex::encode(item));
        }

        Ok(witness)
    }

    fn calculate_txid(
        &self,
        _full_data: &[u8],
        is_segwit: bool,
        version: i32,
        inputs: &[TxInput],
        outputs: &[TxOutput],
        locktime: u32,
    ) -> String {

        let mut serialized = Vec::new();

        serialized.extend_from_slice(&version.to_le_bytes());

        // Input count (varint)
        Self::write_varint(&mut serialized, inputs.len() as u64);

        // Inputs (without witness)
        for input in inputs {
            let txid_bytes: Vec<u8> = hex::decode(&input.txid)
                .unwrap()
                .into_iter()
                .rev()
                .collect();
            serialized.extend_from_slice(&txid_bytes);

            // Vout
            serialized.extend_from_slice(&input.vout.to_le_bytes());

            // ScriptSig
            let script_bytes = hex::decode(&input.script_sig.hex).unwrap();
            Self::write_varint(&mut serialized, script_bytes.len() as u64);
            serialized.extend_from_slice(&script_bytes);

            // Sequence
            serialized.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Output count
        Self::write_varint(&mut serialized, outputs.len() as u64);

        // Outputs
        for output in outputs {
            // Value
            serialized.extend_from_slice(&output.value.to_le_bytes());

            // ScriptPubKey
            let script_bytes = hex::decode(&output.script_pubkey.hex).unwrap();
            Self::write_varint(&mut serialized, script_bytes.len() as u64);
            serialized.extend_from_slice(&script_bytes);
        }

        // Locktime
        serialized.extend_from_slice(&locktime.to_le_bytes());

        let hash = sha256d(&serialized);

        if is_segwit {
            hash.iter().rev().map(|b| format!("{:02x}", b)).collect()
        } else {
            hash.iter().rev().map(|b| format!("{:02x}", b)).collect()
        }
    }

    fn write_varint(buf: &mut Vec<u8>, n: u64) {
        if n < 0xfd {
            buf.push(n as u8);
        } else if n <= 0xffff {
            buf.push(0xfd);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        } else if n <= 0xffffffff {
            buf.push(0xfe);
            buf.extend_from_slice(&(n as u32).to_le_bytes());
        } else {
            buf.push(0xff);
            buf.extend_from_slice(&n.to_le_bytes());
        }
    }

    fn witness_size(&self, inputs: &[TxInput]) -> usize {
        let mut size = 0;
        for input in inputs {
            if let Some(witness) = &input.witness {
                // Count varint for number of items
                size += Self::varint_size(witness.len() as u64);
                for item in witness {
                    let item_bytes = hex::decode(item).unwrap_or_default();
                    size += Self::varint_size(item_bytes.len() as u64);
                    size += item_bytes.len();
                }
            }
        }
        size
    }

    fn varint_size(n: u64) -> usize {
        if n < 0xfd {
            1
        } else if n <= 0xffff {
            3
        } else if n <= 0xffffffff {
            5
        } else {
            9
        }
    }
}
