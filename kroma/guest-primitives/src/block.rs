// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy_consensus::Header as AlloyHeader;
use alloy_primitives::{b256, Address, BlockHash, BlockNumber, Bloom, Bytes, B256, B64, U256};
use alloy_rlp_derive::RlpEncodable;
use serde::{Deserialize, Serialize};

use crate::{keccak::keccak, trie::EMPTY_ROOT};

/// Keccak-256 hash of the RLP of an empty list.
pub const EMPTY_LIST_HASH: B256 =
    b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable)]
#[rlp(trailing)]
pub struct Header {
    /// Hash of the parent block's header.
    pub parent_hash: BlockHash,
    /// Unused 256-bit hash, always [EMPTY_LIST_HASH].
    pub ommers_hash: B256,
    /// Address that receives the priority fees of each transaction in the block.
    pub beneficiary: Address,
    /// Root hash of the state trie after all transactions in the block are executed.
    pub state_root: B256,
    /// Root hash of the trie containing all transactions in the block.
    pub transactions_root: B256,
    /// Root hash of the trie containing the receipts of each transaction in the block.
    pub receipts_root: B256,
    /// Bloom filter for log entries in the block.
    pub logs_bloom: Bloom,
    /// Always set to `0` as it's unused.
    pub difficulty: U256,
    /// The block number in the chain.
    pub number: BlockNumber,
    /// Maximum amount of gas that can be used in this block.
    pub gas_limit: U256,
    /// Total amount of gas used by all transactions in this block.
    pub gas_used: U256,
    /// Value corresponding to the seconds since Epoch at this block's inception.
    pub timestamp: U256,
    /// Arbitrary byte array containing extra data related to the block.
    pub extra_data: Bytes,
    /// Hash previously used for the PoW now containing the RANDAO value.
    pub mix_hash: B256,
    /// Unused 64-bit hash, always zero.
    pub nonce: B64,
    /// Base fee paid by all transactions in the block.
    pub base_fee_per_gas: U256,
    /// Root hash of the trie containing all withdrawals in the block. Present after the
    /// Shanghai update.
    #[serde(default)]
    pub withdrawals_root: Option<B256>,
    #[serde(default)]
    pub blob_gas_used: Option<U256>,
    #[serde(default)]
    pub excess_blob_gas: Option<U256>,
    #[serde(default)]
    pub parent_beacon_block_root: Option<B256>,
}

impl Default for Header {
    /// Provides default values for a block header.
    fn default() -> Self {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: EMPTY_LIST_HASH,
            beneficiary: Address::ZERO,
            state_root: EMPTY_ROOT,
            transactions_root: EMPTY_ROOT,
            receipts_root: EMPTY_ROOT,
            logs_bloom: Bloom::default(),
            difficulty: U256::ZERO,
            number: 0,
            gas_limit: U256::ZERO,
            gas_used: U256::ZERO,
            timestamp: U256::ZERO,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: B64::ZERO,
            base_fee_per_gas: U256::ZERO,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        }
    }
}

impl Header {
    /// Computes the hash of the block header.
    pub fn hash(&self) -> BlockHash {
        keccak(alloy_rlp::encode(self)).into()
    }

    pub fn to_alloy_header(&self) -> AlloyHeader {
        AlloyHeader {
            parent_hash: self.parent_hash,
            ommers_hash: self.ommers_hash,
            beneficiary: self.beneficiary,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: self.difficulty,
            number: self.number,
            gas_limit: self.gas_limit.to::<u128>(),
            gas_used: self.gas_used.to::<u128>(),
            timestamp: self.timestamp.to::<u64>(),
            extra_data: self.extra_data.clone(),
            mix_hash: self.mix_hash,
            nonce: self.nonce,
            base_fee_per_gas: Some(self.base_fee_per_gas.to::<u128>()),
            withdrawals_root: self.withdrawals_root,
            blob_gas_used: self.blob_gas_used.map(|gas| gas.to::<u128>()),
            excess_blob_gas: self.excess_blob_gas.map(|gas| gas.to::<u128>()),
            parent_beacon_block_root: self.parent_beacon_block_root,
        }
    }
}
