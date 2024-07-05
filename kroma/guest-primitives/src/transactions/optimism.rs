// Copyright 2024 RISC Zero, Inc.
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

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable};
use bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};

use super::signature::TxSignature;
use crate::transactions::{
    ethereum::{EthereumTxEssence, TransactionKind},
    SignedDecodable, TxEssence,
};

/// The EIP-2718 transaction type for an Optimism deposited transaction.
pub const OPTIMISM_DEPOSITED_TX_TYPE: u8 = 0x7E;

/// Represents an Optimism depositing transaction that is a L2 transaction that was
/// derived from L1 and included in a L2 block.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
pub struct TxEssenceOptimismDeposited {
    /// The source hash which uniquely identifies the origin of the deposit.
    pub source_hash: B256,
    /// The 160-bit address of the sender.
    pub from: Address,
    /// The 160-bit address of the intended recipient for a message call or
    /// [TransactionKind::Create] for contract creation.
    pub to: TransactionKind,
    /// The ETH value to mint on L2.
    pub mint: U256,
    /// The amount, in Wei, to be transferred to the recipient of the message call.
    pub value: U256,
    /// The maximum amount of gas allocated for the execution of the L2 transaction.
    pub gas_limit: U256,
    /// If true, the transaction does not interact with the L2 block gas pool.
    pub is_system_tx: bool,
    /// The transaction's payload, represented as a variable-length byte array.
    pub data: Bytes,
}

/// Represents the core essence of an Optimism transaction, specifically the portion that
/// gets signed.
///
/// The [OptimismTxEssence] enum provides a way to handle different types of Optimism
/// transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimismTxEssence {
    /// Represents an Ethereum-compatible L2 transaction.
    Ethereum(EthereumTxEssence),
    /// Represents an Optimism depositing transaction.
    OptimismDeposited(TxEssenceOptimismDeposited),
}

impl Default for OptimismTxEssence {
    fn default() -> Self {
        OptimismTxEssence::Ethereum(EthereumTxEssence::default())
    }
}

impl Encodable for OptimismTxEssence {
    /// Encodes the [OptimismTxEssence] enum variant into the provided `out` buffer.
    #[inline]
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.encode(out),
            OptimismTxEssence::OptimismDeposited(op) => op.encode(out),
        }
    }

    /// Computes the length of the RLP-encoded [OptimismTxEssence] enum variant in bytes.
    #[inline]
    fn length(&self) -> usize {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.length(),
            OptimismTxEssence::OptimismDeposited(op) => op.length(),
        }
    }
}

impl SignedDecodable<TxSignature> for OptimismTxEssence {
    fn decode_signed(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, TxSignature)> {
        match buf.first().copied() {
            Some(0x7e) => {
                buf.advance(1);
                Ok((
                    OptimismTxEssence::OptimismDeposited(TxEssenceOptimismDeposited::decode(buf)?),
                    TxSignature::default(),
                ))
            }
            Some(_) => EthereumTxEssence::decode_signed(buf)
                .map(|(e, s)| (OptimismTxEssence::Ethereum(e), s)),
            None => Err(alloy_rlp::Error::InputTooShort),
        }
    }
}

impl TxEssence for OptimismTxEssence {
    /// Returns the EIP-2718 transaction type.
    fn tx_type(&self) -> u8 {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.tx_type(),
            OptimismTxEssence::OptimismDeposited(_) => OPTIMISM_DEPOSITED_TX_TYPE,
        }
    }
    /// Returns the gas limit set for the transaction.
    fn gas_limit(&self) -> U256 {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.gas_limit(),
            OptimismTxEssence::OptimismDeposited(op) => op.gas_limit,
        }
    }
    /// Returns the recipient address of the transaction, if available.
    fn to(&self) -> Option<Address> {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.to(),
            OptimismTxEssence::OptimismDeposited(op) => op.to.into(),
        }
    }
    /// Recovers the Ethereum address of the sender from the transaction's signature.
    fn recover_from(&self, signature: &TxSignature) -> anyhow::Result<Address> {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.recover_from(signature),
            OptimismTxEssence::OptimismDeposited(op) => Ok(op.from),
        }
    }
    /// Returns the length of the RLP-encoding payload in bytes.
    fn payload_length(&self) -> usize {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.payload_length(),
            OptimismTxEssence::OptimismDeposited(op) => op._alloy_rlp_payload_length(),
        }
    }
    /// Returns a reference to the transaction's call data
    fn data(&self) -> &Bytes {
        match self {
            OptimismTxEssence::Ethereum(eth) => eth.data(),
            OptimismTxEssence::OptimismDeposited(op) => &op.data,
        }
    }
}
