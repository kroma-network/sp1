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

use alloy_primitives::{Address, Bytes, ChainId, TxNumber, B256, U256};
use alloy_rlp::{Decodable, Encodable, EMPTY_STRING_CODE};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable};
use anyhow::Context;
use bytes::Buf;
use k256::{
    ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey as K256VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey as K256PublicKey,
};
use serde::{Deserialize, Serialize};

use super::signature::TxSignature;
use crate::{
    access_list::AccessList,
    keccak::keccak,
    transactions::{SignedDecodable, TxEssence},
};

/// Represents a legacy Ethereum transaction as detailed in [EIP-155](https://eips.ethereum.org/EIPS/eip-155).
///
/// The `TxEssenceLegacy` struct encapsulates the core components of a traditional
/// Ethereum transaction prior to the introduction of more recent transaction types. It
/// adheres to the specifications set out in EIP-155.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TxEssenceLegacy {
    /// The network's chain ID introduced in EIP-155 to prevent replay attacks across
    /// different chains.
    pub chain_id: Option<ChainId>,
    /// A numeric value representing the total number of transactions previously sent by
    /// the sender.
    pub nonce: TxNumber,
    /// The price, in Wei, that the sender is willing to pay per unit of gas for the
    /// transaction's execution.
    pub gas_price: U256,
    /// The maximum amount of gas allocated for the transaction's execution.
    pub gas_limit: U256,
    /// The 160-bit address of the intended recipient for a message call or
    /// [TransactionKind::Create] for contract creation.
    pub to: TransactionKind,
    /// The amount, in Wei, to be transferred to the recipient of the message call.
    pub value: U256,
    /// The transaction's payload, represented as a variable-length byte array.
    pub data: Bytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
struct TxEssenceLegacyTxSignature {
    pub nonce: TxNumber,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: TransactionKind,
    pub value: U256,
    pub data: Bytes,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

impl SignedDecodable<TxSignature> for TxEssenceLegacy {
    fn decode_signed(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, TxSignature)> {
        let signed_essence = TxEssenceLegacyTxSignature::decode(buf)?;
        let signature = TxSignature {
            v: signed_essence.v,
            r: signed_essence.r,
            s: signed_essence.s,
        };
        Ok((
            Self {
                // with EIP-155, the chain_id is derived from the signature
                chain_id: signature.chain_id(),
                nonce: signed_essence.nonce,
                gas_price: signed_essence.gas_price,
                gas_limit: signed_essence.gas_limit,
                to: signed_essence.to,
                value: signed_essence.value,
                data: signed_essence.data,
            },
            signature,
        ))
    }
}

impl TxEssenceLegacy {
    /// Computes the length of the RLP-encoded payload in bytes.
    ///
    /// This method calculates the combined length of all the individual fields
    /// of the transaction when they are RLP-encoded.
    pub fn payload_length(&self) -> usize {
        self.nonce.length()
            + self.gas_price.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
    }

    /// Encodes the transaction essence into the provided `out` buffer for the purpose of
    /// signing.
    ///
    /// According to EIP-155, if `chain_id` is present, `(chain_id, 0, 0)` must be
    /// appended to the regular RLP encoding when computing the hash of a transaction for
    /// the purposes of signing.
    pub fn signing_encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut payload_length = self.payload_length();
        // append chain ID according to EIP-155 if present
        if let Some(chain_id) = self.chain_id {
            payload_length += chain_id.length() + 1 + 1;
        }
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.nonce.encode(out);
        self.gas_price.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.data.encode(out);
        if let Some(chain_id) = self.chain_id {
            chain_id.encode(out);
            out.put_u8(alloy_rlp::EMPTY_STRING_CODE);
            out.put_u8(alloy_rlp::EMPTY_STRING_CODE);
        }
    }

    /// Computes the length of the RLP-encoded transaction essence in bytes, specifically
    /// for signing.
    ///
    /// This method calculates the total length of the transaction when it is RLP-encoded,
    /// including any additional bytes required for the encoding format.
    pub fn signing_length(&self) -> usize {
        let mut payload_length = self.payload_length();
        // append chain ID according to EIP-155 if present
        if let Some(chain_id) = self.chain_id {
            payload_length += chain_id.length() + 1 + 1;
        }
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

// Implement the Encodable trait for `TxEssenceLegacy`.
// Ensures that the `chain_id` is always ignored during the RLP encoding process.
impl Encodable for TxEssenceLegacy {
    /// Encodes the [TxEssenceLegacy] instance into the provided `out` buffer.
    ///
    /// This method follows the RLP encoding scheme, but intentionally omits the
    /// `chain_id` to ensure compatibility with legacy transactions.
    #[inline]
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);
        self.nonce.encode(out);
        self.gas_price.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.data.encode(out);
    }

    /// Computes the length of the RLP-encoded [TxEssenceLegacy] instance in bytes.
    ///
    /// This method calculates the total length of the transaction when it is RLP-encoded,
    /// excluding the `chain_id`.
    #[inline]
    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

/// Represents an Ethereum transaction with an access list, as detailed in [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930).
///
/// The `TxEssenceEip2930` struct encapsulates the core components of an Ethereum
/// transaction that includes an access list. Access lists are a feature introduced in
/// EIP-2930 to specify a list of addresses and storage keys that the transaction will
/// access, allowing for more predictable gas costs.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
pub struct TxEssenceEip2930 {
    /// The network's chain ID, ensuring the transaction is valid on the intended chain.
    pub chain_id: ChainId,
    /// A numeric value representing the total number of transactions previously sent by
    /// the sender.
    pub nonce: TxNumber,
    /// The price, in Wei, that the sender is willing to pay per unit of gas for the
    /// transaction's execution.
    pub gas_price: U256,
    /// The maximum amount of gas allocated for the transaction's execution.
    pub gas_limit: U256,
    /// The 160-bit address of the intended recipient for a message call. For contract
    /// creation transactions, this is null.
    pub to: TransactionKind,
    /// The amount, in Wei, to be transferred to the recipient of the message call.
    pub value: U256,
    /// The transaction's payload, represented as a variable-length byte array.
    pub data: Bytes,
    /// A list of addresses and storage keys that the transaction will access, helping in
    /// gas optimization.
    pub access_list: AccessList,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
struct TxEssenceEip2930TxSignature {
    pub chain_id: ChainId,
    pub nonce: TxNumber,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: TransactionKind,
    pub value: U256,
    pub data: Bytes,
    pub access_list: AccessList,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

impl SignedDecodable<TxSignature> for TxEssenceEip2930 {
    fn decode_signed(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, TxSignature)> {
        let signed_essence = TxEssenceEip2930TxSignature::decode(buf)?;
        Ok((
            Self {
                chain_id: signed_essence.chain_id,
                nonce: signed_essence.nonce,
                gas_price: signed_essence.gas_price,
                gas_limit: signed_essence.gas_limit,
                to: signed_essence.to,
                value: signed_essence.value,
                data: signed_essence.data,
                access_list: signed_essence.access_list,
            },
            TxSignature {
                v: signed_essence.v,
                r: signed_essence.r,
                s: signed_essence.s,
            },
        ))
    }
}

/// Represents an Ethereum transaction with a priority fee, as detailed in [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559).
///
/// The `TxEssenceEip1559` struct encapsulates the core components of an Ethereum
/// transaction that incorporates the priority fee mechanism introduced in EIP-1559. This
/// mechanism aims to improve the predictability of gas fees and enhance the overall user
/// experience.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
pub struct TxEssenceEip1559 {
    /// The network's chain ID, ensuring the transaction is valid on the intended chain,
    /// as introduced in EIP-155.
    pub chain_id: ChainId,
    /// A numeric value representing the total number of transactions previously sent by
    /// the sender.
    pub nonce: TxNumber,
    /// The maximum priority fee per unit of gas that the sender is willing to pay to the
    /// miner.
    pub max_priority_fee_per_gas: U256,
    /// The combined maximum fee (base + priority) per unit of gas that the sender is
    /// willing to pay for the transaction's execution.
    pub max_fee_per_gas: U256,
    /// The maximum amount of gas allocated for the transaction's execution.
    pub gas_limit: U256,
    /// The 160-bit address of the intended recipient for a message call. For contract
    /// creation transactions, this is null.
    pub to: TransactionKind,
    /// The amount, in Wei, to be transferred to the recipient of the message call.
    pub value: U256,
    /// The transaction's payload, represented as a variable-length byte array.
    pub data: Bytes,
    /// A list of addresses and storage keys that the transaction will access, aiding in
    /// gas optimization.
    pub access_list: AccessList,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
struct TxEssenceEip1559TxSignature {
    pub chain_id: ChainId,
    pub nonce: TxNumber,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: TransactionKind,
    pub value: U256,
    pub data: Bytes,
    pub access_list: AccessList,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

impl SignedDecodable<TxSignature> for TxEssenceEip1559 {
    fn decode_signed(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, TxSignature)> {
        let signed_essence = TxEssenceEip1559TxSignature::decode(buf)?;
        Ok((
            Self {
                chain_id: signed_essence.chain_id,
                nonce: signed_essence.nonce,
                max_priority_fee_per_gas: signed_essence.max_priority_fee_per_gas,
                max_fee_per_gas: signed_essence.max_fee_per_gas,
                gas_limit: signed_essence.gas_limit,
                to: signed_essence.to,
                value: signed_essence.value,
                data: signed_essence.data,
                access_list: signed_essence.access_list,
            },
            TxSignature {
                v: signed_essence.v,
                r: signed_essence.r,
                s: signed_essence.s,
            },
        ))
    }
}

/// Represents the type of an Ethereum transaction: either a contract creation or a call
/// to an existing contract.
///
/// This enum is used to distinguish between the two primary types of Ethereum
/// transactions. It avoids using an [Option] for this purpose because options get RLP
/// encoded into lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Indicates that the transaction is for creating a new contract on the Ethereum
    /// network.
    #[default]
    Create,
    /// Indicates that the transaction is a call to an existing contract, identified by
    /// its 160-bit address.
    Call(Address),
}

/// Provides a conversion from [TransactionKind] to `Option<Address>`.
///
/// This implementation allows for a straightforward extraction of the Ethereum address
/// from a [TransactionKind]. If the transaction kind is a `Call`, the address is wrapped
/// in a `Some`. If it's a `Create`, the result is `None`.
impl From<TransactionKind> for Option<Address> {
    /// Converts a [TransactionKind] into an `Option<Address>`.
    ///
    /// - If the transaction kind is `Create`, this returns `None`.
    /// - If the transaction kind is `Call`, this returns the address wrapped in a `Some`.
    fn from(value: TransactionKind) -> Self {
        match value {
            TransactionKind::Create => None,
            TransactionKind::Call(addr) => Some(addr),
        }
    }
}

/// Provides RLP encoding functionality for the [TransactionKind] enum.
///
/// This implementation ensures that each variant of the [TransactionKind] enum can be
/// RLP-encoded.
/// - The `Call` variant is encoded as the address it contains.
/// - The `Create` variant is encoded as an empty string.
impl Encodable for TransactionKind {
    /// Encodes the [TransactionKind] enum variant into the provided `out` buffer.
    ///
    /// If the transaction kind is `Call`, the Ethereum address is encoded directly.
    /// If the transaction kind is `Create`, an empty string code is added to the buffer.
    #[inline]
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            TransactionKind::Call(addr) => addr.encode(out),
            TransactionKind::Create => out.put_u8(EMPTY_STRING_CODE),
        }
    }

    /// Computes the length of the RLP-encoded [TransactionKind] enum variant in bytes.
    ///
    /// If the transaction kind is `Call`, this returns the length of the Ethereum
    /// address. If the transaction kind is `Create`, this returns 1 (length of the
    /// empty string code).
    #[inline]
    fn length(&self) -> usize {
        match self {
            TransactionKind::Call(addr) => addr.length(),
            TransactionKind::Create => 1,
        }
    }
}

impl Decodable for TransactionKind {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        match buf.first().copied() {
            Some(EMPTY_STRING_CODE) => {
                buf.advance(1);
                Ok(TransactionKind::Create)
            }
            _ => Address::decode(buf).map(TransactionKind::Call),
        }
    }
}

/// Represents the core essence of an Ethereum transaction, specifically the portion that
/// gets signed.
///
/// The [EthereumTxEssence] enum provides a way to handle different types of Ethereum
/// transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthereumTxEssence {
    /// Represents a legacy Ethereum transaction, which follows the original transaction
    /// format.
    Legacy(TxEssenceLegacy),
    /// Represents an Ethereum transaction that includes an access list, as introduced in [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930).
    /// Access lists specify a list of addresses and storage keys that the transaction
    /// will access, allowing for more predictable gas costs.
    Eip2930(TxEssenceEip2930),
    /// Represents an Ethereum transaction that incorporates a priority fee mechanism, as detailed in [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559).
    /// This mechanism aims to improve the predictability of gas fees and enhances the
    /// overall user experience.
    Eip1559(TxEssenceEip1559),
}

impl Default for EthereumTxEssence {
    fn default() -> Self {
        EthereumTxEssence::Legacy(TxEssenceLegacy::default())
    }
}

impl Encodable for EthereumTxEssence {
    /// Encodes the [EthereumTxEssence] enum variant into the provided `out` buffer.
    ///
    /// Depending on the variant of the [EthereumTxEssence] enum, this method will
    /// delegate the encoding process to the appropriate transaction type's encoding
    /// method.
    #[inline]
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            EthereumTxEssence::Legacy(tx) => tx.encode(out),
            EthereumTxEssence::Eip2930(tx) => tx.encode(out),
            EthereumTxEssence::Eip1559(tx) => tx.encode(out),
        }
    }

    /// Computes the length of the RLP-encoded [EthereumTxEssence] enum variant in bytes.
    ///
    /// Depending on the variant of the [EthereumTxEssence] enum, this method will
    /// delegate the length computation to the appropriate transaction type's length
    /// method.
    #[inline]
    fn length(&self) -> usize {
        match self {
            EthereumTxEssence::Legacy(tx) => tx.length(),
            EthereumTxEssence::Eip2930(tx) => tx.length(),
            EthereumTxEssence::Eip1559(tx) => tx.length(),
        }
    }
}

impl SignedDecodable<TxSignature> for EthereumTxEssence {
    fn decode_signed(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, TxSignature)> {
        match buf.first().copied() {
            // check the EIP-2718 transaction type for non-legacy transactions
            Some(value) if value <= 0x7f => {
                buf.advance(1);
                // typed tx
                match value {
                    0x01 => TxEssenceEip2930::decode_signed(buf)
                        .map(|(e, s)| (EthereumTxEssence::Eip2930(e), s)),
                    0x02 => TxEssenceEip1559::decode_signed(buf)
                        .map(|(e, s)| (EthereumTxEssence::Eip1559(e), s)),
                    _ => Err(alloy_rlp::Error::Custom("Unsupported transaction type")),
                }
            }
            // Legacy transactions
            Some(_) => {
                TxEssenceLegacy::decode_signed(buf).map(|(e, s)| (EthereumTxEssence::Legacy(e), s))
            }
            None => Err(alloy_rlp::Error::InputTooShort),
        }
    }
}

impl EthereumTxEssence {
    /// Computes the signing hash for the transaction essence.
    ///
    /// This method calculates the Keccak hash of the data that needs to be signed
    /// for the transaction, ensuring the integrity and authenticity of the transaction.
    pub(crate) fn signing_hash(&self) -> B256 {
        keccak(self.signing_data()).into()
    }

    /// Retrieves the data that should be signed for the transaction essence.
    ///
    /// Depending on the variant of the [EthereumTxEssence] enum, this method prepares the
    /// appropriate data for signing. For EIP-2930 and EIP-1559 transactions, a specific
    /// prefix byte is added before the transaction data.
    fn signing_data(&self) -> Vec<u8> {
        match self {
            EthereumTxEssence::Legacy(tx) => {
                let mut buf = Vec::with_capacity(tx.signing_length());
                tx.signing_encode(&mut buf);
                buf
            }
            EthereumTxEssence::Eip2930(tx) => {
                let mut buf = Vec::with_capacity(tx.length() + 1);
                buf.push(0x01);
                tx.encode(&mut buf);
                buf
            }
            EthereumTxEssence::Eip1559(tx) => {
                let mut buf = Vec::with_capacity(tx.length() + 1);
                buf.push(0x02);
                tx.encode(&mut buf);
                buf
            }
        }
    }

    /// Returns the parity of the y-value of the curve point for which `signature.r` is
    /// the x-value. This is encoded in the `v` field of the signature.
    ///
    /// It returns `None` if the parity cannot be determined.
    fn is_y_odd(&self, signature: &TxSignature) -> Option<bool> {
        match self {
            EthereumTxEssence::Legacy(TxEssenceLegacy { chain_id: None, .. }) => {
                checked_bool(signature.v - 27)
            }
            EthereumTxEssence::Legacy(TxEssenceLegacy {
                chain_id: Some(chain_id),
                ..
            }) => checked_bool(signature.v - 35 - 2 * chain_id),
            _ => checked_bool(signature.v),
        }
    }
}

/// Converts a given value into a boolean based on its parity.
fn checked_bool(v: u64) -> Option<bool> {
    match v {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

impl TxEssence for EthereumTxEssence {
    /// Returns the EIP-2718 transaction type or `0x00` for Legacy transactions.
    fn tx_type(&self) -> u8 {
        match self {
            EthereumTxEssence::Legacy(_) => 0x00,
            EthereumTxEssence::Eip2930(_) => 0x01,
            EthereumTxEssence::Eip1559(_) => 0x02,
        }
    }
    /// Returns the gas limit set for the transaction.
    fn gas_limit(&self) -> U256 {
        match self {
            EthereumTxEssence::Legacy(tx) => tx.gas_limit,
            EthereumTxEssence::Eip2930(tx) => tx.gas_limit,
            EthereumTxEssence::Eip1559(tx) => tx.gas_limit,
        }
    }
    /// Returns the recipient address of the transaction, if available.
    fn to(&self) -> Option<Address> {
        match self {
            EthereumTxEssence::Legacy(tx) => tx.to.into(),
            EthereumTxEssence::Eip2930(tx) => tx.to.into(),
            EthereumTxEssence::Eip1559(tx) => tx.to.into(),
        }
    }
    /// Recovers the Ethereum address of the sender from the transaction's signature.
    fn recover_from(&self, signature: &TxSignature) -> anyhow::Result<Address> {
        let is_y_odd = self.is_y_odd(signature).context("v invalid")?;
        let signature =
            K256Signature::from_scalars(signature.r.to_be_bytes(), signature.s.to_be_bytes())
                .context("r, s invalid")?;

        let verify_key = K256VerifyingKey::recover_from_prehash(
            self.signing_hash().as_slice(),
            &signature,
            RecoveryId::new(is_y_odd, false),
        )
        .context("invalid signature")?;

        let public_key = K256PublicKey::from(&verify_key);
        let public_key = public_key.to_encoded_point(false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak(&public_key[1..]);

        Ok(Address::from_slice(&hash[12..]))
    }
    /// Returns the length of the RLP-encoding payload in bytes.
    fn payload_length(&self) -> usize {
        match self {
            EthereumTxEssence::Legacy(tx) => tx.payload_length(),
            EthereumTxEssence::Eip2930(tx) => tx._alloy_rlp_payload_length(),
            EthereumTxEssence::Eip1559(tx) => tx._alloy_rlp_payload_length(),
        }
    }
    /// Returns a reference to the transaction's call data
    fn data(&self) -> &Bytes {
        match self {
            EthereumTxEssence::Legacy(tx) => &tx.data,
            EthereumTxEssence::Eip2930(tx) => &tx.data,
            EthereumTxEssence::Eip1559(tx) => &tx.data,
        }
    }
}
