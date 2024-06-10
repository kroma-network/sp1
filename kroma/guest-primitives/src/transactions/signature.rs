use alloy_primitives::{ChainId, U256};
use alloy_rlp_derive::{RlpDecodable, RlpEncodable, RlpMaxEncodedLen};
use serde::{Deserialize, Serialize};

/// Represents a cryptographic signature associated with a transaction.
///
/// The `TxSignature` struct encapsulates the components of an ECDSA signature: `v`, `r`,
/// and `s`. This signature can be used to recover the public key of the signer, ensuring
/// the authenticity of the transaction.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpMaxEncodedLen,
    RlpDecodable,
)]
pub struct TxSignature {
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

impl TxSignature {
    /// Returns the chain_id of the V value, if any.
    pub fn chain_id(&self) -> Option<ChainId> {
        match self.v {
            // EIP-155 encodes the chain_id in the V value
            value @ 35..=u64::MAX => Some((value - 35) / 2),
            _ => None,
        }
    }

    /// Computes the length of the RLP-encoded signature payload in bytes.
    pub fn payload_length(&self) -> usize {
        self._alloy_rlp_payload_length()
    }
}
