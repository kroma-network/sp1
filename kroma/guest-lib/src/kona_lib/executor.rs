extern crate alloc;
extern crate std;

use super::raw_tx::RawTransaction;
use crate::kona_lib::mpt_utils::ordered_trie_with_encoder;
use alloc::vec::Vec;
use alloy_primitives::{TxKind, B256, U256};
use anyhow::{anyhow, Result};
use op_alloy_consensus::{Encodable2718, OpReceiptEnvelope, OpTxEnvelope};
use revm::primitives::{OptimismFields, TransactTo, TxEnv};
use superchain_primitives::RollupConfig;

/// The block executor for the L2 client program. Operates off of a [TrieDB] backed [State],
/// allowing for stateless block execution of OP Stack blocks.
#[derive(Debug)]
pub struct StatelessL2BlockExecutor {}

impl StatelessL2BlockExecutor {
    /// Computes the receipts root from the given set of receipts.
    ///
    /// ## Takes
    /// - `receipts`: The receipts to compute the root for.
    /// - `config`: The rollup config to use for the computation.
    /// - `timestamp`: The timestamp to use for the computation.
    ///
    /// ## Returns
    /// The computed receipts root.
    pub fn compute_receipts_root(
        receipts: &[OpReceiptEnvelope],
        config: &RollupConfig,
        timestamp: u64,
    ) -> B256 {
        // There is a minor bug in op-geth and op-erigon where in the Regolith hardfork,
        // the receipt root calculation does not inclide the deposit nonce in the
        // receipt encoding. In the Regolith hardfork, we must strip the deposit nonce
        // from the receipt encoding to match the receipt root calculation.
        if config.is_regolith_active(timestamp) && !config.is_canyon_active(timestamp) {
            let receipts = receipts
                .iter()
                .cloned()
                .map(|receipt| match receipt {
                    OpReceiptEnvelope::Deposit(mut deposit_receipt) => {
                        deposit_receipt.receipt.deposit_nonce = None;
                        OpReceiptEnvelope::Deposit(deposit_receipt)
                    }
                    _ => receipt,
                })
                .collect::<Vec<_>>();

            ordered_trie_with_encoder(receipts.as_ref(), |receipt, mut buf| {
                receipt.encode_2718(&mut buf)
            })
            .root()
        } else {
            ordered_trie_with_encoder(receipts, |receipt, mut buf| receipt.encode_2718(&mut buf))
                .root()
        }
    }

    /// Computes the transactions root from the given set of encoded transactions.
    ///
    /// ## Takes
    /// - `transactions`: The transactions to compute the root for.
    ///
    /// ## Returns
    /// The computed transactions root.
    pub fn compute_transactions_root(transactions: &[RawTransaction]) -> B256 {
        ordered_trie_with_encoder(transactions, |tx, buf| buf.put_slice(tx.as_ref())).root()
    }

    /// Prepares a [TxEnv] with the given [OpTxEnvelope].
    ///
    /// ## Takes
    /// - `transaction`: The transaction to prepare the environment for.
    /// - `env`: The transaction environment to prepare.
    ///
    /// ## Returns
    /// - `Ok(())` if the environment was successfully prepared.
    /// - `Err(_)` if an error occurred while preparing the environment.
    pub fn prepare_tx_env(transaction: &OpTxEnvelope, encoded_transaction: &[u8]) -> Result<TxEnv> {
        let mut env = TxEnv::default();
        match transaction {
            OpTxEnvelope::Legacy(signed_tx) => {
                let tx = signed_tx.tx();
                env.caller = signed_tx
                    .recover_signer()
                    .map_err(|e| anyhow!("Failed to recover signer: {}", e))?;
                env.gas_limit = tx.gas_limit as u64;
                env.gas_price = U256::from(tx.gas_price);
                env.gas_priority_fee = None;
                env.transact_to = match tx.to {
                    TxKind::Call(to) => TransactTo::Call(to),
                    TxKind::Create => TransactTo::create(),
                };
                env.value = tx.value;
                env.data = tx.input.clone();
                env.chain_id = tx.chain_id;
                env.nonce = Some(tx.nonce);
                env.access_list.clear();
                env.blob_hashes.clear();
                env.max_fee_per_blob_gas.take();
                env.optimism = OptimismFields {
                    source_hash: None,
                    mint: None,
                    is_system_transaction: Some(false),
                    enveloped_tx: Some(encoded_transaction.to_vec().into()),
                };
                Ok(env)
            }
            OpTxEnvelope::Eip2930(signed_tx) => {
                let tx = signed_tx.tx();
                env.caller = signed_tx
                    .recover_signer()
                    .map_err(|e| anyhow!("Failed to recover signer: {}", e))?;
                env.gas_limit = tx.gas_limit as u64;
                env.gas_price = U256::from(tx.gas_price);
                env.gas_priority_fee = None;
                env.transact_to = match tx.to {
                    TxKind::Call(to) => TransactTo::Call(to),
                    TxKind::Create => TransactTo::create(),
                };
                env.value = tx.value;
                env.data = tx.input.clone();
                env.chain_id = Some(tx.chain_id);
                env.nonce = Some(tx.nonce);
                env.access_list = tx
                    .access_list
                    .0
                    .iter()
                    .map(|l| {
                        (
                            l.address,
                            l.storage_keys
                                .iter()
                                .map(|k| U256::from_be_bytes(k.0))
                                .collect(),
                        )
                    })
                    .collect();
                env.blob_hashes.clear();
                env.max_fee_per_blob_gas.take();
                env.optimism = OptimismFields {
                    source_hash: None,
                    mint: None,
                    is_system_transaction: Some(false),
                    enveloped_tx: Some(encoded_transaction.to_vec().into()),
                };
                Ok(env)
            }
            OpTxEnvelope::Eip1559(signed_tx) => {
                let tx = signed_tx.tx();
                env.caller = signed_tx
                    .recover_signer()
                    .map_err(|e| anyhow!("Failed to recover signer: {}", e))?;
                env.gas_limit = tx.gas_limit as u64;
                env.gas_price = U256::from(tx.max_fee_per_gas);
                env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                env.transact_to = match tx.to {
                    TxKind::Call(to) => TransactTo::Call(to),
                    TxKind::Create => TransactTo::create(),
                };
                env.value = tx.value;
                env.data = tx.input.clone();
                env.chain_id = Some(tx.chain_id);
                env.nonce = Some(tx.nonce);
                env.access_list = tx
                    .access_list
                    .0
                    .iter()
                    .map(|l| {
                        (
                            l.address,
                            l.storage_keys
                                .iter()
                                .map(|k| U256::from_be_bytes(k.0))
                                .collect(),
                        )
                    })
                    .collect();
                env.blob_hashes.clear();
                env.max_fee_per_blob_gas.take();
                env.optimism = OptimismFields {
                    source_hash: None,
                    mint: None,
                    is_system_transaction: Some(false),
                    enveloped_tx: Some(encoded_transaction.to_vec().into()),
                };
                Ok(env)
            }
            OpTxEnvelope::Deposit(tx) => {
                env.caller = tx.from;
                env.access_list.clear();
                env.gas_limit = tx.gas_limit as u64;
                env.gas_price = U256::ZERO;
                env.gas_priority_fee = None;
                match tx.to {
                    TxKind::Call(to) => {
                        env.transact_to = TransactTo::Call(to);
                    }
                    TxKind::Create => {
                        env.transact_to = TransactTo::create();
                    }
                }
                env.value = tx.value;
                env.data = tx.input.clone();
                env.chain_id = None;
                env.nonce = None;
                env.optimism = OptimismFields {
                    source_hash: Some(tx.source_hash),
                    mint: tx.mint,
                    is_system_transaction: Some(tx.is_system_transaction),
                    enveloped_tx: Some(encoded_transaction.to_vec().into()),
                };
                Ok(env)
            }
            _ => anyhow::bail!("Unexpected tx type"),
        }
    }
}
