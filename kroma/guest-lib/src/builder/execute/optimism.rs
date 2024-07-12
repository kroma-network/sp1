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

use super::{ethereum, TxExecStrategy};
use crate::{builder::BlockBuilder, consts, guest_mem_forget};
use anyhow::{anyhow, bail, Context, Result};
use core::{fmt::Debug, mem::take};
use guest_primitives::{
    alloy_rlp,
    receipt::Receipt,
    transactions::{
        ethereum::{EthereumTxEssence, TransactionKind},
        optimism::{OptimismTxEssence, TxEssenceOptimismDeposited},
        TxEssence,
    },
    trie::{MptNode, EMPTY_ROOT},
    Bloom, Bytes,
};
#[cfg(not(target_os = "zkvm"))]
use log::trace;
use revm::{
    interpreter::Host,
    primitives::{Address, ResultAndState, SpecId, TransactTo, TxEnv},
    Database, DatabaseCommit, Evm,
};
use ruint::aliases::U256;

pub struct OpTxExecStrategy {}

impl TxExecStrategy<OptimismTxEssence> for OpTxExecStrategy {
    fn execute_transactions<D>(
        mut block_builder: BlockBuilder<D, OptimismTxEssence>,
    ) -> Result<BlockBuilder<D, OptimismTxEssence>>
    where
        D: Database + DatabaseCommit,
        <D as Database>::Error: Debug,
    {
        let spec_id = block_builder.spec_id.expect("Spec ID is not initialized");
        let header = block_builder
            .header
            .as_mut()
            .expect("Header is not initialized");

        let chain_id = block_builder.chain_spec.chain_id();
        let mut evm = Evm::builder()
            .with_db(block_builder.db.take().unwrap())
            .optimism()
            .with_spec_id(spec_id)
            .modify_block_env(|blk_env| {
                // set the EVM block environment
                blk_env.number = header.number.try_into().unwrap();
                blk_env.coinbase = block_builder.input.state_input.beneficiary;
                blk_env.timestamp = header.timestamp;
                blk_env.difficulty = U256::ZERO;
                blk_env.prevrandao = Some(header.mix_hash);
                blk_env.basefee = header.base_fee_per_gas;
                blk_env.gas_limit = block_builder.input.state_input.gas_limit;
            })
            .modify_cfg_env(|cfg_env| {
                // set the EVM configuration
                cfg_env.chain_id = chain_id;
            })
            .build();

        // bloom filter over all transaction logs
        let mut logs_bloom = Bloom::default();
        // keep track of the gas used over all transactions
        let mut cumulative_gas_used = consts::ZERO;

        // process all the transactions
        let mut tx_trie = MptNode::default();
        let mut receipt_trie = MptNode::default();
        for (tx_no, tx) in take(&mut block_builder.input.state_input.transactions)
            .into_iter()
            .enumerate()
        {
            // verify the transaction signature
            let tx_from = tx
                .recover_from()
                .with_context(|| format!("Error recovering address for transaction {}", tx_no))?;

            #[cfg(not(target_os = "zkvm"))]
            {
                let tx_hash = tx.hash();
                trace!("Tx no. {} (hash: {})", tx_no, tx_hash);
                trace!("  Type: {}", tx.essence.tx_type());
                trace!("  Fr: {:?}", tx_from);
                trace!("  To: {:?}", tx.essence.to().unwrap_or_default());
            }

            // verify transaction gas
            let block_available_gas =
                block_builder.input.state_input.gas_limit - cumulative_gas_used;
            if block_available_gas < tx.essence.gas_limit() {
                bail!("Error at transaction {}: gas exceeds block limit", tx_no);
            }

            // cache account nonce if the transaction is a deposit, starting with Canyon
            let deposit_nonce = (spec_id >= SpecId::CANYON
                && matches!(tx.essence, OptimismTxEssence::OptimismDeposited(_)))
            .then(|| {
                let db = &mut evm.context.evm.db;
                let account = db.basic(tx_from).expect("Depositor account not found");
                account.unwrap_or_default().nonce
            });

            match &tx.essence {
                OptimismTxEssence::OptimismDeposited(deposit) => {
                    #[cfg(not(target_os = "zkvm"))]
                    {
                        trace!("  Source: {:?}", &deposit.source_hash);
                        trace!("  Mint: {:?}", &deposit.mint);
                        trace!("  System Tx: {:?}", deposit.is_system_tx);
                    }

                    // Initialize tx environment
                    fill_deposit_tx_env(&mut evm.env_mut().tx, deposit, tx_from);
                }
                OptimismTxEssence::Ethereum(essence) => {
                    fill_eth_tx_env(
                        &mut evm.env_mut().tx,
                        alloy_rlp::encode(&tx),
                        essence,
                        tx_from,
                    );
                }
            };

            // process the transaction
            let ResultAndState { result, state } = evm
                .transact()
                .map_err(|evm_err| anyhow!("Error at transaction {}: {:?}", tx_no, evm_err))
                // todo: change unrecoverable panic to host-side recoverable `Result`
                .expect("Block construction failure.");

            let gas_used = result.gas_used().try_into().unwrap();
            cumulative_gas_used = cumulative_gas_used.checked_add(gas_used).unwrap();

            #[cfg(not(target_os = "zkvm"))]
            trace!("  Ok: {:?}", result);

            // create the receipt from the EVM result
            let mut receipt = Receipt::new(
                tx.essence.tx_type(),
                result.is_success(),
                cumulative_gas_used,
                result.logs().into_iter().map(|log| log.into()).collect(),
            );
            if let Some(nonce) = deposit_nonce {
                receipt = receipt.with_deposit_nonce(nonce);
            }

            // update account states
            #[cfg(not(target_os = "zkvm"))]
            for (address, account) in &state {
                if account.is_touched() {
                    // log account
                    trace!(
                        "  State {:?} (is_selfdestructed={}, is_loaded_as_not_existing={}, is_created={})",
                        address,
                        account.is_selfdestructed(),
                        account.is_loaded_as_not_existing(),
                        account.is_created()
                    );
                    // log balance changes
                    trace!(
                        "     After balance: {} (Nonce: {})",
                        account.info.balance,
                        account.info.nonce
                    );

                    // log state changes
                    for (addr, slot) in &account.storage {
                        if slot.is_changed() {
                            trace!("    Storage address: {:?}", addr);
                            trace!("      Before: {:?}", slot.original_value());
                            trace!("       After: {:?}", slot.present_value());
                        }
                    }
                }
            }

            evm.context.evm.db.commit(state);

            // accumulate logs to the block bloom filter
            logs_bloom.accrue_bloom(&receipt.payload.logs_bloom);

            // Add receipt and tx to tries
            let trie_key = alloy_rlp::encode(tx_no);
            tx_trie
                .insert_rlp(&trie_key, tx)
                // todo: change unrecoverable panic to host-side recoverable `Result`
                .expect("failed to insert transaction");
            receipt_trie
                .insert_rlp(&trie_key, receipt)
                // todo: change unrecoverable panic to host-side recoverable `Result`
                .expect("failed to insert receipt");
        }

        // Update result header with computed values
        header.transactions_root = tx_trie.hash();
        header.receipts_root = receipt_trie.hash();
        header.logs_bloom = logs_bloom;
        header.gas_used = cumulative_gas_used;
        header.withdrawals_root = if spec_id < SpecId::CANYON {
            None
        } else {
            Some(EMPTY_ROOT)
        };

        // Leak memory, save cycles
        guest_mem_forget([tx_trie, receipt_trie]);
        // Return block builder with updated database
        Ok(block_builder.with_db(evm.context.evm.db))
    }
}

fn fill_deposit_tx_env(tx_env: &mut TxEnv, essence: &TxEssenceOptimismDeposited, caller: Address) {
    // initialize additional optimism tx fields
    tx_env.optimism.source_hash = Some(essence.source_hash);
    tx_env.optimism.mint = Some(essence.mint.try_into().unwrap());
    tx_env.optimism.is_system_transaction = Some(essence.is_system_tx);
    tx_env.optimism.enveloped_tx = None; // only used for non-deposit txs

    tx_env.caller = caller; // previously overridden to tx.from
    tx_env.gas_limit = essence.gas_limit.try_into().unwrap();
    tx_env.gas_price = U256::ZERO;
    tx_env.gas_priority_fee = None;
    tx_env.transact_to = if let TransactionKind::Call(to_addr) = essence.to {
        TransactTo::Call(to_addr)
    } else {
        TransactTo::create()
    };
    tx_env.value = essence.value;
    tx_env.data = essence.data.clone();
    tx_env.chain_id = None;
    tx_env.nonce = None;
    tx_env.access_list.clear();
}

fn fill_eth_tx_env(tx_env: &mut TxEnv, tx: Vec<u8>, essence: &EthereumTxEssence, caller: Address) {
    // initialize additional optimism tx fields
    tx_env.optimism.source_hash = None;
    tx_env.optimism.mint = None;
    tx_env.optimism.is_system_transaction = Some(false);
    tx_env.optimism.enveloped_tx = Some(Bytes::from(tx));

    ethereum::fill_eth_tx_env(tx_env, essence, caller);
}
