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

use super::TxExecStrategy;
use crate::{
    builder::BlockBuilder,
    kona_lib::{
        eip4788::pre_block_beacon_root_contract_call,
        executor::StatelessL2BlockExecutor,
        executor_util::{
            extract_tx_gas_limit, is_system_transaction, logs_bloom, receipt_envelope_from_parts,
        },
        raw_tx::{from_native_tx, RawTransaction},
    },
};
use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use guest_primitives::{transactions::optimism::OptimismTxEssence, trie::EMPTY_ROOT};
use op_alloy_consensus::{Decodable2718, OpReceiptEnvelope, OpTxEnvelope};
use revm::{primitives::EnvWithHandlerCfg, Database, DatabaseCommit, Evm};

use core::fmt::Debug;

pub struct OpTxExecStrategy {}

impl TxExecStrategy<OptimismTxEssence> for OpTxExecStrategy {
    fn execute_transactions<D>(
        mut block_builder: BlockBuilder<D, OptimismTxEssence>,
    ) -> Result<BlockBuilder<D, OptimismTxEssence>>
    where
        D: Database + DatabaseCommit,
        <D as Database>::Error: Debug,
    {
        let rollup_config = block_builder.chain_spec.to_rollup_config();
        let initialized_cfg = block_builder.evm_cfg_env();
        let initialized_block_env = block_builder.block_env();

        let header = block_builder.header.as_mut().unwrap();
        let gas_limit = header.gas_limit.to::<u64>();
        let timestamp = header.timestamp.to::<u64>();
        let mut db = block_builder
            .db
            .take()
            .expect("Database is not initialized");

        pre_block_beacon_root_contract_call(
            &mut db,
            &rollup_config,
            initialized_block_env.number.to::<u64>(),
            &initialized_cfg,
            &initialized_block_env,
            timestamp,
            Some(block_builder.input.state_input.parent_beacon_block_root),
        )?;

        // Ensure that the create2 contract is deployed upon transition to the Canyon hard fork.
        // ensure_create2_deployer_canyon(&mut self.state, self.config, payload.timestamp)?;

        let raw_txs: Vec<RawTransaction> = block_builder
            .input
            .state_input
            .transactions
            .iter()
            .map(from_native_tx)
            .collect();

        let transactions = raw_txs
            .iter()
            .map(|raw_tx| {
                let tx = OpTxEnvelope::decode_2718(&mut raw_tx.as_ref()).map_err(|e| anyhow!(e))?;
                Ok((tx, raw_tx.as_ref()))
            })
            .collect::<Result<Vec<_>>>()?;

        let is_regolith = rollup_config.is_regolith_active(timestamp);
        let mut cumulative_gas_used = 0u64;
        let mut receipts: Vec<OpReceiptEnvelope> = Vec::with_capacity(raw_txs.len());
        for (transaction, raw_transaction) in transactions {
            let block_available_gas = (gas_limit - cumulative_gas_used) as u128;
            if extract_tx_gas_limit(&transaction) > block_available_gas
                && (is_regolith || !is_system_transaction(&transaction))
            {
                anyhow::bail!("Transaction gas limit exceeds block gas limit")
            }

            let mut evm = Evm::builder()
                .with_db(&mut db)
                .with_env_with_handler_cfg(EnvWithHandlerCfg::new_with_cfg_env(
                    initialized_cfg.clone(),
                    initialized_block_env.clone(),
                    StatelessL2BlockExecutor::prepare_tx_env(&transaction, raw_transaction)?,
                ))
                .build();

            // If the transaction is a deposit, cache the depositor account.
            //
            // This only needs to be done post-Regolith, as deposit nonces were not included in
            // Bedrock. In addition, non-deposit transactions do not have deposit
            // nonces.
            let depositor = is_regolith
                .then(|| {
                    if let OpTxEnvelope::Deposit(deposit) = &transaction {
                        let db = &mut evm.context.evm.db;
                        db.basic(deposit.from).expect("Depositor account not found")
                    } else {
                        None
                    }
                })
                .flatten();

            // Execute the transaction.
            let result = evm
                .transact_commit()
                .map_err(|_| anyhow!("Fatal EVM Error"))?;

            // Accumulate the gas used by the transaction.
            cumulative_gas_used += result.gas_used();

            // Create receipt envelope.
            let receipt = receipt_envelope_from_parts(
                result.is_success(),
                cumulative_gas_used as u128,
                result.logs(),
                transaction.tx_type(),
                depositor.as_ref().map(|depositor| depositor.nonce),
                depositor
                    .is_some()
                    .then(|| rollup_config.is_canyon_active(timestamp).then_some(1))
                    .flatten(),
            );

            receipts.push(receipt);
        }

        // Update result header with computed values
        header.transactions_root =
            StatelessL2BlockExecutor::compute_transactions_root(raw_txs.as_slice());
        header.receipts_root =
            StatelessL2BlockExecutor::compute_receipts_root(&receipts, &rollup_config, timestamp);
        header.logs_bloom = logs_bloom(receipts.iter().flat_map(|receipt| receipt.logs()));
        header.gas_used = U256::from(cumulative_gas_used);
        header.withdrawals_root = Some(EMPTY_ROOT);

        // Return block builder with updated database
        Ok(block_builder.with_db(db))
    }
}
