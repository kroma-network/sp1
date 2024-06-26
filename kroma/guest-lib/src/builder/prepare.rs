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

use core::fmt::Debug;

use anyhow::{bail, Context, Result};
use guest_primitives::{block::Header, transactions::TxEssence, U256};
use revm::{Database, DatabaseCommit};

use crate::{
    builder::BlockBuilder,
    consts::{GAS_LIMIT_BOUND_DIVISOR, MAX_EXTRA_DATA_BYTES, MIN_GAS_LIMIT},
};

pub trait HeaderPrepStrategy {
    fn prepare_header<D, E>(block_builder: BlockBuilder<D, E>) -> Result<BlockBuilder<D, E>>
    where
        D: Database + DatabaseCommit,
        <D as Database>::Error: core::fmt::Debug,
        E: TxEssence;
}

pub struct EthHeaderPrepStrategy {}

impl HeaderPrepStrategy for EthHeaderPrepStrategy {
    fn prepare_header<D, E>(mut block_builder: BlockBuilder<D, E>) -> Result<BlockBuilder<D, E>>
    where
        D: Database + DatabaseCommit,
        <D as Database>::Error: Debug,
        E: TxEssence,
    {
        // Validate gas limit
        let diff = block_builder
            .input
            .state_input
            .parent_header
            .gas_limit
            .abs_diff(block_builder.input.state_input.gas_limit);
        let limit =
            block_builder.input.state_input.parent_header.gas_limit / GAS_LIMIT_BOUND_DIVISOR;
        if diff >= limit {
            bail!(
                "Invalid gas limit: expected {} +- {}, got {}",
                block_builder.input.state_input.parent_header.gas_limit,
                limit,
                block_builder.input.state_input.gas_limit,
            );
        }
        if block_builder.input.state_input.gas_limit < MIN_GAS_LIMIT {
            bail!(
                "Invalid gas limit: expected >= {}, got {}",
                MIN_GAS_LIMIT,
                block_builder.input.state_input.gas_limit,
            );
        }
        // Validate timestamp
        let timestamp = block_builder.input.state_input.timestamp;
        if timestamp <= block_builder.input.state_input.parent_header.timestamp {
            bail!(
                "Invalid timestamp: expected > {}, got {}",
                block_builder.input.state_input.parent_header.timestamp,
                block_builder.input.state_input.timestamp,
            );
        }
        // Validate extra data
        let extra_data_bytes = block_builder.input.state_input.extra_data.len();
        if extra_data_bytes > MAX_EXTRA_DATA_BYTES {
            bail!(
                "Invalid extra data: expected <= {}, got {}",
                MAX_EXTRA_DATA_BYTES,
                extra_data_bytes,
            )
        }
        // Validate number
        let parent_number = block_builder.input.state_input.parent_header.number;
        let number = parent_number
            .checked_add(1)
            .context("Invalid number: too large")?;

        // Derive fork version
        let spec_id = block_builder
            .chain_spec
            .active_fork(number, &timestamp)
            .unwrap_or_else(|err| panic!("Invalid version: {:#}", err));
        block_builder.spec_id = Some(spec_id);
        // Derive header
        block_builder.header = Some(Header {
            // Initialize fields that we can compute from the parent
            parent_hash: block_builder.input.state_input.parent_header.hash(),
            number: block_builder
                .input
                .state_input
                .parent_header
                .number
                .checked_add(1)
                .context("Invalid block number: too large")?,
            base_fee_per_gas: U256::from(block_builder.next_block_base_fee()),
            // Initialize metadata from input
            beneficiary: block_builder.input.state_input.beneficiary,
            gas_limit: block_builder.input.state_input.gas_limit,
            timestamp,
            mix_hash: block_builder.input.state_input.mix_hash,
            extra_data: block_builder.input.state_input.extra_data.clone(),
            blob_gas_used: Some(U256::ZERO),
            excess_blob_gas: Some(U256::ZERO),
            parent_beacon_block_root: Some(
                block_builder.input.state_input.parent_beacon_block_root,
            ),

            // do not fill the remaining fields
            ..Default::default()
        });
        Ok(block_builder)
    }
}
