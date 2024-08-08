use crate::{
    operator::{operator_phase1, operator_phase2, operator_phase3a},
    worker::{worker_phase1, worker_phase2},
    ProveArgs,
};
use anyhow::Result;

pub fn multi_machine_prove(args: ProveArgs) -> Result<Vec<u8>> {
    // Setup the prover client.
    let serialize_args = bincode::serialize(&args).unwrap();

    let mut public_values_stream = Vec::new();
    let mut public_values = Vec::new();
    let mut checkpoints = Vec::new();
    let mut cycles = 0;
    operator_phase1(
        &serialize_args,
        &mut public_values_stream,
        &mut public_values,
        &mut checkpoints,
        &mut cycles,
    );

    let mut commitments_vec = Vec::new();
    let mut records_vec = Vec::new();
    let num_checkpoints = checkpoints.len();
    for (idx, checkpoint) in checkpoints.iter_mut().enumerate() {
        let is_last_checkpoint = idx == num_checkpoints - 1;
        let mut commitments = Vec::new();
        let mut records = Vec::new();
        worker_phase1(
            &serialize_args,
            idx as u32,
            checkpoint,
            is_last_checkpoint,
            &public_values,
            &mut commitments,
            &mut records,
        );
        commitments_vec.push(commitments);
        records_vec.push(records);
        tracing::info!("{:?}-th phase1 worker done", idx);
    }

    let mut challenger_state = Vec::new();
    operator_phase2(
        &serialize_args,
        &commitments_vec,
        &records_vec,
        &mut challenger_state,
    );

    let mut shard_proofs_vec = Vec::new();
    for (idx, records) in records_vec.into_iter().enumerate() {
        let mut shard_proofs = Vec::new();
        worker_phase2(
            &serialize_args,
            &challenger_state,
            records.as_slice(),
            &mut shard_proofs,
        );
        shard_proofs_vec.push(shard_proofs);
        tracing::info!("{:?}-th phase2 worker done", idx);
    }

    // Core proof.
    let mut proof = Vec::new();
    operator_phase3a(
        &serialize_args,
        &shard_proofs_vec,
        &public_values_stream,
        cycles,
        &mut proof,
    );

    Ok(proof)
}
