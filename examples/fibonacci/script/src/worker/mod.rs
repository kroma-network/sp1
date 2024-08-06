use std::fs::File;

use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_symmetric::Hash;
use sp1_core::air::PublicValues;
use sp1_core::runtime::ExecutionRecord;
use sp1_core::stark::MachineProver;
use sp1_core::stark::MachineRecord;
use sp1_core::utils::reset_seek;
use sp1_core::utils::trace_checkpoint;
use sp1_sdk::ExecutionReport;

use crate::common;
use crate::ProveArgs;

pub type CommitmentType = Hash<BabyBear, BabyBear, 8>;
pub type RecordType = ExecutionRecord;
pub type CommitmentPairType = (CommitmentType, RecordType);

pub fn worker_phase1(
    args: &ProveArgs,
    idx: u32,
    checkpoint: &mut File,
    is_last_checkpoint: bool,
    public_values: PublicValues<u32, u32>,
) -> Result<(u32, Vec<CommitmentPairType>)> {
    let (client, _, pk, _) = common::init_client(args.clone());

    let (program, core_opts, _) = common::bootstrap(&client, &pk).unwrap();

    let mut deferred = ExecutionRecord::new(program.clone().into());
    let mut state = public_values.reset();
    let shards_in_checkpoint = core_opts.shard_batch_size as u32;
    state.shard = idx * shards_in_checkpoint;

    // Trace the checkpoint and reconstruct the execution records.
    let (mut records, report) = trace_checkpoint(program.clone(), checkpoint, core_opts);
    // Log some of the `ExecutionReport` information.
    tracing::info!(
        "execution report (totals): total_cycles={}, total_syscall_cycles={}",
        report.total_instruction_count(),
        report.total_syscall_count()
    );
    tracing::info!("execution report (opcode counts):");
    for line in ExecutionReport::sorted_table_lines(&report.opcode_counts) {
        tracing::info!("  {line}");
    }
    tracing::info!("execution report (syscall counts):");
    for line in ExecutionReport::sorted_table_lines(&report.syscall_counts) {
        tracing::info!("  {line}");
    }
    reset_seek(checkpoint);

    // Update the public values & prover state for the shards which contain "cpu events".
    for record in records.iter_mut() {
        state.shard += 1;
        state.execution_shard = record.public_values.execution_shard;
        state.start_pc = record.public_values.start_pc;
        state.next_pc = record.public_values.next_pc;
        record.public_values = state;
    }

    // Generate the dependencies.
    client
        .prover
        .sp1_prover()
        .core_prover
        .machine()
        .generate_dependencies(&mut records, &core_opts);

    // Defer events that are too expensive to include in every shard.
    for record in records.iter_mut() {
        deferred.append(&mut record.defer());
    }

    // See if any deferred shards are ready to be committed to.
    let mut deferred = deferred.split(is_last_checkpoint, core_opts.split_opts);

    // Update the public values & prover state for the shards which do not contain "cpu events"
    // before committing to them.
    if !is_last_checkpoint {
        state.execution_shard += 1;
    }

    for record in deferred.iter_mut() {
        state.shard += 1;
        state.previous_init_addr_bits = record.public_values.previous_init_addr_bits;
        state.last_init_addr_bits = record.public_values.last_init_addr_bits;
        state.previous_finalize_addr_bits = record.public_values.previous_finalize_addr_bits;
        state.last_finalize_addr_bits = record.public_values.last_finalize_addr_bits;
        state.start_pc = state.next_pc;
        record.public_values = state;
    }
    records.append(&mut deferred);

    // Committing to the shards.
    let commitments = records
        .into_iter()
        .map(|record| {
            let commitment = client.prover.sp1_prover().core_prover.commit(&record);
            (commitment, record)
        })
        .collect::<Vec<_>>();

    Ok((idx, commitments))
}