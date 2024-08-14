pub mod steps;

use crate::{
    common::{self, types::RecordType},
    operator::utils::ChallengerState,
    ProveArgs,
};
use sp1_core::{runtime::ExecutionState, stark::MachineProver};
use steps::{worker_phase1_impl, worker_phase2_impl};

pub fn worker_phase1(
    args: &Vec<u8>,
    idx: u32,
    checkpoint: &[u8],
    is_last_checkpoint: bool,
    public_values: &[u8],
    o_commitments: &mut Vec<Vec<u8>>,
    o_records: &mut Vec<Vec<u8>>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let execution_state: ExecutionState = bincode::deserialize(checkpoint).unwrap();
    let mut checkpoint_file = tempfile::tempfile().unwrap();
    execution_state.save(&mut checkpoint_file).unwrap();
    let public_values_obj = bincode::deserialize(public_values).unwrap();

    let (commitments, records) = worker_phase1_impl(
        args_obj,
        idx,
        &mut checkpoint_file,
        is_last_checkpoint,
        public_values_obj,
    )
    .unwrap();

    *o_commitments = commitments
        .iter()
        .map(|commitment| bincode::serialize(commitment).unwrap())
        .collect();
    *o_records = records
        .iter()
        .map(|record| bincode::serialize(record).unwrap())
        .collect();
}

pub fn worker_phase2(
    args: &Vec<u8>,
    challenger_state: &Vec<u8>,
    records: &[Vec<u8>],
    o_shard_proofs: &mut Vec<Vec<u8>>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let (client, _, _, _) = common::init_client(args_obj.clone());
    let challenger = ChallengerState::from_bytes(challenger_state.as_slice())
        .to_challenger(&client.prover.sp1_prover().core_prover.config().perm);
    let records = records
        .iter()
        .map(|record| bincode::deserialize(record).unwrap())
        .collect::<Vec<RecordType>>();

    let shard_proofs = worker_phase2_impl(args_obj, challenger, records).unwrap();
    *o_shard_proofs = shard_proofs
        .iter()
        .map(|shard_proof| bincode::serialize(shard_proof).unwrap())
        .collect();
}
