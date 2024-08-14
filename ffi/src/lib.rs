use core::num;
use std::char;

use fibonacci_script::{
    common::types::CommitmentType,
    operator::{
        operator_phase1, operator_phase2, prove_begin, steps::operator_phase1_impl,
        utils::ChallengerState,
    },
    worker::{worker_phase1, worker_phase2},
    ProveArgs,
};

#[no_mangle]
pub extern "C" fn prove_begin_c(
    o_public_values_stream_len_ptr: *mut usize,
    o_public_values_stream_ptr: *mut *mut u8,
    o_public_values_len_ptr: *mut usize,
    o_public_values_ptr: *mut *mut u8,
    o_num_checkpoints_ptr: *mut usize,
    o_checkpoints_len_ptr: *mut *mut usize,
    o_checkpoints_ptr: *mut *mut *mut u8,
    o_cycles_ptr: *mut u64,
) {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    let mut o_public_values_stream = Vec::new();
    let mut o_public_values_bytes = Vec::new();
    let mut o_checkpoints = Vec::new();
    let mut o_cycles = 0;

    prove_begin(
        &args_bytes,
        &mut o_public_values_stream,
        &mut o_public_values_bytes,
        &mut o_checkpoints,
        &mut o_cycles,
    );

    let checkpoints_len = o_checkpoints
        .iter()
        .map(|checkpoint| checkpoint.len())
        .collect::<Vec<_>>();
    let checkpoints = o_checkpoints
        .into_iter()
        .map(|checkpoint| Box::into_raw(checkpoint.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();

    unsafe {
        *o_public_values_stream_len_ptr = o_public_values_stream.len();
        *o_public_values_stream_ptr =
            Box::into_raw(o_public_values_stream.into_boxed_slice()) as *mut u8;
        *o_public_values_len_ptr = o_public_values_bytes.len();
        *o_public_values_ptr = Box::into_raw(o_public_values_bytes.into_boxed_slice()) as *mut u8;
        *o_num_checkpoints_ptr = checkpoints.len();
        *o_checkpoints_len_ptr = Box::into_raw(checkpoints_len.into_boxed_slice()) as *mut usize;
        *o_checkpoints_ptr = Box::into_raw(checkpoints.into_boxed_slice()) as *mut *mut u8;
        *o_cycles_ptr = o_cycles;
    }
}

#[no_mangle]
pub extern "C" fn worker_phase1_c(
    idx: u32,
    checkpoint_len: usize,
    checkpoint_ptr: *const u8,
    is_last_checkpoint: bool,
    public_values_len: usize,
    public_values: *const u8,
    o_num_commitments_ptr: *mut usize,
    o_commitments_len_ptr: *mut *mut usize,
    o_commitments_ptr: *mut *mut *mut u8,
    o_records_len_ptr: *mut *mut usize,
    o_records_ptr: *mut *mut *mut u8,
) {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    let mut o_commitments = Vec::new();
    let mut o_records = Vec::new();

    let checkpoint = unsafe { std::slice::from_raw_parts(checkpoint_ptr, checkpoint_len) };
    let public_values = unsafe { std::slice::from_raw_parts(public_values, public_values_len) };
    worker_phase1(
        &args_bytes,
        idx,
        checkpoint,
        is_last_checkpoint,
        public_values,
        &mut o_commitments,
        &mut o_records,
    );

    let commitments_len = o_commitments
        .iter()
        .map(|commitment| commitment.len())
        .collect::<Vec<_>>();
    let commitments = o_commitments
        .into_iter()
        .map(|commitment| Box::into_raw(commitment.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();
    let records_len = o_records
        .iter()
        .map(|record| record.len())
        .collect::<Vec<_>>();
    let records = o_records
        .into_iter()
        .map(|record| Box::into_raw(record.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();

    unsafe {
        *o_num_commitments_ptr = commitments.len();
        *o_commitments_len_ptr = Box::into_raw(commitments_len.into_boxed_slice()) as *mut usize;
        *o_commitments_ptr = Box::into_raw(commitments.into_boxed_slice()) as *mut *mut u8;
        *o_records_len_ptr = Box::into_raw(records_len.into_boxed_slice()) as *mut usize;
        *o_records_ptr = Box::into_raw(records.into_boxed_slice()) as *mut *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_phase1_c(
    num_checkpoints: usize,
    num_commitments_ptr: *const usize,
    commitments_lens_ptr: *const *const usize,
    commitments_vec_ptr: *const *const *const u8,
    records_len_ptr: *const *const usize,
    records_ptr: *const *const *const u8,
    o_challenger_state_len_ptr: *mut usize,
    o_challenger_state_ptr: *mut *mut u8,
) {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    let mut commitments_lens = Vec::new();
    for i in 0..num_checkpoints {
        let num_commitments = unsafe { *num_commitments_ptr.add(i) };
        let commitments_len =
            unsafe { std::slice::from_raw_parts(*commitments_lens_ptr.add(i), num_commitments) };
        commitments_lens.push(commitments_len.to_vec());
    }

    let mut commitments_vec = Vec::new();
    for i in 0..num_checkpoints {
        let num_commitments = unsafe { *num_commitments_ptr.add(i) };
        let commitments_ptr =
            unsafe { std::slice::from_raw_parts(*commitments_vec_ptr.add(i), num_commitments) };
        let mut commitments = Vec::new();
        for j in 0..num_commitments {
            let commitment =
                unsafe { std::slice::from_raw_parts(commitments_ptr[j], commitments_lens[i][j]) };
            commitments.push(commitment.to_vec());
        }
        commitments_vec.push(commitments);
    }

    let mut records_lens = Vec::new();
    for i in 0..num_checkpoints {
        let num_records = unsafe { *num_commitments_ptr.add(i) };
        let records_len =
            unsafe { std::slice::from_raw_parts(*records_len_ptr.add(i), num_records) };
        records_lens.push(records_len.to_vec());
    }

    let mut records_vec = Vec::new();
    for i in 0..num_checkpoints {
        let num_records = unsafe { *num_commitments_ptr.add(i) };
        let records_ptr = unsafe { std::slice::from_raw_parts(*records_ptr.add(i), num_records) };
        let mut records = Vec::new();
        for j in 0..num_records {
            let record = unsafe { std::slice::from_raw_parts(records_ptr[j], records_lens[i][j]) };
            records.push(record.to_vec());
        }
        records_vec.push(records);
    }

    let mut o_challenger_state = Vec::new();
    operator_phase1(
        &args_bytes,
        &commitments_vec,
        &records_vec,
        &mut o_challenger_state,
    );

    unsafe {
        *o_challenger_state_len_ptr = o_challenger_state.len();
        *o_challenger_state_ptr = Box::into_raw(o_challenger_state.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn worker_phase2_c(
    challenger_state_len: usize,
    challenger_state_ptr: *const u8,
    num_records: usize,
    records_lens: *const usize,
    records_ptr: *const *const u8,
    o_shard_proofs_len_ptr: *mut *mut usize,
    o_shard_proofs_ptr: *mut *mut *mut u8,
) {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    let challenger_state =
        unsafe { std::slice::from_raw_parts(challenger_state_ptr, challenger_state_len) }.to_vec();

    let mut records = Vec::new();
    for i in 0..num_records {
        records.push(
            unsafe { std::slice::from_raw_parts(*records_ptr.add(i), *records_lens.add(i)) }
                .to_vec(),
        );
    }

    let mut o_shard_proofs = Vec::new();
    worker_phase2(
        &args_bytes,
        &challenger_state,
        &records,
        &mut o_shard_proofs,
    );

    let shard_proofs_len = o_shard_proofs
        .iter()
        .map(|shard_proof| shard_proof.len())
        .collect::<Vec<_>>();
    let shard_proofs = o_shard_proofs
        .into_iter()
        .map(|shard_proof| Box::into_raw(shard_proof.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();

    unsafe {
        *o_shard_proofs_len_ptr = Box::into_raw(shard_proofs_len.into_boxed_slice()) as *mut usize;
        *o_shard_proofs_ptr = Box::into_raw(shard_proofs.into_boxed_slice()) as *mut *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_phase2_c(
    num_checkpoints: usize,
    num_shard_proofs_ptr: *const usize,
    shard_proofs_lens_ptr: *const *const usize,
    shard_proofs_ptr: *const *const *const u8,
    public_values_stream_len: usize,
    public_values_stream_ptr: *const u8,
    cycles: u64,
    o_proof_len_ptr: *mut usize,
    o_proof_ptr: *mut *mut u8,
) {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    let mut shard_proofs_vec = Vec::new();
    for i in 0..num_checkpoints {
        let num_shard_proofs = unsafe { *num_shard_proofs_ptr.add(i) };
        let shard_proofs_len =
            unsafe { std::slice::from_raw_parts(*shard_proofs_lens_ptr.add(i), num_shard_proofs) };
        let shard_proofs_ptr =
            unsafe { std::slice::from_raw_parts(*shard_proofs_ptr.add(i), num_shard_proofs) };
        let mut shard_proofs = Vec::new();
        for j in 0..num_shard_proofs {
            let shard_proof =
                unsafe { std::slice::from_raw_parts(shard_proofs_ptr[j], shard_proofs_len[j]) };
            shard_proofs.push(shard_proof.to_vec());
        }
        shard_proofs_vec.push(shard_proofs);
    }

    let public_values_stream =
        unsafe { std::slice::from_raw_parts(public_values_stream_ptr, public_values_stream_len) }
            .to_vec();

    let mut o_proof = Vec::new();
    operator_phase2(
        &args_bytes,
        &shard_proofs_vec,
        &public_values_stream,
        cycles,
        &mut o_proof,
    );

    unsafe {
        *o_proof_len_ptr = o_proof.len();
        *o_proof_ptr = Box::into_raw(o_proof.into_boxed_slice()) as *mut u8;
    }
}
