use crate::FIBONACCI_ELF;
use fibonacci_script::FibonacciArgs;
use sp1_sdk::mmp::{
    common::ProveArgs,
    worker::{worker_commit_checkpoint, worker_compress_proofs, worker_prove_checkpoint},
};

#[no_mangle]
pub extern "C" fn worker_commit_checkpoint_c(
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
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let mut o_commitments = Vec::new();
    let mut o_records = Vec::new();

    let checkpoint = unsafe { std::slice::from_raw_parts(checkpoint_ptr, checkpoint_len) }.to_vec();
    let public_values = unsafe { std::slice::from_raw_parts(public_values, public_values_len) };
    worker_commit_checkpoint::<Vec<u8>>(
        &args_bytes,
        idx,
        &checkpoint,
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
pub extern "C" fn worker_prove_checkpoint_c(
    challenger_state_len: usize,
    challenger_state_ptr: *const u8,
    num_records: usize,
    records_lens: *const usize,
    records_ptr: *const *const u8,
    o_shard_proofs_len_ptr: *mut *mut usize,
    o_shard_proofs_ptr: *mut *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
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
    worker_prove_checkpoint::<Vec<u8>>(
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
pub extern "C" fn worker_compress_proofs_c(
    layout_len: usize,
    layout_ptr: *const u8,
    layout_type: usize,
    last_proof_public_values_len: usize,
    last_proof_public_values_ptr: *const u8,
    o_proof_len_ptr: *mut usize,
    o_proof_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let layout = unsafe { std::slice::from_raw_parts(layout_ptr, layout_len) }.to_vec();
    let last_proof_public_values = unsafe {
        std::slice::from_raw_parts(last_proof_public_values_ptr, last_proof_public_values_len)
    }
    .to_vec();

    let mut o_proof = Vec::new();
    worker_compress_proofs::<Vec<u8>>(
        &args_bytes,
        &layout,
        layout_type,
        Some(&last_proof_public_values),
        &mut o_proof,
    );

    unsafe {
        *o_proof_len_ptr = o_proof.len();
        *o_proof_ptr = Box::into_raw(o_proof.into_boxed_slice()) as *mut u8;
    }
}
