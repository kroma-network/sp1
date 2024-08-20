use crate::FIBONACCI_ELF;
use fibonacci_script::FibonacciArgs;
use sp1_core::{stark::ShardProof, utils::BabyBearPoseidon2};
use sp1_prover::{ReduceProgramType, SP1ReduceProof};
use sp1_sdk::mmp::{
    common::ProveArgs,
    operator::{
        operator_absorb_commits, operator_construct_sp1_core_proof,
        operator_prepare_compress_input_chunks, operator_prepare_compress_inputs,
        operator_prepare_plonk_witness, operator_prove_plonk, operator_prove_shrink,
        operator_split_into_checkpoints,
    },
    scenario::{compress_prove, core_prove, plonk_prove},
};

#[no_mangle]
pub extern "C" fn operator_split_into_checkpoints_c(
    o_public_values_stream_len_ptr: *mut usize,
    o_public_values_stream_ptr: *mut *mut u8,
    o_public_values_len_ptr: *mut usize,
    o_public_values_ptr: *mut *mut u8,
    o_num_checkpoints_ptr: *mut usize,
    o_checkpoints_len_ptr: *mut *mut usize,
    o_checkpoints_ptr: *mut *mut *mut u8,
    o_cycles_ptr: *mut u64,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let mut o_public_values_stream = Vec::new();
    let mut o_public_values_bytes = Vec::new();
    let mut o_checkpoints = Vec::new();
    let mut o_cycles = 0;

    operator_split_into_checkpoints::<Vec<u8>>(
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
pub extern "C" fn operator_absorb_commits_c(
    num_checkpoints: usize,
    num_commitments_ptr: *const usize,
    commitments_lens_ptr: *const *const usize,
    commitments_vec_ptr: *const *const *const u8,
    records_len_ptr: *const *const usize,
    records_ptr: *const *const *const u8,
    o_challenger_state_len_ptr: *mut usize,
    o_challenger_state_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
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
    operator_absorb_commits::<Vec<u8>>(
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
pub extern "C" fn operator_construct_sp1_core_proof_c(
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
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
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
    operator_construct_sp1_core_proof::<Vec<u8>>(
        &args_bytes,
        &shard_proofs_vec,
        &public_values_stream,
        cycles,
        &mut o_proof,
    );

    // TODO(TomTaehoonKim): Remove this when verification c api is implemented.
    core_prove::scenario_end(&args, &o_proof).expect("verification failed");

    unsafe {
        *o_proof_len_ptr = o_proof.len();
        *o_proof_ptr = Box::into_raw(o_proof.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_prepare_compress_inputs_c(
    core_proof_len: usize,
    core_proof_ptr: *const u8,
    o_num_rec_layouts_ptr: *mut usize,
    o_rec_layouts_lens_ptr: *mut *mut usize,
    o_rec_layouts_ptr: *mut *mut *mut u8,
    o_num_def_layouts_ptr: *mut usize,
    o_def_layouts_lens_ptr: *mut *mut usize,
    o_def_layouts_ptr: *mut *mut *mut u8,
    o_last_proof_public_values_len_ptr: *mut usize,
    o_last_proof_public_values_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let core_proof = unsafe { std::slice::from_raw_parts(core_proof_ptr, core_proof_len) }.to_vec();

    let mut o_rec_layouts = Vec::new();
    let mut o_def_layouts = Vec::new();
    let mut o_last_proof_public_values = Vec::new();
    operator_prepare_compress_inputs::<Vec<u8>>(
        &args_bytes,
        &core_proof,
        &mut o_rec_layouts,
        &mut o_def_layouts,
        &mut o_last_proof_public_values,
    );

    let rec_layouts_lens = o_rec_layouts
        .iter()
        .map(|rec_layout| rec_layout.len())
        .collect::<Vec<_>>();
    let rec_layouts = o_rec_layouts
        .into_iter()
        .map(|rec_layout| Box::into_raw(rec_layout.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();

    let def_layouts_lens = o_def_layouts
        .iter()
        .map(|def_layout| def_layout.len())
        .collect::<Vec<_>>();
    let def_layouts = o_def_layouts
        .into_iter()
        .map(|def_layout| Box::into_raw(def_layout.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();

    unsafe {
        *o_num_rec_layouts_ptr = rec_layouts.len();
        *o_rec_layouts_lens_ptr = Box::into_raw(rec_layouts_lens.into_boxed_slice()) as *mut usize;
        *o_rec_layouts_ptr = Box::into_raw(rec_layouts.into_boxed_slice()) as *mut *mut u8;
        *o_num_def_layouts_ptr = def_layouts.len();
        *o_def_layouts_lens_ptr = Box::into_raw(def_layouts_lens.into_boxed_slice()) as *mut usize;
        *o_def_layouts_ptr = Box::into_raw(def_layouts.into_boxed_slice()) as *mut *mut u8;
        *o_last_proof_public_values_len_ptr = o_last_proof_public_values.len();
        *o_last_proof_public_values_ptr =
            Box::into_raw(o_last_proof_public_values.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_prepare_compress_input_chunks_c(
    num_compressed_proofs: usize,
    compressed_proofs_lens_ptr: *const usize,
    compressed_proofs_ptr: *const *const u8,
    o_num_red_layouts_ptr: *mut usize,
    o_red_layout_len_ptr: *mut *mut usize,
    o_red_layout_ptr: *mut *mut *mut u8,
) {
    let compressed_proofs_lens =
        unsafe { std::slice::from_raw_parts(compressed_proofs_lens_ptr, num_compressed_proofs) };
    let mut compressed_proofs = Vec::new();
    for i in 0..num_compressed_proofs {
        let compressed_proof = unsafe {
            std::slice::from_raw_parts(*compressed_proofs_ptr.add(i), compressed_proofs_lens[i])
        };
        compressed_proofs.push(compressed_proof.to_vec());
    }

    let mut o_red_layout = Vec::new();
    operator_prepare_compress_input_chunks(&compressed_proofs, &mut o_red_layout);

    let red_layout_lens = o_red_layout
        .iter()
        .map(|red_layout| red_layout.len())
        .collect::<Vec<_>>();
    let red_layout = o_red_layout
        .into_iter()
        .map(|red_layout| Box::into_raw(red_layout.into_boxed_slice()) as *mut u8)
        .collect::<Vec<_>>();

    unsafe {
        *o_num_red_layouts_ptr = red_layout.len();
        *o_red_layout_len_ptr = Box::into_raw(red_layout_lens.into_boxed_slice()) as *mut usize;
        *o_red_layout_ptr = Box::into_raw(red_layout.into_boxed_slice()) as *mut *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_verify_sp1_compressed_proof_c(
    core_proof_len: usize,
    core_proof_ptr: *const u8,
    compressed_proof_len: usize,
    compressed_proof_ptr: *const u8,
    o_compressed_proof_len_ptr: *mut usize,
    o_compressed_proof_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };

    let core_proof = unsafe { std::slice::from_raw_parts(core_proof_ptr, core_proof_len) }.to_vec();
    let compressed_proof =
        unsafe { std::slice::from_raw_parts(compressed_proof_ptr, compressed_proof_len) }.to_vec();

    let compressed_shard_proofs_obj: (ShardProof<BabyBearPoseidon2>, ReduceProgramType) =
        bincode::deserialize(&compressed_proof).unwrap();
    let compressed_proof = SP1ReduceProof {
        proof: compressed_shard_proofs_obj.0,
    };
    let compressed_proof = bincode::serialize(&compressed_proof).unwrap();

    compress_prove::scenario_end(&args, &core_proof, &compressed_proof)
        .expect("verification failed");

    unsafe {
        *o_compressed_proof_len_ptr = compressed_proof.len();
        *o_compressed_proof_ptr = Box::into_raw(compressed_proof.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_prove_shrink_c(
    compressed_proof_len: usize,
    compressed_proof_ptr: *const u8,
    o_shrink_proof_len_ptr: *mut usize,
    o_shrink_proof_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let compressed_proof =
        unsafe { std::slice::from_raw_parts(compressed_proof_ptr, compressed_proof_len) }.to_vec();

    let mut o_shrink_proof = Vec::new();
    operator_prove_shrink::<Vec<u8>>(&args_bytes, &compressed_proof, &mut o_shrink_proof);

    unsafe {
        *o_shrink_proof_len_ptr = o_shrink_proof.len();
        *o_shrink_proof_ptr = Box::into_raw(o_shrink_proof.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_prepare_plonk_witness_c(
    shrink_proof_len: usize,
    shrink_proof_ptr: *const u8,
    o_plonk_witness_len_ptr: *mut usize,
    o_plonk_witness_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let shrink_proof =
        unsafe { std::slice::from_raw_parts(shrink_proof_ptr, shrink_proof_len) }.to_vec();

    let mut o_plonk_witness = Vec::new();
    operator_prepare_plonk_witness::<Vec<u8>>(&args_bytes, &shrink_proof, &mut o_plonk_witness);

    unsafe {
        *o_plonk_witness_len_ptr = o_plonk_witness.len();
        *o_plonk_witness_ptr = Box::into_raw(o_plonk_witness.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_prove_plonk_c(
    shrink_proof_len: usize,
    shrink_proof_ptr: *const u8,
    o_plonk_proof_len_ptr: *mut usize,
    o_plonk_proof_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };
    let args_bytes = args.to_bytes();

    let shrink_proof =
        unsafe { std::slice::from_raw_parts(shrink_proof_ptr, shrink_proof_len) }.to_vec();

    let mut o_plonk_proof = Vec::new();
    operator_prove_plonk::<Vec<u8>>(&args_bytes, &shrink_proof, &mut o_plonk_proof);

    unsafe {
        *o_plonk_proof_len_ptr = o_plonk_proof.len();
        *o_plonk_proof_ptr = Box::into_raw(o_plonk_proof.into_boxed_slice()) as *mut u8;
    }
}

#[no_mangle]
pub extern "C" fn operator_verify_sp1_plonk_proof_c(
    core_proof_len: usize,
    core_proof_ptr: *const u8,
    plonk_proof_len: usize,
    plonk_proof_ptr: *const u8,
    o_plonk_proof_with_public_values_len_ptr: *mut usize,
    o_plonk_proof_with_public_values_ptr: *mut *mut u8,
) {
    // TODO(TomTaehoonKim): Remove this when args are passed from the caller.
    let fibonacci_args = FibonacciArgs { n: 20, evm: false };
    let args = ProveArgs {
        zkvm_input: fibonacci_args.n.to_le_bytes().to_vec(),
        elf: FIBONACCI_ELF.to_vec(),
    };

    let core_proof = unsafe { std::slice::from_raw_parts(core_proof_ptr, core_proof_len) }.to_vec();
    let plonk_proof =
        unsafe { std::slice::from_raw_parts(plonk_proof_ptr, plonk_proof_len) }.to_vec();

    let plonk_proof_with_public_values =
        plonk_prove::scenario_end(&args, &core_proof, &plonk_proof).expect("verification failed");
    let plonk_proof_with_public_values =
        bincode::serialize(&plonk_proof_with_public_values).unwrap();

    unsafe {
        *o_plonk_proof_with_public_values_len_ptr = plonk_proof_with_public_values.len();
        *o_plonk_proof_with_public_values_ptr =
            Box::into_raw(plonk_proof_with_public_values.into_boxed_slice()) as *mut u8;
    }
}
