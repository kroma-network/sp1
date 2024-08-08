use fibonacci_script::{
    operator::{operator_phase1, prove_begin, steps::operator_phase1_impl, utils::ChallengerState},
    worker::worker_phase1,
    ProveArgs,
};

// #[repr(C)]
// pub struct ProveBeginResult {
//     pub public_values_stream_len: usize,
//     pub public_values_stream_ptr: *mut u8,
// }

#[repr(C)]
#[derive(Debug)]
pub struct BytesVec {
    len: usize,
    data: *const u8,
}

impl BytesVec {
    fn from_vec(vec: Vec<u8>) -> *mut Self {
        let v = Box::new(Self {
            len: vec.len(),
            data: vec.as_ptr(),
        });
        std::mem::forget(vec);
        Box::into_raw(v)
    }
}

#[repr(C)]
pub struct BytesVecVec {
    len: usize,
    data: *const *const BytesVec,
}

impl BytesVecVec {
    fn from_vec(vec: Vec<Vec<u8>>) -> *mut Self {
        let v = Box::new(Self {
            len: vec.len(),
            data: vec
                .iter()
                .map(|v| BytesVec::from_vec(v.clone()) as *const BytesVec)
                .collect::<Vec<_>>()
                .as_ptr(),
        });
        std::mem::forget(vec);
        Box::into_raw(v)
    }
}

#[repr(C)]
pub struct ProveBeginResult {
    public_values_stream: *const BytesVec,
    public_values_bytes: *const BytesVec,
    checkpoints_bytes: *const BytesVecVec,
    cycles: u64,
}

#[no_mangle]
pub extern "C" fn prove_begin_c() -> *const ProveBeginResult {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    let (public_values_stream, public_values_bytes, checkpoints_bytes, cycles) =
        prove_begin(&args_bytes);
    println!("RUST public_values_stream: {:?}", public_values_stream);

    Box::into_raw(Box::new(ProveBeginResult {
        public_values_stream: BytesVec::from_vec(public_values_stream),
        public_values_bytes: BytesVec::from_vec(public_values_bytes),
        checkpoints_bytes: BytesVecVec::from_vec(checkpoints_bytes),
        cycles,
    }))
}

#[no_mangle]
pub extern "C" fn worker_phase1_c(
    idx: u32,
    checkpoint: *const u8,
    checkpoint_len: usize,
    is_last_checkpoint: bool,
    public_values: *const u8,
    public_values_len: usize,
    o_commitments: *mut *mut u8,
    o_commitments_len: *mut usize,
    o_records: *mut *mut u8,
    o_records_len: *mut usize,
) {
    let args = ProveArgs { n: 20, evm: false };
    let args_bytes = args.to_bytes();

    // Convert the raw pointers back to slices
    let checkpoint_slice = unsafe { std::slice::from_raw_parts(checkpoint, checkpoint_len) };
    // println!("checkpoint_slice: {:?}", checkpoint_slice);
    let public_values_slice =
        unsafe { std::slice::from_raw_parts(public_values, public_values_len) };

    // Create mutable Vecs for the output
    let mut commitments = Vec::new();
    let mut records = Vec::new();

    // Call the Rust function
    worker_phase1(
        &args_bytes,
        idx,
        &checkpoint_slice.to_vec(),
        is_last_checkpoint,
        public_values_slice,
        &mut commitments,
        &mut records,
    );

    // Set the output pointers and lengths
    unsafe {
        *o_commitments = commitments.as_ptr() as *mut u8;
        *o_commitments_len = commitments.len();
        std::mem::forget(commitments);

        *o_records = records.as_ptr() as *mut u8;
        *o_records_len = records.len();
        std::mem::forget(records);
    }
}

#[no_mangle]
pub extern "C" fn operator_phase1_c(
    args: *const u8,
    args_len: usize,
    commitments_vec: *const *const u8,
    commitments_vec_len: usize,
    records_vec: *const *const u8,
    records_vec_len: usize,
    o_challenger_state: *mut *mut u8,
    o_challenger_state_len: *mut usize,
) {
    let args = unsafe { std::slice::from_raw_parts(args, args_len) };
    let args_obj = ProveArgs::from_slice(args);

    let commitments_vec = unsafe {
        std::slice::from_raw_parts(commitments_vec, commitments_vec_len)
            .iter()
            .map(|commitments| {
                let commitments = std::slice::from_raw_parts(*commitments, 0);
                bincode::deserialize(commitments).unwrap()
            })
            .collect()
    };

    let records_vec = unsafe {
        std::slice::from_raw_parts(records_vec, records_vec_len)
            .iter()
            .map(|records| {
                let records = std::slice::from_raw_parts(*records, 0);
                bincode::deserialize(records).unwrap()
            })
            .collect()
    };

    let challenger = operator_phase1_impl(args_obj, commitments_vec, records_vec).unwrap();
    let challenger_bytes = ChallengerState::from(&challenger).to_bytes();
    unsafe {
        *o_challenger_state = challenger_bytes.as_ptr() as *mut u8;
        *o_challenger_state_len = challenger_bytes.len();
        std::mem::forget(challenger_bytes);
    }
}
