use std::{fs::File, sync::Arc, time::Instant};

use anyhow::Result;
use sp1_prover::{
    components::DefaultProverComponents, SP1CoreProof, SP1CoreProofData, SP1DeferredMemoryLayout,
    SP1ProofWithMetadata, SP1RecursionMemoryLayout,
};
use sysinfo::System;

use crate::{
    common::{self, bootstrap},
    ProveArgs,
};

use p3_baby_bear::BabyBear;
use sp1_core::{
    air::PublicValues,
    runtime::{Program, Runtime},
    stark::{MachineProver, RiscvAir, ShardProof},
    utils::{SP1CoreOpts, SP1CoreProverError, SP1ProverOpts},
};
use sp1_recursion_core::stark::RecursionAir;
use sp1_sdk::{
    action, InnerSC, ProverClient, SP1Context, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues,
    SP1Prover, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};

pub fn build_runtime<'a>(
    program: Program,
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context<'a>,
) -> Runtime<'a> {
    let mut runtime = Runtime::with_context(program, opts, context);
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }
    runtime
}

pub fn generate_checkpoints(
    runtime: &mut Runtime,
) -> Result<(Vec<u8>, PublicValues<u32, u32>, Vec<File>), SP1CoreProverError> {
    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let create_checkpoints_span = tracing::debug_span!("create checkpoints").entered();
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) = loop {
        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        // Save the checkpoint to a temp file.
        let mut checkpoint_file = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
        checkpoint
            .save(&mut checkpoint_file)
            .map_err(SP1CoreProverError::IoError)?;
        checkpoints.push(checkpoint_file);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                runtime.state.public_values_stream.clone(),
                runtime
                    .records
                    .last()
                    .expect("at least one record")
                    .public_values,
            );
        }
    };
    create_checkpoints_span.exit();

    Ok((public_values_stream, public_values, checkpoints))
}

//    begin                end
// operator -> worker -> operator
//          -> worker
//          -> worker
//          -> worker

pub fn operator_phase1_begin(
    arg: ProveArgs,
) -> Result<(Vec<u8>, PublicValues<u32, u32>, Vec<File>)> {
    let (client, stdin, pk, vk) = common::init_client(arg.clone());

    let (program, core_opts, context) = common::bootstrap(&client, &pk).unwrap();

    // Execute the program.
    let mut runtime = build_runtime(program, &stdin, core_opts, context);

    // // Setup the machine.
    // let (stark_pk, stark_vk) = client
    //     .prover
    //     .sp1_prover()
    //     .core_prover
    //     .setup(runtime.program.as_ref());

    let (public_values_stream, public_values, checkpoints) =
        generate_checkpoints(&mut runtime).unwrap();

    Ok((public_values_stream, public_values, checkpoints))
}

pub fn operator_phase3_begin<'a>(
    client: &'a ProverClient,
    vk: &'a SP1VerifyingKey,
    // proof: SP1CoreProof,
    shard_proofs: Vec<ShardProof<InnerSC>>,
    deferred_proofs: Vec<ShardProof<InnerSC>>,
) -> (
    Vec<SP1RecursionMemoryLayout<'a, InnerSC, RiscvAir<BabyBear>>>,
    Vec<SP1DeferredMemoryLayout<'a, InnerSC, RecursionAir<BabyBear, 3>>>,
) {
    // let shard_proofs = &proof.proof.0;

    let leaf_challenger = common::get_leaf_challenger(&client, &vk, proof);

    client.prover.sp1_prover().get_first_layer_inputs(
        &vk,
        &leaf_challenger,
        &shard_proofs,
        &deferred_proofs,
        2,
    )
}

//     let (proof, public_values_stream, cycles) =
//     sp1_core::utils::prove_with_context::<_, <sp1_prover::components::DefaultProverComponents as sp1_prover::components::SP1ProverComponents>::CoreProver>(
//         &client.prover.sp1_prover().core_prover,
//         program,
//         &stdin,
//         core_opts,
//         context,
//     )?;

//     SP1Prover::<DefaultProverComponents>::check_for_high_cycles(cycles);
//     let public_values = SP1PublicValues::from(&public_values_stream);
//     let proof_meta = SP1CoreProof {
//         proof: SP1CoreProofData(proof.shard_proofs),
//         stdin: stdin.clone(),
//         public_values,
//         cycles,
//     };

//     // Operator part

//     // Worker part

//     {
//         let proof_meta = proof_meta.clone();
//         let proof = SP1ProofWithPublicValues {
//             proof: SP1Proof::Core(proof_meta.proof.0),
//             stdin: proof_meta.stdin,
//             public_values: proof_meta.public_values,
//             sp1_version: client.prover.version().to_string(),
//         };
//         client
//             .prover
//             .verify(&proof, &vk)
//             .expect("failed to verify proof");
//         println!("Successfully verified proof!");
//     }

//     Ok(proof_meta)
// }
