use std::sync::Arc;

use anyhow::Result;
use sp1_prover::{
    components::DefaultProverComponents, SP1CoreProof, SP1CoreProofData, SP1ProofWithMetadata,
};
use sysinfo::System;

use crate::{common, ProveArgs};

use sp1_core::{runtime::Program, utils::SP1ProverOpts};
use sp1_sdk::{
    action, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1Prover, SP1PublicValues,
};

pub fn prove_operator_phase1(arg: ProveArgs) -> Result<SP1ProofWithMetadata<SP1CoreProofData>> {
    let (client, stdin, pk, vk) = common::init_client(arg.clone());

    // Local Prover
    let prover = client.prover;
    let action = action::Prove::new(prover.as_ref(), &pk, stdin);
    let action::Prove {
        // Local Prover
        prover,
        kind,
        pk,
        stdin,
        mut context_builder,
        core_opts,
        recursion_opts,
    } = action;

    let opts = SP1ProverOpts {
        core_opts,
        recursion_opts,
    };
    let mut context = context_builder.build();

    // prove function in local.rs
    // Operator only.
    let total_ram_gb = System::new_all().total_memory() / 1_000_000_000;
    if kind == SP1ProofKind::Plonk && total_ram_gb <= 120 {
        return Err(anyhow::anyhow!(
            "not enough memory to generate plonk proof. at least 128GB is required."
        ));
    };

    // prove core function in local.rs
    context
        .subproof_verifier
        .get_or_insert_with(|| Arc::new(prover.sp1_prover()));
    let program = Program::from(&pk.elf);

    let (proof, public_values_stream, cycles) =
    sp1_core::utils::prove_with_context::<_, <sp1_prover::components::DefaultProverComponents as sp1_prover::components::SP1ProverComponents>::CoreProver>(
        &prover.sp1_prover().core_prover,
        program,
        &stdin,
        opts.core_opts,
        context,
    )?;

    SP1Prover::<DefaultProverComponents>::check_for_high_cycles(cycles);
    let public_values = SP1PublicValues::from(&public_values_stream);
    let proof_meta = SP1CoreProof {
        proof: SP1CoreProofData(proof.shard_proofs),
        stdin: stdin.clone(),
        public_values,
        cycles,
    };

    // Operator part

    // Worker part

    {
        let proof_meta = proof_meta.clone();
        let proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Core(proof_meta.proof.0),
            stdin: proof_meta.stdin,
            public_values: proof_meta.public_values,
            sp1_version: prover.version().to_string(),
        };
        prover.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }

    Ok(proof_meta)
}
