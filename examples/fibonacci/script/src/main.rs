//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be verified
//! on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package fibonacci-script --bin prove --release
//! ```

pub mod common;
pub mod operator;
pub mod worker;

use clap::Parser;
use fibonacci_script::{
    operator::steps::operator_core_end, scenario, ProofType, ProveArgs, PublicValuesTuple,
};

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    // Parse the command line arguments.
    let args = ProveArgs::parse();
    let serialized_args = args.to_bytes();

    let raw_core_proof = scenario::core_prove::multi_machine_prove(args.clone()).unwrap();
    if args.proof_type == ProofType::CORE {
        operator_core_end(&serialized_args, &raw_core_proof);
        return;
    }
    let core_proof: SP1CoreProof = bincode::deserialize(raw_core_proof.as_slice()).unwrap();

    let (client, stdin, pk, vk) = common::init_client(args.clone());
    let (_, opts, _) = common::bootstrap(&client, &pk).unwrap();

    let deferred_proofs = core_proof
        .stdin
        .proofs
        .iter()
        .map(|p| p.0.clone())
        .collect();
    let public_values = core_proof.public_values.clone();
    let reduce_proof = client
        .prover
        .sp1_prover()
        .compress(&pk.vk, core_proof, deferred_proofs, opts)
        .unwrap();

    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Compressed(reduce_proof.proof),
        stdin,
        public_values,
        sp1_version: client.prover.version().to_string(),
    };

    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof");
}
