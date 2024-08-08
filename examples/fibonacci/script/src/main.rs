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
    } else {
        // Generate the proof.
        // let proof = client
        //     .prove(&pk, stdin)
        //     .plonk()
        //     .run()
        //     .expect("failed to generate proof");
        // create_plonk_fixture(&proof, &vk);
    }
}
