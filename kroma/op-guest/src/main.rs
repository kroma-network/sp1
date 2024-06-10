//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use guest_lib::{
    builder::{BlockBuilderStrategy, OptimismStrategy},
    consts::OP_MAINNET_CHAIN_SPEC,
    input::BlockBuildInput,
};
use guest_primitives::transactions::optimism::OptimismTxEssence;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let op_block_input = sp1_zkvm::io::read::<BlockBuildInput<OptimismTxEssence>>();

    // Build the resulting block.
    let output = OptimismStrategy::build_from(&OP_MAINNET_CHAIN_SPEC, op_block_input.clone())
        .expect("Failed to build the resulting block")
        .with_state_hashed();

    // Commit to the public values of the program.
    sp1_zkvm::io::commit(&op_block_input);
    sp1_zkvm::io::commit(&output);
}
