pub const FIBONACCI_ELF: &[u8] =
    include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

pub mod operator;
pub mod worker;

pub use operator::*;
pub use worker::*;
