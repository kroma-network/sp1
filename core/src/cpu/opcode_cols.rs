use core::borrow::{Borrow, BorrowMut};
use std::mem::size_of;

use p3_field::PrimeField;
use std::vec::IntoIter;
use valida_derive::AlignedBorrow;

use crate::runtime::{Instruction, Opcode};

#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectors<T> {
    // // Whether op_b is an immediate value.
    pub imm_b: T,
    // Whether op_c is an immediate value.
    pub imm_c: T,

    // Table selectors for opcodes.
    pub add_op: T,
    pub sub_op: T,
    pub mul_op: T,
    pub div_op: T,
    pub shift_op: T,
    pub bitwise_op: T,
    pub lt_op: T,

    // Memory operation selectors.
    pub is_load: T,
    pub is_store: T,
    pub is_word: T,
    pub is_half: T,
    pub is_byte: T,
    pub is_signed: T,

    // Specific instruction selectors.
    pub jalr: T,
    pub jal: T,
    pub auipc: T,

    // Whether this is a branch op.
    pub branch_op: T,

    // Whether this is a no-op.
    pub noop: T,
    pub reg_0_write: T,
}

impl<F: PrimeField> OpcodeSelectors<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        if instruction.is_alu_instruction() {
            match instruction.opcode {
                Opcode::ADD => {
                    self.add_op = F::one();
                }
                Opcode::SUB => {
                    self.sub_op = F::one();
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_op = F::one();
                }
                Opcode::SLL | Opcode::SRL | Opcode::SRA => {
                    self.shift_op = F::one();
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_op = F::one();
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {}
                _ => {
                    panic!(
                        "unexpected opcode {} in register instruction table processing",
                        instruction.opcode
                    )
                }
            }
        } else if instruction.is_load_instruction() {
            self.is_load = F::one();
            match instruction.opcode {
                Opcode::LB => {
                    self.is_byte = F::one();
                    self.is_signed = F::one();
                }
                Opcode::LBU => {
                    self.is_byte = F::one();
                }
                Opcode::LHU => {
                    self.is_half = F::one();
                }
                Opcode::LH => {
                    self.is_half = F::one();
                    self.is_signed = F::one();
                }
                Opcode::LW => {
                    self.is_word = F::one();
                }
                _ => unreachable!(),
            }
        } else if instruction.is_store_instruction() {
            self.is_store = F::one();
            match instruction.opcode {
                Opcode::SB => {
                    self.is_byte = F::one();
                }
                Opcode::SH => {
                    self.is_half = F::one();
                }
                Opcode::SW => {
                    self.is_word = F::one();
                }
                _ => unreachable!(),
            }
        } else if instruction.is_branch_instruction() {
            self.branch_op = F::one();
        } else if instruction.opcode == Opcode::JAL {
            self.jal = F::one();
        } else if instruction.opcode == Opcode::JALR {
            self.jalr = F::one();
        } else if instruction.opcode == Opcode::UNIMP {
            self.noop = F::one();
        }

        if instruction.op_a == 0 {
            // If op_a is 0 and we're writing to the register, then we don't do a write.
            // We are always writing to the first register UNLESS it is a branch, is_store.
            if !(self.branch_op == F::one() || self.is_store == F::one() || self.noop == F::one()) {
                self.reg_0_write = F::one();
            }
        }
    }
}

impl<T> IntoIterator for OpcodeSelectors<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        vec![
            self.imm_b.into(),
            self.imm_c.into(),
            self.add_op.into(),
            self.sub_op.into(),
            self.mul_op.into(),
            self.div_op.into(),
            self.shift_op.into(),
            self.bitwise_op.into(),
            self.lt_op.into(),
            self.is_load.into(),
            self.is_store.into(),
            self.is_word.into(),
            self.is_half.into(),
            self.is_byte.into(),
            self.is_signed.into(),
            self.jalr.into(),
            self.jal.into(),
            self.auipc.into(),
            self.branch_op.into(),
            self.noop.into(),
            self.reg_0_write.into(),
        ]
        .into_iter()
    }
}