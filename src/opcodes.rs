use std::collections::HashMap;

use crate::cpu::AddressingMode;
use lazy_static::lazy_static;

pub struct OpCode {
    pub code: u8,
    pub mnemonic: &'static str,
    pub len: u8,
    pub cycles: u8,
    pub addr_mode: AddressingMode,
}

impl OpCode {
    pub fn new(
        code: u8,
        mnemonic: &'static str,
        len: u8,
        cycles: u8,
        addr_mode: AddressingMode,
    ) -> Self {
        OpCode {
            code,
            mnemonic,
            len,
            cycles,
            addr_mode,
        }
    }
}

lazy_static! {
    pub static ref CPU_OPS_CODES: Vec<OpCode> = vec![
        OpCode::new(0x00, "BRK", 1, 7, AddressingMode::NoneAddressing),
        OpCode::new(0xaa, "TAX", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0xe8, "INX", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0xa9, "LDA", 2, 2, AddressingMode::Immediate),
        OpCode::new(0xa5, "LDA", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0xb5, "LDA", 2, 4, AddressingMode::ZeroPageX),
        OpCode::new(0xad, "LDA", 3, 4, AddressingMode::Absolute),
        OpCode::new(0xbd, "LDA", 3, 4, AddressingMode::AbsoluteX),
        OpCode::new(0xb9, "LDA", 3, 4, AddressingMode::AbsoluteY),
        OpCode::new(0xa1, "LDA", 2, 6, AddressingMode::IndirectX),
        OpCode::new(0xb1, "LDA", 2, 5, AddressingMode::IndirectY),
        OpCode::new(0x85, "STA", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0x95, "STA", 2, 4, AddressingMode::ZeroPageX),
        OpCode::new(0x8d, "STA", 3, 4, AddressingMode::Absolute),
        OpCode::new(0x9d, "STA", 3, 5, AddressingMode::AbsoluteX),
        OpCode::new(0x99, "STA", 3, 5, AddressingMode::AbsoluteY),
        OpCode::new(0x81, "STA", 2, 6, AddressingMode::IndirectX),
        OpCode::new(0x91, "STA", 2, 6, AddressingMode::IndirectY),
        OpCode::new(0x69, "ADC", 2, 2, AddressingMode::Immediate),
        OpCode::new(0x65, "ADC", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0x75, "ADC", 2, 4, AddressingMode::ZeroPageX),
        OpCode::new(0x6d, "ADC", 3, 4, AddressingMode::Absolute),
        OpCode::new(0x7d, "ADC", 3, 4/* +1 if page crossed*/, AddressingMode::AbsoluteX),
        OpCode::new(0x79, "ADC", 3, 4/* +1 if page crossed*/, AddressingMode::AbsoluteY),
        OpCode::new(0x61, "ADC", 2, 6, AddressingMode::IndirectX),
        OpCode::new(0x71, "ADC", 2, 5/* +1 if page crossed*/, AddressingMode::IndirectY),
        OpCode::new(0x29, "AND", 2, 2, AddressingMode::Immediate),
        OpCode::new(0x25, "AND", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0x35, "AND", 2, 4, AddressingMode::ZeroPageX),
        OpCode::new(0x2d, "AND", 3, 4, AddressingMode::Absolute),
        OpCode::new(0x3d, "AND", 3, 4/* +1 if page crossed*/, AddressingMode::AbsoluteX),
        OpCode::new(0x39, "AND", 3, 4/* +1 if page crossed*/, AddressingMode::AbsoluteY),
        OpCode::new(0x21, "AND", 2, 6, AddressingMode::IndirectX),
        OpCode::new(0x31, "AND", 2, 5/* +1 if page crossed*/, AddressingMode::IndirectY),
        OpCode::new(0x0a, "ASL", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0x06, "ASL", 2, 5, AddressingMode::ZeroPage),
        OpCode::new(0x16, "ASL", 2, 6, AddressingMode::ZeroPageX),
        OpCode::new(0x0e, "ASL", 3, 6, AddressingMode::Absolute),
        OpCode::new(0x1e, "ASL", 3, 7, AddressingMode::AbsoluteX),
        OpCode::new(0x90, "BCC", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0xb0, "BCS", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0x24, "BIT", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0x2c, "BIT", 2, 4, AddressingMode::Absolute),
        OpCode::new(0x30, "BMI", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0xd0, "BNE", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0x10, "BPL", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0x50, "BVC", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0x70, "BVS", 2, 2/* +1 if branch succeeds +2 if new page */, AddressingMode::NoneAddressing),
        OpCode::new(0x18, "CLC", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0xd8, "CLD", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0x58, "CLI", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0xb8, "CLV", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0xc9, "CMP", 2, 2, AddressingMode::Immediate),
        OpCode::new(0xc5, "CMP", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0xd5, "CMP", 2, 4, AddressingMode::ZeroPageX),
        OpCode::new(0xcd, "CMP", 3, 4, AddressingMode::Absolute),
        OpCode::new(0xdd, "CMP", 3, 4/* +1 if page crossed */, AddressingMode::AbsoluteX),
        OpCode::new(0xd9, "CMP", 3, 4/* +1 if page crossed */, AddressingMode::AbsoluteY),
        OpCode::new(0xc1, "CMP", 2, 6, AddressingMode::IndirectX),
        OpCode::new(0xd1, "CMP", 2, 5/* +1 if page crossed */, AddressingMode::IndirectY),
        OpCode::new(0xe0, "CPX", 2, 2, AddressingMode::Immediate),
        OpCode::new(0xe4, "CPX", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0xec, "CPX", 3, 4, AddressingMode::Absolute),
        OpCode::new(0xc0, "CPY", 2, 2, AddressingMode::Immediate),
        OpCode::new(0xc4, "CPY", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0xcc, "CPY", 3, 4, AddressingMode::Absolute),
        OpCode::new(0xc6, "DEC", 2, 5, AddressingMode::ZeroPage),
        OpCode::new(0xd6, "DEC", 2, 6, AddressingMode::ZeroPageX),
        OpCode::new(0xce, "DEC", 3, 6, AddressingMode::Absolute),
        OpCode::new(0xde, "DEC", 3, 7, AddressingMode::AbsoluteX),
        OpCode::new(0xca, "DEX", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0x88, "DEY", 1, 2, AddressingMode::NoneAddressing),
        OpCode::new(0x49, "EOR", 2, 2, AddressingMode::Immediate),
        OpCode::new(0x45, "EOR", 2, 3, AddressingMode::ZeroPage),
        OpCode::new(0x55, "EOR", 2, 4, AddressingMode::ZeroPageX),
        OpCode::new(0x4d, "EOR", 3, 4, AddressingMode::Absolute),
        OpCode::new(0x5d, "EOR", 3, 4/* +1 if page crossed */, AddressingMode::AbsoluteX),
        OpCode::new(0x59, "EOR", 3, 4/* +1 if page crossed */, AddressingMode::AbsoluteY),
        OpCode::new(0x41, "EOR", 2, 6, AddressingMode::IndirectX),
        OpCode::new(0x51, "EOR", 2, 5/* +1 if page crossed */, AddressingMode::IndirectY),
    ];
    pub static ref OPCODES_MAP: HashMap<u8, &'static OpCode> = {
        let mut map = HashMap::new();
        for cpuop in &*CPU_OPS_CODES {
            map.insert(cpuop.code, cpuop);
        }
        map
    };
}
