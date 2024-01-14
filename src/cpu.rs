use crate::opcodes;
use bitflags::bitflags;
use std::collections::HashMap;

bitflags! {
    /// # Status Register (P) http://wiki.nesdev.com/w/index.php/Status_flags
    ///
    ///  7 6 5 4 3 2 1 0
    ///  N V _ B D I Z C
    ///  | |   | | | | +--- Carry Flag
    ///  | |   | | | +----- Zero Flag
    ///  | |   | | +------- Interrupt Disable
    ///  | |   | +--------- Decimal Mode (not used on NES)
    ///  | |   +----------- Break Command
    ///  | +--------------- Overflow Flag
    ///  +----------------- Negative Flag
    ///

    pub struct CpuFlags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE      = 0b00001000;
        const BREAK             = 0b00010000;
        const BREAK2            = 0b00100000;
        const OVERFLOW          = 0b01000000;
        const NEGATIVE          = 0b10000000;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RegIdx {
    A = 0,
    // Status,
    X,
    Y,
}

#[derive(Debug)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    IndirectX,
    IndirectY,
    NoneAddressing,
}

// pub static ref CPU_OPCODES: Vec<OpCode> =

pub struct CPU {
    pub regs: [u8; 3],
    // pub reg_a: u8,
    pub status: CpuFlags,
    // pub reg_x: u8,
    pub pc: u16,
    mem: [u8; 0xffff],
}

trait Mem {
    fn mem_read(&self, addr: u16) -> u8;

    fn mem_write(&mut self, addr: u16, data: u8);

    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }
}

impl Mem for CPU {
    fn mem_read(&self, addr: u16) -> u8 {
        self.mem[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.mem[addr as usize] = data;
    }
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            regs: [0, 0, 0],
            status: CpuFlags::from_bits_truncate(0b00000000),
            // reg_a: 0,
            // reg_status: 0, // NVB?DIZC
            // reg_x: 0,
            pc: 0,
            mem: [0; 0xffff],
        }
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.mem[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xfffc, 0x8000)
    }

    pub fn reset(&mut self) {
        // Reset Interrupt: all register to zero and
        // set PC to 0xfffc
        self.regs = [0, 0, 0];

        self.pc = self.mem_read_u16(0xfffc)
    }

    pub fn run(&mut self) {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            let code = self.mem_read(self.pc);
            self.pc += 1; // the word is just 1byte so the increment is just by 1
            let pc_state = self.pc;

            let opcode = opcodes
                .get(&code)
                .expect(&format!("opcode {:x} is not recognized!", code));

            match code {
                // ADC
                0x69 | 0x65 | 0x75 | 0x6d | 0x7d | 0x79 | 0x61 | 0x71 => {
                    self.adc(&opcode.addr_mode);
                }

                // AND
                0x29 | 0x25 | 0x35 | 0x2d | 0x3d | 0x39 | 0x21 | 0x31 => {
                    self.and(&opcode.addr_mode);
                }

                // ASL -> ACUMMULATOR
                0x0a => self.asl_accumulator(),

                // ASL -> ADDRESSING
                0x06 | 0x16 | 0x0e | 0x1e => self.asl(&opcode.addr_mode),

                // BCC
                0x90 => self.branch(!self.status.contains(CpuFlags::CARRY)),

                // BCS
                0xb0 => self.branch(self.status.contains(CpuFlags::CARRY)),

                // BEQ
                0xf0 => self.branch(self.status.contains(CpuFlags::ZERO)),

                // BIT
                0x24 | 0x2C => self.bit(&opcode.addr_mode),

                // BMI
                0x30 => self.branch(self.status.contains(CpuFlags::NEGATIVE)),

                // BNE
                0xd0 => self.branch(!self.status.contains(CpuFlags::ZERO)),

                // BLP
                0x10 => self.branch(!self.status.contains(CpuFlags::NEGATIVE)),

                // BVC
                0x50 => self.branch(!self.status.contains(CpuFlags::OVERFLOW)),

                // BVC
                0x70 => self.branch(self.status.contains(CpuFlags::OVERFLOW)),

                // CLC
                0x18 => self.status.remove(CpuFlags::CARRY),

                // CLD
                0xd8 => self.status.remove(CpuFlags::DECIMAL_MODE),

                // CLI
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),

                // CLV
                0xb8 => self.status.remove(CpuFlags::OVERFLOW),

                // CMP
                0xc9 | 0xc5 | 0xd5 | 0xcd | 0xdd | 0xd9 | 0xc1 | 0xd1 => {
                    self.cmp(&opcode.addr_mode, self.regs[RegIdx::A as usize]);
                }

                // CPX
                0xe0 | 0xe4 | 0xec => {
                    self.cmp(&opcode.addr_mode, self.regs[RegIdx::X as usize]);
                }

                // CPY
                0xc0 | 0xc4 | 0xcc => {
                    self.cmp(&opcode.addr_mode, self.regs[RegIdx::Y as usize]);
                }

                // DEC
                0xc6 | 0xd6 | 0xce | 0xde => {
                    self.dec(&opcode.addr_mode);
                }

                // DEX
                0xca => self.dec_reg(RegIdx::X),

                // DEY
                0x88 => self.dec_reg(RegIdx::Y),

                // EOR
                0x49 | 0x45 | 0x55 | 0x4d | 0x5d | 0x59 | 0x41 | 0x51 => {
                    self.eor(&opcode.addr_mode);
                }

                // INC
                0xe6 | 0xf6 | 0xee | 0xfe => self.inc(&opcode.addr_mode),

                // INX
                0xe8 => self.inx(),

                // INY
                0xc8 => self.iny(),

                // LDA
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.addr_mode);
                    // self.pc += 1;
                }

                // STA
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.addr_mode);
                }

                // TAX
                0xaa => self.tax(),

                //BRK
                0x00 => {
                    self.status.insert(CpuFlags::BREAK);
                    return; //Break
                }
                _ => todo!(),
            }

            if pc_state == self.pc {
                self.pc += (opcode.len - 1) as u16;
            }
        }
    }

    fn get_operand_address(&mut self, mode: &AddressingMode) -> u16 {
        let idx_x = RegIdx::X as usize;
        let idx_y = RegIdx::Y as usize;
        match mode {
            AddressingMode::Immediate => self.pc,
            AddressingMode::ZeroPage => self.mem_read(self.pc) as u16,
            AddressingMode::Absolute => self.mem_read_u16(self.pc),
            AddressingMode::ZeroPageX => {
                let pos = self.mem_read(self.pc);
                let addr = pos.wrapping_add(self.regs[idx_x]) as u16;
                addr
            }
            AddressingMode::ZeroPageY => {
                let pos = self.mem_read(self.pc);
                let addr = pos.wrapping_add(self.regs[idx_y]) as u16;
                addr
            }
            AddressingMode::AbsoluteX => {
                let base = self.mem_read_u16(self.pc);
                let addr = base.wrapping_add(self.regs[idx_x] as u16);
                addr
            }
            AddressingMode::AbsoluteY => {
                let base = self.mem_read_u16(self.pc);
                let addr = base.wrapping_add(self.regs[idx_y] as u16);
                addr
            }
            AddressingMode::IndirectX => {
                let base = self.mem_read_u16(self.pc);
                let ptr: u8 = (base as u8).wrapping_add(self.regs[idx_x]);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);

                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::IndirectY => {
                let base = self.mem_read(self.pc);
                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.regs[idx_y] as u16);
                deref
            }
            AddressingMode::NoneAddressing => panic!("mode {:?} is not supported", mode),
        }
    }

    fn set_reg_a_and_update_flags(&mut self, value: u8) {
        self.regs[RegIdx::A as usize] = value;
        self.update_zero_and_negative_flags(value);
    }

    fn add_to_reg_a(&mut self, data: u8) {
        let sum = self.regs[RegIdx::A as usize] as u16
            + data as u16
            + (if self.status.contains(CpuFlags::CARRY) {
                1
            } else {
                0
            }) as u16;

        let carry = sum > 0xff;
        let result = sum as u8;

        if carry {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        if (data ^ result) & (result ^ self.regs[RegIdx::A as usize]) & 0x80 != 0 {
            self.status.insert(CpuFlags::OVERFLOW);
        } else {
            self.status.remove(CpuFlags::OVERFLOW);
        }

        self.set_reg_a_and_update_flags(result);
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);

        self.add_to_reg_a(data);
    }

    fn and(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);

        self.set_reg_a_and_update_flags(data & self.regs[RegIdx::A as usize]);
    }

    fn asl_accumulator(&mut self) {
        let reg_a = self.regs[RegIdx::A as usize];

        if reg_a >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        self.set_reg_a_and_update_flags(reg_a << 1);
    }

    fn asl(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let mut data = self.mem_read(addr);

        if data >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        data = data << 1;

        self.mem_write(addr, data);
        self.update_zero_and_negative_flags(data);
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            let jump: i8 = self.mem_read(self.pc) as i8;
            let jump_addr = self.pc.wrapping_add(1).wrapping_add(jump as u16);

            self.pc = jump_addr;
        }
    }

    fn bit(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let and_result = self.regs[RegIdx::A as usize] & data;

        if and_result == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        self.status.set(CpuFlags::NEGATIVE, data & 0b10000000 > 0);
        self.status.set(CpuFlags::OVERFLOW, data & 0b01000000 > 0);
    }

    fn cmp(&mut self, mode: &AddressingMode, value: u8) {
        let addr = self.get_operand_address(mode);

        let data = self.mem_read(addr);

        let cmp_result = self.regs[RegIdx::A as usize] - data;

        self.status.set(CpuFlags::CARRY, cmp_result <= value);

        self.update_zero_and_negative_flags(cmp_result);
    }

    fn dec(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        let data = self.mem_read(addr).wrapping_sub(1);

        self.mem_write(addr, data);

        self.update_zero_and_negative_flags(data);
    }

    fn dec_reg(&mut self, reg: RegIdx) {
        self.regs[reg as usize] = self.regs[reg as usize].wrapping_sub(1);
        self.update_zero_and_negative_flags(self.regs[reg as usize]);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);

        self.set_reg_a_and_update_flags(data ^ self.regs[RegIdx::A as usize]);
    }

    fn inc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        let data = self.mem_read(addr).wrapping_add(1);

        self.mem_write(addr, data);

        self.update_zero_and_negative_flags(data);
    }

    fn inx(&mut self) {
        let idx = RegIdx::X as usize;
        self.regs[idx] = self.regs[idx].wrapping_add(1);
        self.update_zero_and_negative_flags(self.regs[idx]);
    }

    fn iny(&mut self) {
        let idx = RegIdx::Y as usize;
        self.regs[idx] = self.regs[idx].wrapping_add(1);
        self.update_zero_and_negative_flags(self.regs[idx]);
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        self.regs[RegIdx::A as usize] = self.mem_read(addr);
        self.update_zero_and_negative_flags(self.regs[RegIdx::A as usize]);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.regs[RegIdx::A as usize]);
    }

    fn tax(&mut self) {
        let idx_x = RegIdx::X as usize;
        self.regs[idx_x] = self.regs[RegIdx::A as usize];
        self.update_zero_and_negative_flags(self.regs[idx_x]);
    }

    fn update_zero_and_negative_flags(&mut self, value: u8) {
        if value == 0 {
            self.status.insert(CpuFlags::ZERO);
            // self.regs[idx] = self.regs[idx] | 0b0000_0010;
        } else {
            self.status.remove(CpuFlags::ZERO);
            // self.regs[idx] = self.regs[idx] & 0b1111_1101;
        }

        if value & 0b1000_0000 != 0 {
            self.status.insert(CpuFlags::NEGATIVE);
            // self.regs[idx] = self.regs[idx] | 0b1000_0000;
        } else {
            self.status.remove(CpuFlags::NEGATIVE);
            // self.regs[idx] = self.regs[idx] & 0b0111_1111;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);
        // cpu.interpret(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.regs[RegIdx::A as usize], 0x05);
        // assert!(cpu.reg_status & 0b0000_0010 == 0b00);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b0000_0000);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        // cpu.interpret(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b10);
    }

    #[test]
    fn test_0xaa_tax_transfer_a_to_x() {
        let mut cpu = CPU::new();
        // cpu.regs[RegIdx::A as usize] = 10;
        cpu.load_and_run(vec![0xa9, 0x0a, 0xaa, 0x00]);
        // cpu.interpret(vec![0xaa, 0x00]);

        assert_eq!(cpu.regs[RegIdx::X as usize], 10)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        // cpu.regs[RegIdx::X as usize] = 0xff;
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0xe8, 0xe8, 0x00]);
        // cpu.interpret(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.regs[RegIdx::X as usize], 1);
    }

    #[test]
    fn test_0x49_eor_zero_and_negative() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![0xa9, 0xa5, 0x49, 0x04, 0x00]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0xa1);
        assert!(cpu.status.bits() == 0b1001_0000);

        let mut cpu2 = CPU::new();

        cpu2.load_and_run(vec![0xa9, 0xa5, 0x49, 0xa5, 0x00]);

        assert_eq!(cpu2.regs[RegIdx::A as usize], 0x00);
        assert!(cpu2.status.bits() == 0b0001_0010);
    }

    #[test]
    fn test_0xe6_inc_zero_and_negative() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0xff, 0x8d, 0x00, 0x02, 0xee, 0x00, 0x02, 0xad, 0x00, 0x02, 0x00,
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x00);
        assert!(cpu.status.bits() == 0b0001_0010);

        let mut cpu2 = CPU::new();

        cpu2.load_and_run(vec![
            0xa9, 0x7f, 0x8d, 0x00, 0x02, 0xee, 0x00, 0x02, 0xad, 0x00, 0x02, 0x00,
        ]);

        assert_eq!(cpu2.regs[RegIdx::A as usize], 0x80);
        assert!(cpu2.status.bits() == 0b1001_0000);
    }

    #[test]
    fn test_four_instructions_together() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);
        // cpu.interpret(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);
        assert_eq!(cpu.regs[RegIdx::X as usize], 0xc1)
    }
}
