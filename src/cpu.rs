use crate::bus::Bus;
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
    #[derive(Clone, Copy)]
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

const STACK_BEGIN: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;

#[derive(Debug, Clone, Copy)]
pub enum RegIdx {
    A = 0,
    // Status,
    X,
    Y,
    SP,
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

pub struct CPU {
    pub regs: [u8; 4],
    pub status: CpuFlags,
    pub pc: u16,
    //mem: [u8; 0xffff],
    pub bus: Bus,
}

pub trait Mem {
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
        self.bus.mem_read(addr)
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.bus.mem_write(addr, data);
    }

    fn mem_read_u16(&self, pos: u16) -> u16 {
        self.bus.mem_read_u16(pos)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        self.bus.mem_write_u16(pos, data);
    }
}

impl CPU {
    pub fn new(bus: Bus) -> Self {
        CPU {
            regs: [0, 0, 0, STACK_RESET],
            status: CpuFlags::from_bits_truncate(0b100100),
            pc: 0,
            bus,
        }
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.pc = 0x0600;
        self.run();
    }

    pub fn load(&mut self, program: Vec<u8>) {
        for i in 0..(program.len() as u16) {
            self.mem_write(0x0600 + i, program[i as usize]);
        }
        //self.mem_write_u16(0xfffc, 0x8600);
    }

    // pub fn load_alternative(&mut self, program: Vec<u8>) {
    //     self.mem[0x0600..(0x0600 + program.len())].copy_from_slice(&program[..]);
    //     self.mem_write_u16(0xfffc, 0x0600);
    // }

    pub fn reset(&mut self) {
        // Reset Interrupt: all register to zero and
        // set PC to 0xfffc
        self.regs = [0, 0, 0, STACK_RESET];
        self.status = CpuFlags::from_bits_truncate(0b100100);
        self.pc = self.mem_read_u16(0xfffc);
    }

    pub fn run_with_callback<F>(&mut self, mut callback: F)
    where
        F: FnMut(&mut CPU),
    {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            callback(self);
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

                // BVS
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

                // JMP -> ABSOLUTE
                0x4c => self.pc = self.mem_read_u16(self.pc),

                // JMP -> INDIRECT
                0x6c => {
                    let mem_addr = self.mem_read_u16(self.pc);

                    let indirect_value = if mem_addr & 0x00ff == 0x00ff {
                        let lo = self.mem_read(mem_addr);
                        let hi = self.mem_read(mem_addr & 0xFF00);
                        (hi as u16) << 8 | (lo as u16)
                    } else {
                        self.mem_read_u16(mem_addr)
                    };

                    self.pc = indirect_value
                }

                // JSR
                0x20 => {
                    self.stack_push_u16(self.pc + 2 - 1);
                    let targed_addr = self.mem_read_u16(self.pc);
                    self.pc = targed_addr;
                }

                // LDA
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.addr_mode);
                }

                // LDX
                0xa2 | 0xa6 | 0xb6 | 0xae | 0xbe => {
                    self.load_reg(&opcode.addr_mode, RegIdx::X);
                }

                // LDY
                0xa0 | 0xa4 | 0xb4 | 0xac | 0xbc => {
                    self.load_reg(&opcode.addr_mode, RegIdx::Y);
                }

                // LSR -> ACCUMULATOR
                0x4a => self.lsr_accumulator(),

                // LSR
                0x46 | 0x56 | 0x4e | 0x5e => self.lsr(&opcode.addr_mode),

                // NOP
                0xea => {}

                // ORA
                0x09 | 0x05 | 0x15 | 0x0d | 0x1d | 0x19 | 0x01 | 0x11 => {
                    self.ora(&opcode.addr_mode);
                }

                // PHA
                0x48 => self.stack_push(self.regs[RegIdx::A as usize]),

                // PHP
                0x08 => {
                    let mut flags = self.status.clone();
                    flags.insert(CpuFlags::BREAK);
                    flags.insert(CpuFlags::BREAK2);
                    self.stack_push(flags.bits());
                }

                // PLA
                0x68 => self.pla(),

                // PLP
                0x28 => self.plp(),

                // ROL (ACCUMULATOR)
                0x2a => self.rol_accumulator(),

                // ROL
                0x26 | 0x36 | 0x2e | 0x3e => self.rol(&opcode.addr_mode),

                // ROR (ACCUMULATOR)
                0x6a => self.ror_accumulator(),

                // ROR
                0x66 | 0x76 | 0x6e | 0x7e => self.ror(&opcode.addr_mode),

                // RTI
                0x40 => {
                    self.status = CpuFlags::from_bits_truncate(self.stack_pop());
                    self.status.remove(CpuFlags::BREAK);
                    self.status.insert(CpuFlags::BREAK2);
                    self.pc = self.stack_pop_u16();
                }

                // RTS
                0x60 => self.pc = self.stack_pop_u16() + 1,

                // SBC
                0xe9 | 0xe5 | 0xf5 | 0xed | 0xfd | 0xf9 | 0xe1 | 0xf1 => {
                    self.sbc(&opcode.addr_mode);
                }

                // SEC
                0x38 => self.status.insert(CpuFlags::CARRY),

                // SED
                0xf8 => self.status.insert(CpuFlags::DECIMAL_MODE),

                // SEI
                0x78 => self.status.insert(CpuFlags::INTERRUPT_DISABLE),

                // STA
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.addr_mode);
                }
                // STX
                0x86 | 0x96 | 0x8e => self.stx(&opcode.addr_mode),

                // STY
                0x84 | 0x94 | 0x8c => self.sty(&opcode.addr_mode),

                // TAX
                0xaa => self.tax(),

                // TAY
                0xa8 => {
                    self.regs[RegIdx::Y as usize] = self.regs[RegIdx::A as usize];
                    self.update_zero_and_negative_flags(self.regs[RegIdx::Y as usize]);
                }

                /* TSX */
                0xba => {
                    self.regs[RegIdx::X as usize] = self.regs[RegIdx::SP as usize];
                    self.update_zero_and_negative_flags(self.regs[RegIdx::X as usize]);
                }

                /* TXA */
                0x8a => {
                    self.regs[RegIdx::A as usize] = self.regs[RegIdx::X as usize];
                    self.update_zero_and_negative_flags(self.regs[RegIdx::A as usize]);
                }

                /* TXS */
                0x9a => {
                    self.regs[RegIdx::SP as usize] = self.regs[RegIdx::X as usize];
                }

                /* TYA */
                0x98 => {
                    self.regs[RegIdx::A as usize] = self.regs[RegIdx::Y as usize];
                    self.update_zero_and_negative_flags(self.regs[RegIdx::A as usize]);
                }

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

    pub fn run(&mut self) {
        self.run_with_callback(|_| {});
    }

    pub fn get_absolute_address(&self, mode: &AddressingMode, addr: u16) -> u16 {
        match mode {
            AddressingMode::ZeroPage => self.mem_read(addr) as u16,
            AddressingMode::Absolute => self.mem_read_u16(addr),
            AddressingMode::ZeroPageX => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.regs[RegIdx::X as usize]) as u16;
                addr
            }
            AddressingMode::ZeroPageY => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.regs[RegIdx::Y as usize]) as u16;
                addr
            }
            AddressingMode::AbsoluteX => {
                let pos = self.mem_read_u16(addr);
                let addr = pos.wrapping_add(self.regs[RegIdx::X as usize] as u16);
                addr
            }
            AddressingMode::AbsoluteY => {
                let pos = self.mem_read_u16(addr);
                let addr = pos.wrapping_add(self.regs[RegIdx::Y as usize] as u16);
                addr
            }
            AddressingMode::IndirectX => {
                let base = self.mem_read(addr);

                let ptr: u8 = (base as u8).wrapping_add(self.regs[RegIdx::X as usize]);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::IndirectY => {
                let base = self.mem_read(addr);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.regs[RegIdx::Y as usize] as u16);
                deref
            }

            _ => {
                panic!("mode {:?} is not supported", mode);
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
                let base = self.mem_read(self.pc);
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

    fn stack_pop(&mut self) -> u8 {
        self.regs[RegIdx::SP as usize] = self.regs[RegIdx::SP as usize].wrapping_add(1);
        self.mem_read(STACK_BEGIN + self.regs[RegIdx::SP as usize] as u16)
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write(STACK_BEGIN + self.regs[RegIdx::SP as usize] as u16, data);
        self.regs[RegIdx::SP as usize] = self.regs[RegIdx::SP as usize].wrapping_sub(1)
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;

        hi << 8 | lo
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;

        self.stack_push(hi);
        self.stack_push(lo);
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

        //let cmp_result = self.regs[RegIdx::A as usize].wrapping_sub(data);

        self.status.set(CpuFlags::CARRY, data <= value);

        self.update_zero_and_negative_flags(value.wrapping_sub(data));
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
        let addr = self.get_operand_address(&mode);

        let val = self.mem_read(addr);
        self.set_reg_a_and_update_flags(val);
    }

    fn load_reg(&mut self, mode: &AddressingMode, reg: RegIdx) {
        let addr = self.get_operand_address(&mode);

        let data = self.mem_read(addr);

        self.regs[reg as usize] = data;
        self.update_zero_and_negative_flags(data);
    }

    fn lsr_accumulator(&mut self) {
        let idx = RegIdx::A as usize;

        self.status
            .set(CpuFlags::CARRY, (self.regs[idx] & 0b1) == 1);

        self.set_reg_a_and_update_flags(self.regs[idx] >> 1);
    }

    fn lsr(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        let mut data = self.mem_read(addr);

        self.status.set(CpuFlags::CARRY, (data & 0b1) == 1);

        data = data >> 1;
        self.mem_write(addr, data);
        self.update_zero_and_negative_flags(data);
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        let data = self.mem_read(addr);

        self.set_reg_a_and_update_flags(data | self.regs[RegIdx::A as usize]);
    }

    fn pla(&mut self) {
        let val = self.stack_pop();
        self.set_reg_a_and_update_flags(val);
    }

    fn plp(&mut self) {
        let val = self.stack_pop();
        self.status = CpuFlags::from_bits_truncate(val);
        self.status.remove(CpuFlags::BREAK);
        self.status.insert(CpuFlags::BREAK2);
    }

    fn rol_accumulator(&mut self) {
        let mut reg_a = self.regs[RegIdx::A as usize];

        let old_c_flag = self.status.contains(CpuFlags::CARRY);

        if reg_a >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        reg_a = reg_a << 1;

        if old_c_flag {
            reg_a = reg_a | 1;
        }

        self.set_reg_a_and_update_flags(reg_a);
    }

    fn rol(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        let mut data = self.mem_read(addr);

        let old_c_flag = self.status.contains(CpuFlags::CARRY);

        if data >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        data = data << 1;

        if old_c_flag {
            data = data | 1;
        }

        self.mem_write(addr, data);
        self.update_zero_and_negative_flags(data);
    }

    fn ror_accumulator(&mut self) {
        let mut reg_a = self.regs[RegIdx::A as usize];
        let old_c_flag = self.status.contains(CpuFlags::CARRY);

        if reg_a & 1 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        reg_a = reg_a >> 1;
        if old_c_flag {
            reg_a = reg_a | 0b1000_0000;
        }
        self.set_reg_a_and_update_flags(reg_a);
    }

    fn ror(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);

        let mut data = self.mem_read(addr);

        let old_c_flag = self.status.contains(CpuFlags::CARRY);

        if data & 1 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }
        data = data >> 1;

        if old_c_flag {
            data = data | 0b1000_0000;
        }

        self.mem_write(addr, data);
        self.update_zero_and_negative_flags(data);
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);

        self.add_to_reg_a(((data as i8).wrapping_neg().wrapping_sub(1)) as u8);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.regs[RegIdx::A as usize]);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.regs[RegIdx::X as usize]);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.regs[RegIdx::Y as usize]);
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
    use crate::cartridge::Rom;

    use super::*;

    #[test]
    fn test_0x49_eor_zero_and_negative() {
        let rom = Rom::new(&vec![0xa9, 0xa5, 0x49, 0x04, 0x00]);
        let bus = Bus::new(rom.unwrap());
        let mut cpu = CPU::new(bus);
        cpu.reset();
        cpu.run();

        assert_eq!(cpu.regs[RegIdx::A as usize], 0xa1);
        assert!(cpu.status.bits() == 0b1011_0100);

        let rom2 = Rom::new(&vec![0xa9, 0xa5, 0x49, 0xa5, 0x00]);
        let bus2 = Bus::new(rom2.unwrap());
        let mut cpu2 = CPU::new(bus2);
        cpu.reset();
        cpu.run();

        assert_eq!(cpu2.regs[RegIdx::A as usize], 0x00);
        assert_eq!(cpu2.status.bits(), 0b0011_0110);
    }

    #[test]
    fn test_0xe6_inc_zero_and_negative() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0xff, 0x8d, 0x00, 0x02, 0xee, 0x00, 0x02, 0xad, 0x00, 0x02, 0x00,
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x00);
        assert_eq!(cpu.status.bits(), 0b0011_0110);

        let mut cpu2 = CPU::new();

        cpu2.load_and_run(vec![
            0xa9, 0x7f, 0x8d, 0x00, 0x02, 0xee, 0x00, 0x02, 0xad, 0x00, 0x02, 0x00,
        ]);

        assert_eq!(cpu2.regs[RegIdx::A as usize], 0x80);
        assert_eq!(cpu2.status.bits(), 0b1011_0100);
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
    fn test_jmp() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x03, // LDA #$0x03
            0x4c, 0x08, 0x80, // JMP $8008
            0xaa, // TAX
            0xe8, // INX
            0xe8, // INX
            0xaa, // TAX
            0xca, // DEX
            0x8d, 0x00, 0x02, 0x00,
        ]);

        assert_eq!(cpu.regs[RegIdx::X as usize], 2);
        assert_eq!(cpu.regs[RegIdx::A as usize], 3);
        assert_eq!(cpu.status.bits(), 0b0011_0100);
    }

    #[test]
    fn test_jsr_without_rts() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![0x20, 0x06, 0x80, 0xa9, 0x10, 0xaa, 0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.regs[RegIdx::X as usize], 2);
        assert_eq!(cpu.status.bits(), 0b0011_0100);
    }

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
    fn test_0xa2_ldx_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa2, 0x05, 0x00]);

        assert_eq!(cpu.regs[RegIdx::X as usize], 0x05);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b0000_0000);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xa0_ldy_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa0, 0x05, 0x00]);

        assert_eq!(cpu.regs[RegIdx::Y as usize], 0x05);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b0000_0000);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0x4a_lsr_accumulator() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x69, // LDA #0x69
            0x4a, // LSR
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x69 >> 1);
        assert!(cpu.status.bits() & 0b0000_0001 == 1);
        assert!(cpu.status.bits() & 0b0000_0010 == 0);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xea_nop() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0xa2, 0x02, // LDX #$02
            0xa0, 0x00, // LDY #$03
            0xea, // NOP
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x01);
        assert_eq!(cpu.regs[RegIdx::X as usize], 0x02);
        assert_eq!(cpu.regs[RegIdx::Y as usize], 0x00);
        assert_eq!(cpu.status.bits(), 0b0011_0110);
    }

    #[test]
    fn test_ora_operation() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x53, // LDA #$53
            0x09, 0x0C, // ORA #$0C
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x5F);
    }

    #[test]
    fn test_0x09_ora_immediate_zero_flag() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00
            0x09, 0x00, // ORA #$00
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x00);
        assert!(cpu.status.bits() == 0b0011_0110);
    }

    #[test]
    fn test_ora_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00
            0x09, 0x80, // ORA #$80
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x80);
        assert_eq!(cpu.status.bits(), 0b1011_0100);
    }

    #[test]
    fn test_0x48_pha_operation() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![0xa9, 0x7f, 0x48, 0x00]);

        assert_eq!(cpu.regs[RegIdx::SP as usize], 0xfc);
        assert_eq!(cpu.mem_read(0x01fd), 0x7f);
    }

    #[test]
    fn test_0x08_php_operation() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![0xa9, 0x00, 0x08, 0x00]);

        assert_eq!(cpu.regs[RegIdx::SP as usize], 0xfc);
        assert_eq!(cpu.mem_read(0x01fd), 0b0011_0110);
    }

    #[test]
    fn test_0x68_pla() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$0x80
            0x48, // PHA
            0xa9, 0x00, // LDA #$0x00
            0x68, // PLA
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x80);

        assert!(cpu.status.contains(CpuFlags::NEGATIVE));
        assert!(!cpu.status.contains(CpuFlags::ZERO));
    }

    #[test]
    fn test_0x2a_rol_accumulator() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0x18, // CLC
            0xa9, 0x80, // LDA #$80
            0x2a, // ROL A
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x00);
        assert!(cpu.status.contains(CpuFlags::CARRY));
        assert!(cpu.status.contains(CpuFlags::ZERO));
        assert!(!cpu.status.contains(CpuFlags::NEGATIVE));
    }

    #[test]
    fn test_0x6a_ror_accumulator() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x01, // LDA #$01
            0x6a, // ROR A
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x80);
        assert!(cpu.status.contains(CpuFlags::CARRY));
        assert!(!cpu.status.contains(CpuFlags::ZERO));
        assert!(cpu.status.contains(CpuFlags::NEGATIVE));
    }

    #[test]
    fn test_0x60_rts() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00
            0x20, 0x06, 0x80, // JSR $8006
            0x00, // BRK
            // Subroutine:
            0xa9, 0x42, // LDA #$42
            0x60, // RTS
        ]);

        assert!(!cpu.status.contains(CpuFlags::NEGATIVE));
        assert!(cpu.status.contains(CpuFlags::BREAK));
    }

    #[test]
    fn test_0xe9_sbc_basic_subtraction() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x05, // LDA #$05
            0x38, // SEC
            0xe9, 0x02, // SBC #$02
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x03);
        assert!(cpu.status.contains(CpuFlags::CARRY));
        assert!(!cpu.status.contains(CpuFlags::ZERO));
        assert!(!cpu.status.contains(CpuFlags::NEGATIVE));
    }

    #[test]
    fn test_0xe9_sbc_with_borrow_negative_result() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00 - Load 0x00 into the accumulator
            0x18, // CLC - Clear carry flag to simulate an initial borrow
            0xe9, 0x01, // SBC #$01 - Subtract 0x01 from the accumulator
            0x00, // BRK - End of program
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0xfe);
        assert!(!cpu.status.contains(CpuFlags::CARRY));
        assert!(!cpu.status.contains(CpuFlags::ZERO));
        assert!(cpu.status.contains(CpuFlags::NEGATIVE));
    }

    #[test]
    fn test_0x38_sec() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0x38, // SEC
            0x00, // BRK
        ]);

        // Check if the Carry flag is set
        assert!(cpu.status.contains(CpuFlags::CARRY));
    }

    #[test]
    fn test_0xf8_sed() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xf8, // SED
            0x00, // BRK
        ]);

        assert!(cpu.status.contains(CpuFlags::DECIMAL_MODE));
    }

    #[test]
    fn test_0x78_sei() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0x78, // SEI
            0x00, // BRK
        ]);

        assert!(cpu.status.contains(CpuFlags::INTERRUPT_DISABLE));
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
    fn test_0xa8_tay() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa9, 0x42, // LDA #$42
            0xa8, // TAY
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::Y as usize], 0x42);
    }

    #[test]
    fn test_0xba_tsx() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xba, // TSX
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::X as usize], STACK_RESET);
    }

    #[test]
    fn test_0x8a_txa() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa2, 0x33, // LDX #$33
            0x8a, // TXA
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x33);
    }

    #[test]
    fn test_0x9a_txs() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa2, 0xe2, // LDX #$E2
            0x9a, // TXS
            0xba, // TSX
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::X as usize], 0xe2);
    }

    #[test]
    fn test_0x98_tya() {
        let mut cpu = CPU::new();

        cpu.load_and_run(vec![
            0xa0, 0x55, // LDY #$55
            0x98, // TYA
            0x00, // BRK
        ]);

        assert_eq!(cpu.regs[RegIdx::A as usize], 0x55); // Check if Accumulator holds the transferred value
    }

    #[test]
    fn test_four_instructions_together() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);
        // cpu.interpret(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);
        assert_eq!(cpu.regs[RegIdx::X as usize], 0xc1)
    }
}
