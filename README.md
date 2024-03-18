# Uemura: A Simple NES Emulator
---
## Introduction
Welcome to Uemura, a from-scratch NES emulator built in Rust. Named in honor of Masayuki Uemura, the architect of the original NES, this emulator is a homage to the classic gaming era. Uemura is an open-source project aimed at accurately emulating the NES, and providing both a learning experience in how an emulator works, it's building blocks and also a nostalgic trip for retro gaming fans.

## Project Goal
The ultimate goal of Uemura is to be capable of running every NES game, replicating the original hardware experience as closely as possible. This involves meticulous implementation of the 6502 instruction set and other NES components, ensuring compatibility and performance.

## 6502 Instruction Set Checklist
As part of our development process, we are methodically implementing the 6502 instruction set. This checklist serves as our progress tracker:

### Instructions Implementation Progress

- [x] ADC - Add with Carry
- [x] AND - Logical AND
- [x] ASL - Arithmetic Shift Left
- [x] BCC - Branch if Carry Clear
- [x] BCS - Branch if Carry Set
- [x] BEQ - Branch if Equal
- [x] BIT - Bit Test
- [x] BMI - Branch if Minus
- [x] BNE - Branch if Not Equal
- [x] BPL - Branch if Positive
- [x] BRK - Force Interrupt (Needs improvement)
- [x] BVC - Branch if Overflow Clear
- [x] BVS - Branch if Overflow Set
- [x] CLC - Clear Carry Flag
- [x] CLD - Clear Decimal Mode
- [x] CLI - Clear Interrupt Disable
- [x] CLV - Clear Overflow Flag
- [x] CMP - Compare Accumulator
- [x] CPX - Compare X Register
- [x] CPY - Compare Y Register
- [x] DEC - Decrement Memory
- [x] DEX - Decrement X Register
- [x] DEY - Decrement Y Register
- [x] EOR - Exclusive OR
- [x] INC - Increment Memory
- [x] INX - Increment X Register
- [x] INY - Increment Y Register
- [x] JMP - Jump
- [x] JSR - Jump to Subroutine
- [x] LDA - Load Accumulator
- [x] LDX - Load X Register
- [x] LDY - Load Y Register
- [x] LSR - Logical Shift Right
- [x] NOP - No Operation
- [x] ORA - Logical Inclusive OR
- [x] PHA - Push Accumulator
- [ ] PHP - Push Processor Status
- [ ] PLA - Pull Accumulator
- [ ] PLP - Pull Processor Status
- [ ] ROL - Rotate Left
- [ ] ROR - Rotate Right
- [ ] RTI - Return from Interrupt
- [ ] RTS - Return from Subroutine
- [ ] SBC - Subtract with Carry
- [ ] SEC - Set Carry Flag
- [ ] SED - Set Decimal Flag
- [ ] SEI - Set Interrupt Disable
- [x] STA - Store Accumulator
- [ ] STX - Store X Register
- [ ] STY - Store Y Register
- [x] TAX - Transfer Accumulator to X
- [ ] TAY - Transfer Accumulator to Y
- [ ] TSX - Transfer Stack Pointer to X
- [ ] TXA - Transfer X to Accumulator
- [ ] TXS - Transfer X to Stack Pointer
- [ ] TYA - Transfer Y to Accumulator

