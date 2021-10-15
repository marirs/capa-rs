use crate::{error::Error, Arch, DisassemblyReport, DisassemblyResult, Result};
use capstone::prelude::*;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Instruction {
    arch: Arch,
    bitness: u32,
    pub offset: u64,
    bytes: String,
    pub mnemonic: String,
    pub operands: Option<String>,
}

impl Instruction {
    pub fn new(
        arch: Arch,
        bitness: &u32,
        ins: &(u64, String, String, Option<String>),
    ) -> Result<Instruction> {
        Ok(Instruction {
            arch: arch.clone(),
            bitness: bitness.clone(),
            offset: ins.0.clone(),
            bytes: ins.1.clone(),
            mnemonic: ins.2.clone(),
            operands: ins.3.clone(),
        })
    }

    pub fn get_printable_len(&self) -> Result<u64> {
        // should have exactly two operands for mov immediate
        let capstone = Capstone::new()
            .x86()
            .mode(if self.bitness == 32 {
                arch::x86::ArchMode::Mode32
            } else {
                arch::x86::ArchMode::Mode64
            })
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| Error::CapstoneError(e))?;
        let insns = capstone
            .disasm_all(&hex::decode(&self.bytes)?, self.offset)
            .map_err(|e| Error::CapstoneError(e))?;
        for insn in insns.as_ref() {
            let ll = capstone
                .insn_detail(insn)
                .map_err(|e| Error::CapstoneError(e))?;
            let instr = ll.arch_detail();
            if instr.operands().len() != 2 {
                return Ok(0);
            }

            if let capstone::arch::ArchOperand::X86Operand(op) = &instr.operands()[1] {
                if let capstone::arch::x86::X86OperandType::Imm(op_value) = op.op_type {
                    let chars = match op.size {
                        1 => ((op_value & 0xFF) as u8).to_le_bytes().to_vec(),
                        2 => ((op_value & 0xFFFF) as u16).to_le_bytes().to_vec(),
                        4 => ((op_value & 0xFFFFFFFF) as u32).to_le_bytes().to_vec(),
                        8 => ((op_value as u64 & 0xFFFFFFFFFFFFFFFF) as u64)
                            .to_le_bytes()
                            .to_vec(),
                        _ => {
                            return Err(Error::OperandError);
                        }
                    };
                    if is_printable_ascii(&chars)? {
                        return Ok(op.size as u64);
                    }
                    if is_printable_utf16le(&chars)? {
                        return Ok((op.size / 2) as u64);
                    }
                }
            }
        }
        Ok(0)
    }

    pub fn get_data_refs(&self, report: &DisassemblyReport) -> Result<Vec<u64>> {
        let mut res = vec![];
        if ![
            "arpl", "bound", "call", "clc", "cld", "cli", "cmc", "cmova", "cmovae", "cmovb",
            "cmovbe", "cmove", "cmovge", "cmovl", "cmovle", "cmovne", "cmovs", "cmp", "cmps",
            "cmpsb", "cmpsd", "cmpsw", "iret", "iretd", "ja", "jae", "jb", "jbe", "jcxz", "je",
            "jecxz", "jg", "jge", "jl", "jle", "jmp", "jne", "jno", "jnp", "jns", "jo", "jp",
            "jrcxz", "js", "lcall", "ljmp", "loop", "loope", "loopne", "ret", "retf", "retfq",
            "retn", "seta", "setae", "setb", "setbe", "sete", "setg", "setge", "setl", "setle",
            "setne", "setno", "setnp", "setns", "seto", "setp", "sets", "stc", "std", "sti",
            "test",
        ]
        .contains(&&self.mnemonic[..])
        {
            let capstone = Capstone::new()
                .x86()
                .mode(if self.bitness == 32 {
                    arch::x86::ArchMode::Mode32
                } else {
                    arch::x86::ArchMode::Mode64
                })
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| Error::CapstoneError(e))?;
            let insns = capstone
                .disasm_all(&hex::decode(&self.bytes)?, self.offset)
                .map_err(|e| Error::CapstoneError(e))?;
            for insn in insns.as_ref() {
                let ll = capstone
                    .insn_detail(insn)
                    .map_err(|e| Error::CapstoneError(e))?;
                let instr = ll.arch_detail();
                for operand in instr.operands() {
                    if let capstone::arch::ArchOperand::X86Operand(op) = operand {
                        let value = match op.op_type {
                            capstone::arch::x86::X86OperandType::Imm(op_value) => op_value,
                            capstone::arch::x86::X86OperandType::Mem(op_value) => {
                                if let Some(s) = capstone.reg_name(op_value.base()) {
                                    if s == "rip" {
                                        //add RIP value
                                        op_value.disp()
                                            + insn.address() as i64
                                            + insn.bytes().len() as i64
                                    } else {
                                        op_value.disp()
                                    }
                                } else {
                                    op_value.disp()
                                }
                            }
                            _ => 0,
                        };
                        if value != 0 && report.is_addr_within_memory_image(&(value as u64))? {
                            res.push(value as u64);
                        }
                    }
                }
            }
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct Function {
    arch: crate::Arch,
    pub bitness: u32,
    pub offset: u64,
    blocks: HashMap<u64, Vec<Instruction>>,
    pub apirefs: HashMap<u64, (Option<String>, Option<String>)>,
    pub blockrefs: HashMap<u64, Vec<u64>>,
    pub inrefs: Vec<u64>,
    pub outrefs: HashMap<u64, Vec<u64>>,
    pub binweight: u32,
    characteristics: String,
    confidence: f32,
    function_name: String,
    tfidf: f32,
}

impl Function {
    pub fn new(disassembly: &DisassemblyResult, function_offset: &u64) -> Result<Function> {
        let f = Function {
            arch: disassembly.binary_info.architecture.clone(),
            bitness: disassembly.binary_info.bitness.clone(),
            offset: function_offset.clone(),
            blocks: Function::parse_blocks(
                disassembly,
                &disassembly.get_blocks_as_dict(&function_offset)?,
            )?,
            apirefs: disassembly.get_api_refs(&function_offset)?,
            blockrefs: disassembly.get_block_refs(&function_offset)?,
            inrefs: disassembly.get_in_refs(&function_offset)?,
            outrefs: disassembly.get_out_refs(&function_offset)?,
            binweight: 0,
            characteristics: if disassembly.candidates.contains_key(&function_offset) {
                disassembly.candidates[&function_offset].get_characteristics()?
            } else {
                "-----------".to_string()
            },
            confidence: if disassembly.candidates.contains_key(&function_offset) {
                disassembly.candidates[&function_offset].get_confidence()?
            } else {
                0.0
            },
            function_name: match disassembly.function_symbols.get(&function_offset) {
                Some(s) => s.clone(),
                _ => "".to_string(),
            },
            tfidf: if disassembly.candidates.contains_key(&function_offset) {
                disassembly.candidates[&function_offset].get_tfidf()?
            } else {
                0.0
            },
        };
        // f.escaper = IntelInstructionEscaper if disassembly.binary_info.architecture in ["intel"] else None
        // self.pic_hash = self._calculatePicHash(disassembly.binary_info)
        // if config and config.CALCULATE_SCC:
        //     self.strongly_connected_components = self._calculateSccs()
        // self.nesting_depth = self._calculateNestingDepth()
        Ok(f)
    }

    fn parse_blocks(
        disassembly: &DisassemblyResult,
        block_dict: &HashMap<u64, Vec<(u64, String, String, Option<String>)>>,
    ) -> Result<HashMap<u64, Vec<Instruction>>> {
        let mut blocks = HashMap::new();
        let mut _binweight = 0;
        for (offset, block) in block_dict {
            let mut instructions = vec![];
            for ins in block {
                instructions.push(Instruction::new(
                    disassembly.binary_info.architecture,
                    &disassembly.binary_info.bitness,
                    ins,
                )?);
                _binweight += ins.2.len() / 2;
            }
            blocks.insert(offset.clone(), instructions);
        }
        Ok(blocks)
    }

    pub fn get_blocks(&self) -> Result<&HashMap<u64, Vec<Instruction>>> {
        Ok(&self.blocks)
    }

    pub fn get_instructions(&self) -> Result<Vec<&Instruction>> {
        let mut res = vec![];
        for (_, b) in &self.blocks {
            for i in b {
                res.push(i);
            }
        }
        Ok(res)
    }

    pub fn get_num_instructions(&self) -> Result<usize> {
        let mut count = 0;
        for (_, b) in &self.blocks {
            count += b.len();
        }
        Ok(count)
    }

    pub fn get_num_outrefs(&self) -> Result<usize> {
        let mut count = 0;
        for (_, dsts) in &self.outrefs {
            count += dsts.len();
        }
        Ok(count)
    }

    pub fn is_api_thunk(&self) -> Result<bool> {
        if self.get_num_instructions()? != 1 {
            return Ok(false);
        }
        let first_ins = &self.blocks[&self.offset][0];
        if !vec!["jmp", "call"].contains(&&first_ins.mnemonic[..]) {
            return Ok(false);
        }
        if self.apirefs.len() == 0 {
            return Ok(false);
        }
        Ok(true)
    }
}

pub fn is_printable_ascii(chars: &[u8]) -> Result<bool> {
    for c in chars {
        if c >= &127 || !b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ ".contains(c){
            return Ok(false)
        }
    }
    Ok(true)
}

pub fn is_printable_utf16le(chars: &[u8]) -> Result<bool> {
    let mut i = 1;
    let mut u = vec![];
    while i < chars.len() {
        if i % 2 != 0 && chars[i] != 0x00 {
            return Ok(false);
        } else if i % 2 == 0 {
            u.push(chars[i]);
        }
        i += 1;
    }
    is_printable_ascii(&u)
}
