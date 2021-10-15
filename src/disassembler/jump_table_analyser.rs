use crate::error::Error;
use crate::result::Result;
use std::convert::TryInto;

#[derive(Debug)]
pub struct JumpTableAnalyser {
    table_offsets: Vec<u64>,
}

impl JumpTableAnalyser {
    pub fn new() -> JumpTableAnalyser {
        JumpTableAnalyser {
            table_offsets: vec![],
        }
    }

    pub fn init(&mut self, disassembly: &crate::disassembler::DisassemblyResult) -> Result<()> {
        self.table_offsets = self.find_jump_tables(disassembly)?;
        Ok(())
    }

    pub fn find_jump_tables(
        &mut self,
        disassembly: &crate::disassembler::DisassemblyResult,
    ) -> Result<Vec<u64>> {
        let mut jumptables = vec![];
        let re =
            regex::bytes::Regex::new(r"(?-u)(\x48|\x4c)\x8d.{5}(.\x63|\x77|.\x89..\x63)").unwrap();
        for match_offset in re.find_iter(&disassembly.binary_info.binary) {
            let packed_dword: &[u8; 4] = disassembly
                .get_raw_bytes(match_offset.start() as u64 + 3, 4)?
                .try_into()?;
            let rel_table_offset = u32::from_le_bytes(*packed_dword) as u64;
            let ins_offset = disassembly.binary_info.base_addr + match_offset.start() as u64;
            let table_offset = ins_offset + rel_table_offset + 7;
            if disassembly.is_addr_within_memory_image(table_offset)? {
                jumptables.push(table_offset);
            }
        }
        Ok(jumptables)
    }

    pub fn get_jump_targets(
        &self,
        jump_instruction: &capstone::Insn,
        disassembler: &crate::disassembler::Disassembler,
        state: &mut crate::disassembler::FunctionAnalysisState,
    ) -> Result<Vec<u64>> {
        let jump_instruction_address = jump_instruction.address();
        let jump_instruction_op_str = match jump_instruction.op_str() {
            Some(s) => s,
            None => "",
        };
        let mut table_offsets = vec![];
        let backtracked = state.backtrack_instructions(jump_instruction_address, 50)?;
        let backtracked_sequence = ""; //"-".join([ins[2] for ins in backtracked[::-1]][:3])
        let mut jumptable_size = self.find_jump_table_size(&backtracked)?;
        if jump_instruction_op_str.starts_with("dword ptr [")
            || jump_instruction_op_str.starts_with("qword ptr [")
        {
            let off_jumptable = disassembler.get_referenced_addr(jump_instruction_op_str)?;
            let _table_offsets = self.resolve_explicit_table(
                jump_instruction_address,
                &disassembler.disassembly,
                state,
                off_jumptable,
                Some(jumptable_size),
            )?;
        } else {
            //            # 32bit cases typically load into target register directly
            if backtracked_sequence.starts_with("mov") {
                let off_jumptable = self.direct_handler(
                    jump_instruction_op_str,
                    disassembler,
                    state,
                    &backtracked,
                )?;
                table_offsets = self.extract_direct_table_offsets(
                    Some(jumptable_size),
                    off_jumptable,
                    disassembler,
                )?;
            } else if backtracked_sequence.starts_with("add-movsxd") {
                jumptable_size = self.find_jump_table_size(&backtracked)?;
                let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
                //                let mut alternative_base = 0;
                if backtracked[..backtracked.len() - 1][0]
                    .3
                    .as_ref()
                    .unwrap()
                    .contains("rsi")
                {
                    let alternative_base = self.x64_handler(
                        disassembler,
                        state,
                        &backtracked,
                        Some("rsi".to_string()),
                    )?;
                    table_offsets = self.extract_relative_table_offsets(
                        Some(jumptable_size),
                        off_jumptable,
                        Some(alternative_base),
                        0,
                        disassembler,
                    )?;
                }
            } else if backtracked_sequence.starts_with("lea") {
                jumptable_size = self.find_jump_table_size(&backtracked)?;
                let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
                table_offsets = self.extract_relative_table_offsets(
                    Some(jumptable_size),
                    off_jumptable,
                    None,
                    0,
                    disassembler,
                )?;
            } else if backtracked_sequence.starts_with("add-add")
                || backtracked_sequence.starts_with("add-shr")
            {
                jumptable_size = self.find_jump_table_size(&backtracked)?;
                let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
                table_offsets = self.extract_relative_table_offsets(
                    Some(jumptable_size),
                    off_jumptable,
                    None,
                    0,
                    disassembler,
                )?;
            } else if backtracked_sequence.starts_with("add-mov") {
                jumptable_size = self.find_jump_table_size(&backtracked)?;
                let off_jumptable = self.x64_handler(disassembler, state, &backtracked, None)?;
                let bonus = self.get_x64_bonus_offset(disassembler, &backtracked)?;
                table_offsets = self.extract_relative_table_offsets(
                    Some(jumptable_size),
                    off_jumptable,
                    None,
                    bonus,
                    disassembler,
                )?;
            }
        }
        Ok(table_offsets)
    }

    pub fn find_jump_table_size(
        &self,
        backtracked: &Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
    ) -> Result<usize> {
        let mut jumptable_size = 0;
        if backtracked.len() == 0 {
            return Ok(jumptable_size);
        }
        for instr in &backtracked[..backtracked.len() - 1] {
            if instr.2.as_ref().unwrap().starts_with("ret") {
                break;
            }
            if instr.2.as_ref().unwrap() == "cmp" {
                let re = regex::Regex::new(
                    r"(?-u)(?P<one>[a-z0-9]{2,4}), (?P<two>([0-9])|(0x[0-9a-f]+))",
                )
                .unwrap();
                if re.is_match(instr.3.as_ref().unwrap()) {
                    let c = re
                        .captures(instr.3.as_ref().unwrap())
                        .ok_or(Error::LogicError(file!(), line!()))?;
                    jumptable_size = usize::from_str_radix(&c["two"], 16)? + 1;
                    break;
                }
            }
        }
        Ok(jumptable_size)
    }

    pub fn resolve_explicit_table(
        &self,
        jump_instruction_address: u64,
        disassembly: &crate::disassembler::DisassemblyResult,
        state: &mut crate::disassembler::FunctionAnalysisState,
        jumptable_address: u64,
        jumptable_size: Option<usize>,
    ) -> Result<Vec<u64>> {
        let jumptable_size = match jumptable_size {
            Some(s) => s,
            None => 0xFF,
        };
        let mut jumptable_addresses = vec![];
        let bitness = disassembly.binary_info.bitness;
        let entry_size = match bitness {
            32 => 4,
            _ => 8,
        };
        let mut table_entry = 0;
        if disassembly.is_addr_within_memory_image(jumptable_address)? {
            for i in 0..jumptable_size {
                if bitness == 32 {
                    let packed_dword: &[u8; 4] = disassembly
                        .get_bytes(jumptable_address + i as u64 * entry_size, entry_size)?
                        .try_into()?;
                    table_entry = u32::from_le_bytes(*packed_dword) as u64;
                } else if bitness == 64 {
                    let packed_dword: &[u8; 8] = disassembly
                        .get_bytes(jumptable_address + i as u64 * entry_size, entry_size)?
                        .try_into()?;
                    table_entry = u64::from_le_bytes(*packed_dword);
                }
                if !disassembly.is_addr_within_memory_image(table_entry)? {
                    break;
                }
                state.add_data_ref(
                    jump_instruction_address,
                    jumptable_address + i as u64 * entry_size,
                    entry_size,
                )?;
                jumptable_addresses.push(table_entry);
            }
        }
        Ok(jumptable_addresses)
    }

    pub fn direct_handler(
        &self,
        jump_instruction_op_str: &str,
        disassembler: &crate::disassembler::Disassembler,
        state: &mut crate::disassembler::FunctionAnalysisState,
        backtracked: &Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
    ) -> Result<u64> {
        let register = jump_instruction_op_str.to_lowercase();
        let mut off_jumptable = None;
        for instr in backtracked.iter().rev() {
            if instr.2.as_ref().unwrap() == "mov" {
                let re =
                    regex::Regex::new(r"(?-u)[a-z0-9]{2,3}, dword ptr \[[^ ]+ \+ 0x[0-9a-f]+\]")
                        .unwrap();
                if re.is_match(instr.3.as_ref().unwrap()) {
                    let data_ref_instruction_addr = instr.0;
                    off_jumptable =
                        Some(disassembler.get_referenced_addr(instr.3.as_ref().unwrap())?);
                    state.add_data_ref(
                        data_ref_instruction_addr,
                        *off_jumptable.as_ref().unwrap(),
                        4,
                    )?;
                    break;
                }
            } else if instr.2.as_ref().unwrap() == "add"
                && instr.3.as_ref().unwrap().starts_with(&register)
            {
                let data_ref_instruction_addr = instr.0;
                off_jumptable = Some(disassembler.get_referenced_addr(instr.3.as_ref().unwrap())?);
                state.add_data_ref(
                    data_ref_instruction_addr,
                    *off_jumptable.as_ref().unwrap(),
                    4,
                )?;
                break;
            }
        }
        match off_jumptable {
            Some(o) => Ok(o),
            None => Err(Error::LogicError(file!(), line!())),
        }
    }

    pub fn extract_direct_table_offsets(
        &self,
        jumptable_size: Option<usize>,
        off_jumptable: u64,
        disassembler: &crate::disassembler::Disassembler,
    ) -> Result<Vec<u64>> {
        let mut jump_targets = vec![];
        if let Some(jumptable_size) = jumptable_size {
            if off_jumptable != 0
                && disassembler
                    .disassembly
                    .is_addr_within_memory_image(off_jumptable)?
            {
                for index in 0..jumptable_size {
                    let packed_dword: &[u8; 4] = disassembler
                        .disassembly
                        .get_bytes(off_jumptable + index as u64 * 4, 4)?
                        .try_into()?;
                    let entry = u32::from_le_bytes(*packed_dword) as u64;
                    jump_targets.push(entry);
                }
            }
        }
        jump_targets.sort();
        Ok(jump_targets)
    }

    pub fn x64_handler(
        &self,
        disassembler: &crate::disassembler::Disassembler,
        state: &mut crate::disassembler::FunctionAnalysisState,
        backtracked: &Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
        target_register: Option<String>,
    ) -> Result<u64> {
        let mut off_jumptable = None;
        for instr in backtracked.iter().rev() {
            if instr.2.as_ref().unwrap() == "lea" {
                let re =
                    regex::Regex::new(r"(?-u)[a-z0-9]{2,3}, \[rip (\+|\-) 0x[0-9a-f]+\]").unwrap();
                if re.is_match(instr.3.as_ref().unwrap()) {
                    if let Some(target_register_) = &target_register {
                        if !instr.3.as_ref().unwrap().contains(target_register_) {
                            continue;
                        }
                    }
                    let data_ref_instruction_addr = instr.0;
                    let mut offset =
                        disassembler.get_referenced_addr(instr.3.as_ref().unwrap())? as i64;
                    let rip_sign = if instr.3.as_ref().unwrap().contains("+") {
                        "+"
                    } else {
                        "-"
                    };
                    if rip_sign == "-" {
                        offset = offset * -1;
                    }
                    off_jumptable = Some(instr.0 as i64 + instr.1 as i64 + offset);
                    state.add_data_ref(
                        data_ref_instruction_addr,
                        *off_jumptable.as_ref().unwrap() as u64,
                        4,
                    )?;
                    break;
                }
            }
        }
        match off_jumptable {
            Some(s) => Ok(s as u64),
            None => Err(Error::LogicError(file!(), line!())),
        }
    }

    pub fn extract_relative_table_offsets(
        &self,
        jumptable_size: Option<usize>,
        off_jumptable: u64,
        alternative_base: Option<u64>,
        bonus_offset: u64,
        disassembler: &crate::disassembler::Disassembler,
    ) -> Result<Vec<u64>> {
        let jumptable_size = match jumptable_size {
            Some(s) => s,
            None => 0xFF,
        };
        let mut jump_targets = vec![];
        let jump_base = match alternative_base {
            Some(s) => s,
            None => off_jumptable,
        };
        if jumptable_size != 0
            && off_jumptable != 0
            && disassembler
                .disassembly
                .is_addr_within_memory_image(off_jumptable)?
        {
            for index in 0..jumptable_size {
                let rebased =
                    off_jumptable + bonus_offset - disassembler.disassembly.binary_info.base_addr;
                let packed_dword: &[u8; 4] = disassembler
                    .disassembly
                    .get_bytes(rebased + index as u64 * 4, 4)?
                    .try_into()?;
                let entry = u32::from_le_bytes(*packed_dword) as u64;
                //# check if we are hitting a known jump table
                if index != 0
                    && self
                        .table_offsets
                        .contains(&(off_jumptable + index as u64 * 4))
                {
                    break;
                }
                if !disassembler
                    .disassembly
                    .is_addr_within_memory_image(jump_base + entry)?
                {
                    break;
                }
                if entry != 0 {
                    let target = (jump_base + entry) & disassembler.get_bitmask();
                    jump_targets.push(target);
                    //# state.addDataRef(off_jumptable, rebased + index * 4, size=4)
                } else if let None = alternative_base {
                    break;
                }
            }
        }
        jump_targets.sort();
        Ok(jump_targets)
    }

    pub fn get_x64_bonus_offset(
        &self,
        disassembler: &crate::disassembler::Disassembler,
        backtracked: &Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
    ) -> Result<u64> {
        let mut bonus_offset = 0;
        let mut i = 0;
        for instr in &backtracked[..backtracked.len() - 1] {
            if i < 3 {
                let re = regex::Regex::new(r"(?-u)[a-z0-9]{2,3},.*0x[0-9a-f]+\]").unwrap();
                if instr.2.as_ref().unwrap() == "mov" && re.is_match(instr.3.as_ref().unwrap()) {
                    bonus_offset = disassembler.get_referenced_addr(instr.3.as_ref().unwrap())?;
                    break;
                }
            }
            i += 1;
        }
        Ok(bonus_offset)
    }
}
