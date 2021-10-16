use crate::{error::Error, DisassemblyResult, Result, CALL_INS, END_INS};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug)]
pub struct FunctionAnalysisState {
    pub start_addr: u64,
    pub block_queue: VecDeque<u64>,
    pub(crate) current_block: Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
    blocks: Vec<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>>,
    num_blocks_analyzed: u32,
    pub instructions: Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
    pub instruction_start_bytes: HashSet<u64>,
    processed_blocks: HashSet<u64>,
    processed_bytes: HashSet<u64>,
    jump_targets: Vec<u64>,
    pub call_register_ins: Vec<u64>,
    pub block_start: u64,
    data_bytes: Vec<u64>,
    data_refs: Vec<(u64, u64)>,
    pub code_refs: Vec<(u64, u64)>,
    code_refs_from: HashMap<u64, Vec<u64>>,
    code_refs_to: HashMap<u64, Vec<u64>>,
    pub suspicious_ins_count: u32,
    is_jmp: bool,
    is_next_instruction_reachable: bool,
    is_block_ending_instruction: bool,
    is_sanely_ending: bool,
    has_collision: bool,
    pub is_tailcall_function: bool,
    is_leaf_function: bool,
    is_recursive: bool,
    is_thunk_call: bool,
    pub label: String,
}

impl FunctionAnalysisState {
    pub fn new(addr: u64) -> Result<FunctionAnalysisState> {
        Ok(FunctionAnalysisState {
            start_addr: addr,
            block_queue: vec![addr].into_iter().collect(),
            current_block: vec![],
            blocks: vec![],
            num_blocks_analyzed: 0,
            instructions: vec![],
            instruction_start_bytes: HashSet::new(),
            processed_blocks: HashSet::new(),
            processed_bytes: HashSet::new(),
            jump_targets: vec![],
            call_register_ins: vec![],
            block_start: 0xFFFFFFFF,
            data_bytes: vec![],
            data_refs: vec![],
            code_refs: vec![],
            code_refs_from: HashMap::new(),
            code_refs_to: HashMap::new(),
            suspicious_ins_count: 0,
            is_jmp: false,
            is_next_instruction_reachable: true,
            is_block_ending_instruction: false,
            is_sanely_ending: false,
            has_collision: false,
            is_tailcall_function: false,
            is_leaf_function: true,
            is_recursive: false,
            is_thunk_call: false,
            label: String::from(""),
        })
    }

    pub fn is_processed_function(&self, disassembly: &DisassemblyResult) -> bool {
        disassembly.code_map.contains_key(&self.start_addr)
    }

    pub fn has_unprocessed_blocks(&self) -> bool {
        let ss: HashSet<u64> = self.block_queue.clone().into_iter().collect();
        ss.difference(&self.processed_blocks).count() > 0
    }

    pub fn choose_next_block(&mut self) -> Result<u64> {
        self.is_block_ending_instruction = false;
        self.block_start = self
            .block_queue
            .pop_back()
            .ok_or(Error::LogicError(file!(), line!()))?;
        self.processed_blocks.insert(self.block_start);
        Ok(self.block_start)
    }

    pub fn set_next_instruction_reachable(&mut self, flag: bool) -> Result<()> {
        self.is_next_instruction_reachable = flag;
        Ok(())
    }

    pub fn set_leaf(&mut self, flag: bool) -> Result<()> {
        self.is_leaf_function = flag;
        Ok(())
    }

    pub fn add_code_ref(&mut self, addr_from: u64, addr_to: u64, by_jump: bool) -> Result<()> {
        self.code_refs.push((addr_from, addr_to));
        let mut refs_from = match self.code_refs_from.remove(&addr_from) {
            Some(v) => v,
            _ => vec![],
        };
        refs_from.push(addr_to);
        self.code_refs_from.insert(addr_from, refs_from);
        let mut refs_to = match self.code_refs_to.remove(&addr_to) {
            Some(v) => v,
            _ => vec![],
        };
        refs_to.push(addr_from);
        self.code_refs_to.insert(addr_to, refs_to.clone());
        if by_jump {
            self.is_jmp = true;
            self.jump_targets.push(addr_to);
        }
        Ok(())
    }

    pub fn is_processed(&self, addr: &u64) -> Result<bool> {
        Ok(self.processed_bytes.contains(addr))
    }

    pub fn is_block_ending_instruction(&self) -> Result<bool> {
        Ok(self.is_block_ending_instruction)
    }

    pub fn set_recursion(&mut self, flag: bool) -> Result<()> {
        self.is_recursive = flag;
        Ok(())
    }

    pub fn set_sanely_ending(&mut self, flag: bool) -> Result<()> {
        self.is_sanely_ending = flag;
        Ok(())
    }

    pub fn is_first_instruction(&self) -> Result<bool> {
        Ok(self.instructions.len() == 0)
    }

    pub fn add_block_to_queue(&mut self, block_start: u64) -> Result<()> {
        if !self.processed_blocks.contains(&block_start) {
            self.block_queue.push_back(block_start);
        }
        Ok(())
    }

    pub fn set_block_ending_instruction(&mut self, flag: bool) -> Result<()> {
        self.is_block_ending_instruction = flag;
        Ok(())
    }

    pub fn backtrack_instructions(
        &self,
        addr_from: u64,
        num_instructions: u32,
    ) -> Result<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>> {
        let mut backtracked = vec![];
        for instruction in &self.instructions {
            if instruction.0 < addr_from {
                backtracked.push(instruction.clone());
            }
        }
        if backtracked.len() < num_instructions as usize {
            Ok(backtracked[..].to_vec())
        } else {
            Ok(backtracked[backtracked.len() - num_instructions as usize..].to_vec())
        }
    }

    pub fn add_data_ref(
        &mut self,
        addr_from: u64,
        addr_to: u64,
        size: u64, /*1*/
    ) -> Result<()> {
        self.data_refs.push((addr_from, addr_to));
        for i in 0..size {
            self.data_bytes.push(addr_to + i);
        }
        Ok(())
    }

    pub fn end_block(&mut self) -> Result<()> {
        if self.current_block.len() > 0 {
            self.num_blocks_analyzed += 1;
            //# self.blocks.append(self.current_block)
        }
        self.current_block = vec![];
        Ok(())
    }

    pub fn add_instruction(
        &mut self,
        i_address: u64,
        i_size: usize,
        i_mnemonic: Option<String>,
        i_op_str: Option<String>,
        i_bytes: Vec<u8>,
    ) -> Result<()> {
        let ins = (i_address, i_size as u32, i_mnemonic, i_op_str, i_bytes);
        self.instructions.push(ins.clone());
        self.instruction_start_bytes.insert(i_address);
        self.current_block.push(ins);
        for byte in 0..i_size {
            self.processed_bytes.insert(i_address + byte as u64);
        }
        if self.is_next_instruction_reachable {
            self.add_code_ref(i_address, i_address + i_size as u64, self.is_jmp)?;
        }
        self.is_jmp = false;
        Ok(())
    }

    pub fn set_collision(&mut self, flag: bool) -> Result<()> {
        self.has_collision = flag;
        Ok(())
    }

    pub fn finalize_analysis(
        &mut self,
        as_gap: bool,
        disassembly: &mut DisassemblyResult,
    ) -> Result<bool> {
        if as_gap {
            //LOGGER.debug("0x%08x had sanity state: %s (%d ins, blocks: %d)", self.start_addr, self.is_sanely_ending, len(self.instructions), self.num_blocks_analyzed)
            //for instruction in sorted(self.instructions):
        }
        if as_gap && !self.is_sanely_ending {
            if self.instructions.len() == 1 && self.instructions[0].2.as_ref().unwrap() == "jmp" {
                let byte = disassembly.get_byte(self.instructions[0].0)?;
                if byte == b'\xEB' {
                    return Ok(false);
                }
            }
            //# sane case, stub found that just jumps to a referenced function
            else if self.num_blocks_analyzed == 1
                && vec![String::from("jmp"), String::from("call")].contains(
                    &self.instructions[self.instructions.len() - 1]
                        .2
                        .as_ref()
                        .unwrap(),
                )
            {
                //# similar case to the one above, mostly stubs with tailcalls to a function or shared tail block.
            } else {
                return Ok(false);
            }
        }
        //# in case we have a successful analysis, forward results to disassembly
        if self.num_blocks_analyzed > 0 {
            self.finalize_regular_analysis(disassembly)?;
        }
        Ok(true)
    }

    pub fn get_blocks(
        &self,
    ) -> Result<Vec<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>>> {
        //        if self.blocks.len() > 0{
        //            return Ok(&self.blocks);
        //      }
        //self.instructions.sort();
        let mut cc = 0;
        let mut ins = HashMap::new();
        for i in &self.instructions {
            ins.insert(i.0, cc);
            cc += 1;
        }
        let mut potential_starts = self.jump_targets.clone();
        potential_starts.push(self.start_addr);
        potential_starts.sort();
        let mut blocks = vec![];
        for start in &potential_starts {
            if !ins.contains_key(&start) {
                continue;
            }
            let mut block = vec![];
            for i in ins[&start]..self.instructions.len() {
                let current = self.instructions[i].clone();
                block.push(current.clone());

                // if one code reference is to another address than the next
                if self.code_refs_from.contains_key(&current.0)
                    && !CALL_INS.contains(&Some(current.2.as_ref().unwrap().as_str()))
                    && i != self.instructions.len() - 1
                {
                    for r in &self.code_refs_from[&current.0] {
                        if *r != self.instructions[i + 1].0 {
                            break;
                        }
                    }
                }
                if i != self.instructions.len() - 1
                    && self.code_refs_to.contains_key(&self.instructions[i + 1].0)
                {
                    if self.code_refs_to[&self.instructions[i + 1].0].len() > 1
                        || potential_starts.contains(&self.instructions[i + 1].0)
                    {
                        break;
                    }
                }
                if END_INS.contains(&Some(current.2.as_ref().unwrap().as_str())) {
                    break;
                }
            }
            if block.len() > 0 {
                blocks.push(block);
            }
        }
        //      self.blocks = blocks;
        Ok(blocks)
    }

    pub fn finalize_regular_analysis(&mut self, disassembly: &mut DisassemblyResult) -> Result<()> {
        let mut fn_min: u64 = 0xFFFFFFFFFFFFFFFF;
        for s in &self.instructions {
            if s.0 < fn_min {
                fn_min = s.0;
            }
        }
        let mut fn_max: u64 = 0;
        for s in &self.instructions {
            if s.0 + s.1 as u64 > fn_max {
                fn_max = s.0 + s.1 as u64;
            }
        }
        disassembly
            .function_symbols
            .insert(self.start_addr, self.label.clone());
        disassembly
            .function_borders
            .insert(self.start_addr, (fn_min, fn_max));
        for ins in &self.instructions {
            disassembly
                .instructions
                .insert(ins.0, (ins.2.as_ref().unwrap().to_string(), ins.1));
            for offset in 0..ins.1 {
                disassembly.code_map.insert(ins.0 + offset as u64, ins.0);
                disassembly
                    .ins2fn
                    .insert(ins.0 + offset as u64, self.start_addr);
            }
        }
        for cref in &self.code_refs {
            disassembly.add_code_refs(cref.0, cref.1)?;
        }
        for dref in &self.data_refs {
            disassembly.add_data_refs(dref.0, dref.1)?;
        }
        for d in &self.data_bytes {
            disassembly.data_map.insert(*d);
        }
        disassembly
            .functions
            .insert(self.start_addr, self.get_blocks()?);
        if self.is_recursive {
            disassembly.recursive_functions.insert(self.start_addr);
        }
        if self.is_leaf_function {
            disassembly.leaf_functions.insert(self.start_addr);
        }
        if self.is_thunk_call {
            disassembly.thunk_functions.insert(self.start_addr);
        }
        Ok(())
    }

    pub fn identify_call_conflicts(
        &self,
        all_refs: &HashMap<u64, u64>,
    ) -> Result<HashMap<u64, Vec<u64>>> {
        let mut conflicts: HashMap<u64, Vec<u64>> = HashMap::new();
        let non_instruction_start_bytes: HashSet<u64> = self
            .processed_bytes
            .difference(&self.instruction_start_bytes)
            .map(|e| *e)
            .collect();
        let all_refs_set: HashSet<u64> = all_refs.keys().map(|e| *e).collect();
        let conflict_addrs = all_refs_set.intersection(&non_instruction_start_bytes);
        for candidate_source_ref in conflict_addrs {
            let candidate = all_refs[candidate_source_ref];
            match conflicts.get_mut(&candidate) {
                Some(c) => c.push(*candidate_source_ref),
                None => {
                    conflicts.insert(candidate, vec![*candidate_source_ref]);
                }
            }
        }
        Ok(conflicts)
    }

    pub fn revert_analysis(&self) -> Result<()> {
        //TODO
        //        self.disassembly.function_borders.pop(self.start_addr, None)
        //            for ins in self.instructions:
        //     self.disassembly.instructions.pop(ins[0], None)
        //     for byte in range(ins[1]):
        //         self.disassembly.code_map.pop(ins[0] + byte, None)
        //         self.disassembly.ins2fn.pop(ins[0] + byte, None)
        // for cref in self.code_refs:
        //     self.disassembly.removeCodeRefs(cref[0], cref[1])
        // for dref in self.data_refs:
        //     self.disassembly.removeDataRefs(dref[0], dref[1])
        //     self.disassembly.functions.pop(self.start_addr, None)
        Ok(())
    }
}
