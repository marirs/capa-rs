use crate::{error::Error, label_providers::ApiEntry, Disassembler, FunctionAnalysisState, Result};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
};

#[derive(Debug)]
pub struct IndirectCallAnalyser {
    //    current_calling_addr: u64
}

impl IndirectCallAnalyser {
    pub fn new() -> IndirectCallAnalyser {
        IndirectCallAnalyser{
//            current_calling_addr: 0
        }
    }

    pub fn init(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn resolve_register_calls(
        &self,
        disassembler: &Disassembler,
        analysis_state: &mut FunctionAnalysisState,
        block_depth: i32,
    ) -> Result<(Vec<(u64, ApiEntry)>, Vec<(u64, u64)>)> {
        //# after block reconstruction do simple data flow analysis to
        // resolve open cases like "call <register>" as stored in
        // self.call_register_ins
        let mut res = vec![];
        let mut res2 = vec![];
        let calling_addr_vec = analysis_state.call_register_ins.clone();
        for calling_addr in &calling_addr_vec {
            //LOGGER.debug("#" * 20)
            //            self.current_calling_addr = *calling_addr;
            let mut start_block = vec![];
            for ins in self.search_block(analysis_state, calling_addr)? {
                if ins.0 <= *calling_addr {
                    start_block.push(ins);
                }
            }
            if !start_block.is_empty() {
                let mut s: String = start_block[start_block.len() - 1]
                    .3
                    .as_ref()
                    .unwrap()
                    .to_string();
                self.process_block(
                    analysis_state,
                    start_block,
                    &mut HashMap::new(),
                    &mut s,
                    &mut HashSet::new(),
                    block_depth,
                    *calling_addr,
                    disassembler,
                    &mut res,
                    &mut res2,
                )?;
            }
        }
        Ok((res, res2))
    }

    pub fn search_block(
        &self,
        analysis_state: &FunctionAnalysisState,
        address: &u64,
    ) -> Result<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>> {
        for block in &analysis_state.get_blocks()? {
            for i in block {
                if address == &i.0 {
                    return Ok(block.clone());
                }
            }
        }
        Ok(vec![])
        //        Err(Error::LogicError(file!(), line!()))
    }

    pub fn process_block(
        &self,
        analysis_state: &mut FunctionAnalysisState,
        block: Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>,
        registers: &mut HashMap<String, u64>,
        register_name: &mut String,
        processed: &mut HashSet<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>>,
        depth: i32,
        current_calling_addr: u64,
        disassembler: &Disassembler,
        api_e: &mut Vec<(u64, ApiEntry)>,
        cand_e: &mut Vec<(u64, u64)>,
    ) -> Result<bool> {
        if block.is_empty() {
            return Ok(false);
        }
        if processed.contains(&block) {
            //LOGGER.debug("already processed block 0x%08x; skipping", block[0][0])
            return Ok(false);
        }
        processed.insert(block.clone());
        //LOGGER.debug("start processing block: 0x%08x\nlooking for register %s", block[0][0], register_name)
        let mut abs_value_found = false;
        for ins in block.iter().rev() {
            //LOGGER.debug("0x%08x: %s %s", ins[0], ins[2], ins[3])
            if ins.2.as_ref().unwrap() == "mov" {
                //#mov <reg>, <reg>
                let re = regex::Regex::new(r"(?P<reg1>[a-z]{3}), (?P<reg2>[a-z]{3})$").unwrap();
                for match1 in re.captures_iter(ins.3.as_ref().unwrap()) {
                    if &match1["reg1"].to_string() == register_name {
                        *register_name = match1["reg2"].to_string();
                    }
                }
                //#mov <reg>, <const>
                let re =
                    regex::Regex::new(r"(?P<reg>[a-z]{3}), (?P<val>0x[0-9a-f]{1,8})$").unwrap();
                for match2 in re.captures_iter(ins.3.as_ref().unwrap()) {
                    registers.insert(
                        match2["reg"].to_string(),
                        u64::from_str_radix(&match2["val"][2..], 16)?,
                    );
                    //LOGGER.debug("**moved value 0x%08x to register %s", int(match2.group("val"), 16), match2.group("reg"))
                    if &match2["reg"].to_string() == register_name {
                        abs_value_found = true;
                    }
                }
                //#mov <reg>, dword ptr [<addr>]
                let re = regex::Regex::new(
                    r"(?P<reg>[a-z]{3}), dword ptr \[(?P<addr>0x[0-9a-f]{1,8})\]$",
                )
                .unwrap();
                for match3 in re.captures_iter(ins.3.as_ref().unwrap()) {
                    //# HACK: test to see if the address points to a import and
                    //# use that instead of the actual memory value
                    let addr = u64::from_str_radix(&match3["addr"][2..], 16)?;
                    let (dll, api) = disassembler.resolve_api(addr, addr)?;
                    if dll != None || api != None {
                        registers.insert(match3["reg"].to_string(), addr);
                        //LOGGER.debug("**moved API ref (%s:%s) @0x%08x to register %s", dll, api, addr, match3.group("reg"))
                        if &match3["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    } else if let Ok(dword) = self.get_dword(addr, disassembler) {
                        registers.insert(match3["reg"].to_string(), dword);
                        //LOGGER.debug("**moved value 0x%08x to register %s", dword, match3.group("reg"))
                        if &match3["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    }
                }
                //# mov <reg>, qword ptr [reg + <addr>]
                let re = regex::Regex::new(
                    r"(?P<reg>[a-z]{3}), qword ptr \[rip \+ (?P<addr>0x[0-9a-f]{1,8})\]$",
                )
                .unwrap();
                for match4 in re.captures_iter(ins.3.as_ref().unwrap()) {
                    let rip = ins.0 + ins.1 as u64;
                    if let Ok(dword) = self.get_dword(
                        rip + u64::from_str_radix(&match4["addr"][2..], 16)?,
                        disassembler,
                    ) {
                        registers.insert(match4["reg"].to_string(), rip + dword);
                        //LOGGER.debug("**moved value 0x%08x + 0x%08x == 0x%08x to register %s", rip, dword, rip + dword, match4.group("reg"))
                        if &match4["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    }
                }
            } else if ins.2.as_ref().unwrap() == "lea" {
                //# lea <reg>, dword ptr [<addr>]
                let re = regex::Regex::new(
                    r"(?P<reg>[a-z]{3}), dword ptr \[(?P<addr>0x[0-9a-f]{1,8})\]$",
                )
                .unwrap();
                for match1 in re.captures_iter(ins.3.as_ref().unwrap()) {
                    if let Ok(dword) =
                        self.get_dword(u64::from_str_radix(&match1["addr"][2..], 16)?, disassembler)
                    {
                        registers.insert(match1["reg"].to_string(), dword);
                        //LOGGER.debug("**moved value 0x%08x to register %s", dword, match1.group("reg"))
                        if &match1["reg"].to_string() == register_name {
                            abs_value_found = true;
                        }
                    }
                }
                //# not handled: lea <reg>, dword ptr [<reg> +- <val>]
                //# requires state-keeping of multiple registers
                //# there exist potentially many more way how the register being called can be calculated
            }
            //# for now we ignore them
            else {
            }
            //# if the absolute value was found for the call <reg> instruction, detect API
            if abs_value_found {
                analysis_state.set_leaf(false)?;
                if registers.contains_key(register_name) {
                    let candidate = registers[register_name];
                    //LOGGER.debug("candidate: 0x%x - %s, register: %s", candidate, ins[3], register_name)
                    let (dll, api) = disassembler.resolve_api(candidate, candidate)?;
                    if dll != None || api != None {
                        //LOGGER.debug("successfully resolved: %s %s", dll, api)
                        let mut api_entry = ApiEntry {
                            referencing_addr: HashSet::new(),
                            dll_name: dll,
                            api_name: api,
                        };
                        if disassembler.disassembly.apis.contains_key(&candidate) {
                            api_entry = disassembler.disassembly.apis[&candidate].clone();
                        }
                        if !api_entry.referencing_addr.contains(&current_calling_addr) {
                            api_entry.referencing_addr.insert(current_calling_addr);
                        }
                        api_e.push((candidate, api_entry));
                    } else if disassembler
                        .disassembly
                        .is_addr_within_memory_image(candidate)?
                    {
                        //LOGGER.debug("successfully resolved: 0x%x", candidate)
                        cand_e.push((candidate, current_calling_addr));
                    } else {
                        //LOGGER.debug("candidate not resolved")
                    }
                } else {
                    //LOGGER.debug("no candidate to resolved")
                }
                return Ok(true);
            }
        }
        //# process previous blocks
        if depth >= 0 {
            let mut l = HashSet::new();
            for block in processed.iter() {
                for ins in block {
                    l.insert(ins.0);
                }
            }
            let mut refs_in = vec![];
            for (fr, to) in &analysis_state.code_refs {
                for block in processed.iter() {
                    if to == &block[0].0 && !l.contains(fr) {
                        refs_in.push(fr);
                    }
                }
            }
            //LOGGER.debug("start processing previous blocks")
            let mut bb = vec![];
            for i in refs_in {
                if let Ok(b) = self.search_block(analysis_state, i) {
                    bb.push(b);
                }
            }
            for b in bb {
                if self.process_block(
                    analysis_state,
                    b,
                    registers,
                    register_name,
                    processed,
                    depth - 1,
                    current_calling_addr,
                    disassembler,
                    api_e,
                    cand_e,
                )? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn get_dword(&self, addr: u64, disassembler: &Disassembler) -> Result<u64> {
        if !disassembler.disassembly.is_addr_within_memory_image(addr)? {
            return Err(Error::LogicError(file!(), line!()));
        }
        let extracted_dword: &[u8; 4] = &disassembler.disassembly.get_bytes(addr, 4)?.try_into()?;
        Ok(u32::from_le_bytes(*extracted_dword) as u64)
    }
}
