use crate::{
    error::Error, function_candidate::FunctionCandidate, DisassemblyResult, FunctionAnalysisState,
    Result,
};
use capstone::prelude::*;
use itertools::Itertools;
use regex::bytes::Regex;
use std::{collections::HashMap, convert::TryInto};

const DEFAULT_PROLOGUES: &'static [&'static str; 4] = &[
    r"(?-u)\x8B\xFF\x55\x8B\xEC",
    r"(?-u)\x89\xFF\x55\x8B\xEC",
    r"(?-u)\x55\x8B\xEC",
    r"(?-u)\x55\x89\xE5",
];

#[derive(Debug)]
struct GapSequences {
    gs: HashMap<usize, Vec<Vec<u8>>>,
}

impl GapSequences {
    pub fn new() -> GapSequences {
        let mut gs = GapSequences { gs: HashMap::new() };
        gs.gs.insert(
            1,
            vec![
                b"\x90".to_vec(), //NOP1_OVERRIDE_NOP - AMD / nop - INTEL
                b"\xCC".to_vec(), //int3
                b"\x00".to_vec(), //pass over sequences of null bytes
            ],
        );
        gs.gs.insert(
            2,
            vec![
                b"\x66\x90".to_vec(), //NOP2_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8b\xc0".to_vec(),
                b"\x8b\xff".to_vec(), //mov edi, edi
                b"\x8d\x00".to_vec(), //lea eax, dword ptr [eax]
                b"\x86\xc0".to_vec(), //xchg al, al
                b"\x66\x2e".to_vec(), //NOP2_OVERRIDE_NOP - AMD / nop - INTEL
            ],
        );
        gs.gs.insert(
            3,
            vec![
                b"\x0f\x1f\x00".to_vec(), // NOP3_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8d\x40\x00".to_vec(), // lea eax, dword ptr [eax]
                b"\x8d\x00\x00".to_vec(), // lea eax, dword ptr [eax]
                b"\x8d\x49\x00".to_vec(), // lea ecx, dword ptr [ecx]
                b"\x8d\x64\x24".to_vec(), // lea esp, dword ptr [esp]
                b"\x8d\x76\x00".to_vec(),
                b"\x66\x66\x90".to_vec(),
            ],
        );
        gs.gs.insert(
            4,
            vec![
                b"\x0f\x1f\x40\x00".to_vec(), // NOP4_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8d\x74\x26\x00".to_vec(),
                b"\x66\x66\x66\x90".to_vec(),
            ],
        );
        gs.gs.insert(
            5,
            vec![
                b"\x0f\x1f\x44\x00\x00".to_vec(), //NOP5_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x90\x8d\x74\x26\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            6,
            vec![
                b"\x66\x0f\x1f\x44\x00\x00".to_vec(), // NOP6_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x8d\xb6\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            7,
            vec![
                b"\x0f\x1f\x80\x00\x00\x00\x00".to_vec(), // NOP7_OVERRIDE_NOP - AMD / nop - INTEL,
                b"\x8d\xb4\x26\x00\x00\x00\x00".to_vec(),
                b"\x8D\xBC\x27\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            8,
            vec![
                b"\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP8_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x90\x8d\xb4\x26\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            9,
            vec![
                b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP9_OVERRIDE_NOP - AMD / nop - INTEL
                b"\x89\xf6\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            10,
            vec![
                b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP10_OVERRIDE_NOP - AMD
                b"\x8d\x76\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            11,
            vec![
                b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(), // NOP11_OVERRIDE_NOP - AMD
                b"\x8d\x74\x26\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            12,
            vec![
                b"\x8d\xb6\x00\x00\x00\x00\x8d\xbf\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            13,
            vec![
                b"\x8d\xb6\x00\x00\x00\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            14,
            vec![
                b"\x8d\xb4\x26\x00\x00\x00\x00\x8d\xbc\x27\x00\x00\x00\x00".to_vec(),
                b"\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec(),
            ],
        );
        gs.gs.insert(
            15,
            vec![b"\x66\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".to_vec()],
        );
        gs
    }
}

#[derive(Debug)]
pub struct FunctionCandidateManager {
    pub bitness: u32,
    cs: Option<Capstone>,
    identified_alignment: u32,
    code_areas: Vec<(u64, u64)>,
    all_call_refs: HashMap<u64, u64>,
    pub symbol_addresses: Vec<u64>,
    pub candidates: HashMap<u64, FunctionCandidate>,
    candidate_offsets: Vec<u64>,
    gs: GapSequences,
    candidate_queue: Vec<u64>,
    gap_pointer: u64,
    previously_analyzed_gap: u64,
    function_gaps: Vec<(u64, u64, u64)>,
}

impl FunctionCandidateManager {
    pub fn new() -> FunctionCandidateManager {
        FunctionCandidateManager {
            bitness: 0,
            cs: None,
            identified_alignment: 0,
            code_areas: vec![],
            all_call_refs: HashMap::new(),
            symbol_addresses: vec![],
            candidates: HashMap::<u64, FunctionCandidate>::new(),
            candidate_offsets: vec![],
            gs: GapSequences::new(),
            candidate_queue: vec![],
            gap_pointer: 0,
            previously_analyzed_gap: 0,
            function_gaps: vec![],
        }
    }

    pub fn init(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        self.bitness = disassembly.binary_info.bitness;
        self.cs = Some(
            Capstone::new()
                .x86()
                .mode(if self.bitness == 32 {
                    arch::x86::ArchMode::Mode32
                } else {
                    arch::x86::ArchMode::Mode64
                })
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| Error::CapstoneError(e))?,
        );
        self.identified_alignment = 0;
        self.code_areas = disassembly.binary_info.code_areas.clone();
        self.locate_candidates(disassembly)?;
        Ok(())
    }

    fn locate_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        self.locate_symbol_candidates(disassembly)?;
        self.locate_reference_candidates(disassembly)?;
        self.locate_prologue_candidates(disassembly)?;
        //       self.locateLangSpecCandidates()?;
        self.locate_stub_chain_candidates(disassembly)?;
        self.locate_exception_handler_candidates(disassembly)?;
        self.identified_alignment = self.identify_alignment()?;
        Ok(())
    }

    fn locate_symbol_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let s = self.symbol_addresses.clone();
        for symbol_addr in s {
            self.add_symbol_candidate(&symbol_addr, disassembly)?;
        }
        Ok(())
    }

    fn add_symbol_candidate(
        &mut self,
        addr: &u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(*addr))? {
            return Ok(false);
        }
        self.ensure_candidate(*addr, disassembly)?;
        if let Some(s) = self.candidates.get_mut(addr) {
            s.set_is_symbol(true)?;
            s.set_initial_candidate();
        }
        Ok(true)
    }

    fn identify_alignment(&self) -> Result<u32> {
        let mut identified_alignment = 0;
        //        if self.config.USE_ALIGNMENT:
        let mut num_candidates = 0;
        for (_addr, candidate) in &self.candidates {
            if candidate.call_ref_sources.len() > 1 {
                num_candidates += 1;
            }
        }
        let mut num_aligned_16_candidates = 0;
        for (_addr, candidate) in &self.candidates {
            if candidate.call_ref_sources.len() > 1 && candidate.alignment == 16 {
                num_aligned_16_candidates += 1;
            }
        }
        let mut num_aligned_4_candidates = 0;
        for (_addr, candidate) in &self.candidates {
            if candidate.call_ref_sources.len() > 1 && candidate.alignment == 4 {
                num_aligned_4_candidates += 1;
            }
        }
        if num_candidates > 0 {
            let alignment_16_ratio = 1.0 * num_aligned_16_candidates as f32 / num_candidates as f32;
            let alignment_4_ratio = 1.0 * num_aligned_4_candidates as f32 / num_candidates as f32;
            if num_candidates > 20 && alignment_4_ratio > 0.95 {
                identified_alignment = 4;
            }
            if num_candidates > 20 && alignment_16_ratio > 0.95 {
                identified_alignment = 16;
            }
        }
        Ok(identified_alignment)
    }

    fn locate_exception_handler_candidates(
        &mut self,
        disassembly: &DisassemblyResult,
    ) -> Result<()> {
        if self.bitness == 64 {
            for (section_name, section_va_start, section_va_end) in
                disassembly.binary_info.get_sections()?
            {
                if section_name == ".pdata" {
                    let rva_start = section_va_start - disassembly.binary_info.base_addr;
                    let rva_end = section_va_end - disassembly.binary_info.base_addr;
                    let mut offset = rva_start as usize;
                    while offset < rva_end as usize {
                        if offset + 4 <= rva_end as usize {
                            let packed_dword: &[u8; 4] =
                                &disassembly.binary_info.binary[offset..offset + 4].try_into()?;
                            let rva_function_candidate = u32::from_le_bytes(*packed_dword) as u64;
                            self.add_exception_candidate(
                                disassembly.binary_info.base_addr + rva_function_candidate,
                                disassembly,
                            )?;
                        } else {
                            break;
                        }
                        offset += 12;
                    }
                }
            }
        }
        Ok(())
    }

    fn locate_stub_chain_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let re = Regex::new(r"(?-u)(?P<block>(\xFF\x25[\S\s]{4}){2,})")?;
        for block in re.find_iter(&disassembly.binary_info.binary) {
            let re2 = Regex::new(r"(?-u)\xFF\x25(?P<function>[\S\s]{4})")?;
            for call_match in
                re2.find_iter(&disassembly.binary_info.binary[block.start()..block.end()])
            {
                let stub_addr = disassembly.binary_info.base_addr
                    + block.start() as u64
                    + call_match.start() as u64;
                if !self.passes_code_filter(Some(stub_addr))? {
                    continue;
                }
                if self.add_prologue_candidate(stub_addr & self.get_bitmask(), disassembly)? {
                    self.set_initial_candidate(stub_addr & self.get_bitmask())?;
                    self.candidates
                        .get_mut(&stub_addr)
                        .ok_or(Error::LogicError(file!(), line!()))?
                        .set_is_stub();
                }
            }
        }
        let re = Regex::new(r"(?-u)(?P<block>(\xFF\x25[\S\s]{4}\x68[\S\s]{4}\xE9[\S\s]{4}){2,})")?;
        for block in re.find_iter(&disassembly.binary_info.binary) {
            let re2 = Regex::new(r"(?-u)\xFF\x25(?P<function>[\S\s]{4})")?;
            for call_match in
                re2.find_iter(&disassembly.binary_info.binary[block.start()..block.end()])
            {
                let stub_addr = disassembly.binary_info.base_addr
                    + block.start() as u64
                    + call_match.start() as u64;
                if !self.passes_code_filter(Some(stub_addr))? {
                    continue;
                }
                if self.add_prologue_candidate(stub_addr & self.get_bitmask(), disassembly)? {
                    self.set_initial_candidate(stub_addr & self.get_bitmask())?;
                    self.candidates
                        .get_mut(&stub_addr)
                        .ok_or(Error::LogicError(file!(), line!()))?
                        .set_is_stub();
                    //                for offset in 0..10{
                    //                    disassembly.data_map.add(stub_addr + 6 + offset)
                    //                }
                }
            }
        }
        Ok(())
    }

    fn locate_prologue_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        for re_prologue in DEFAULT_PROLOGUES {
            let re = Regex::new(re_prologue)?;
            for prologue_match in re.find_iter(&disassembly.binary_info.binary) {
                if !self.passes_code_filter(Some(
                    disassembly.binary_info.base_addr + prologue_match.start() as u64,
                ))? {
                    continue;
                }
                self.add_prologue_candidate(
                    (disassembly.binary_info.base_addr + prologue_match.start() as u64)
                        & self.get_bitmask(),
                    disassembly,
                )?;
                self.set_initial_candidate(
                    (disassembly.binary_info.base_addr + prologue_match.start() as u64)
                        & self.get_bitmask(),
                )?;
            }
        }
        Ok(())
    }

    fn locate_reference_candidates(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let re = Regex::new(r"(?-u)\xE8").unwrap();
        let matches = re.find_iter(&disassembly.binary_info.binary);
        for call_match in matches {
            if !self.passes_code_filter(Some(
                disassembly.binary_info.base_addr + call_match.start() as u64,
            ))? {
                continue;
            }
            if disassembly.binary_info.binary.len() - call_match.start() > 5 {
                let packed_call: &[u8; 4] = &disassembly
                    .get_raw_bytes(call_match.start() as u64 + 1, 4)?
                    .try_into()?;
                let rel_call_offset = i32::from_le_bytes(*packed_call) as i64;
                if rel_call_offset == 0 {
                    continue;
                }
                let call_destination = ((disassembly.binary_info.base_addr as i64
                    + rel_call_offset
                    + call_match.start() as i64
                    + 5)
                    & self.get_bitmask() as i64) as u64;
                if disassembly.is_addr_within_memory_image(call_destination)? {
                    if self.add_reference_candidate(
                        call_destination as u64,
                        disassembly.binary_info.base_addr + call_match.start() as u64,
                        disassembly,
                    )? {
                        self.set_initial_candidate(call_destination as u64)?;
                    }
                }
            }
        }

        if self.bitness == 32 {
            let re = Regex::new(r"(?-u)\xFF\x25").unwrap();
            for call_match in re.find_iter(&disassembly.binary_info.binary) {
                let function_addr =
                    match self.resolve_pointer_reference(call_match.start() as u64, disassembly) {
                        Ok(f) => Some(f),
                        _ => None,
                    };
                if !self.passes_code_filter(function_addr)? {
                    continue;
                }
                let function_addr = function_addr.unwrap();
                if disassembly.is_addr_within_memory_image(function_addr)? {
                    if self.add_reference_candidate(
                        function_addr,
                        disassembly.binary_info.base_addr + call_match.start() as u64,
                        disassembly,
                    )? {
                        self.set_initial_candidate(function_addr)?;
                    }
                }
            }
            let re = Regex::new(r"(?-u)\xFF\x15").unwrap();
            for call_match in re.find_iter(&disassembly.binary_info.binary) {
                let function_addr =
                    match self.resolve_pointer_reference(call_match.start() as u64, disassembly) {
                        Ok(f) => Some(f),
                        _ => None,
                    };
                if !self.passes_code_filter(function_addr)? {
                    continue;
                }
                let function_addr = function_addr.unwrap();
                if disassembly.is_addr_within_memory_image(function_addr)? {
                    if self.add_reference_candidate(
                        function_addr,
                        disassembly.binary_info.base_addr + call_match.start() as u64,
                        disassembly,
                    )? {
                        self.set_initial_candidate(function_addr)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn resolve_pointer_reference(
        &self,
        offset: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<u64> {
        if self.bitness == 32 {
            let addr_block: &[u8; 4] = disassembly.get_raw_bytes(offset + 2, 4)?.try_into()?;
            let function_pointer = u32::from_le_bytes(*addr_block) as u64;
            return Ok(disassembly.dereference_dword(function_pointer)? as u64);
        }
        if self.bitness == 64 {
            let addr_block: &[u8; 4] = disassembly.get_raw_bytes(offset + 2, 4)?.try_into()?;
            let mut function_pointer = u32::from_le_bytes(*addr_block) as u64;
            if disassembly.get_raw_bytes(offset, 2)? == b"\xFF\x25" {
                function_pointer += offset + 7
            } else if disassembly.get_raw_bytes(offset, 2)? == b"\xFF\x15" {
                function_pointer += offset + 6;
            } else {
                return Err(Error::LogicError(file!(), line!()));
            }
            return Ok(disassembly.binary_info.base_addr + function_pointer);
        }
        return Err(Error::LogicError(file!(), line!()));
    }

    fn get_bitmask(&self) -> u64 {
        //        if self.bitness == 64{
        return 0xFFFFFFFFFFFFFFFF;
        //        }
        //        0xFFFFFFFF
    }

    fn passes_code_filter(&self, address: Option<u64>) -> Result<bool> {
        match address {
            Some(addr) => {
                for (start, end) in &self.code_areas {
                    if *start <= addr && *end > addr {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            _ => Ok(false),
        }
    }

    fn ensure_candidate(&mut self, addr: u64, disassembly: &DisassemblyResult) -> Result<bool> {
        if !self.candidates.contains_key(&addr) {
            self.candidates.insert(
                addr,
                FunctionCandidate::new(&disassembly.binary_info, addr)?,
            );
            return Ok(true);
        }
        Ok(true)
    }

    fn add_reference_candidate(
        &mut self,
        addr: u64,
        source_ref: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        if self.ensure_candidate(addr, disassembly)? {
            self.all_call_refs.insert(source_ref, addr);
        }
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .add_call_ref(source_ref)?;
        Ok(true)
    }

    fn add_prologue_candidate(
        &mut self,
        addr: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        self.ensure_candidate(addr, disassembly)?;
        Ok(true)
    }

    fn set_initial_candidate(&mut self, addr: u64) -> Result<()> {
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_initial_candidate();
        Ok(())
    }

    fn add_exception_candidate(
        &mut self,
        addr: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        self.ensure_candidate(addr, disassembly)?;
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_exception_handler();
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_initial_candidate();
        Ok(true)
    }

    pub fn get_queue(&self) -> Result<Vec<u64>> {
        let mut res = vec![];
        for (addr, _candidate) in &self.candidates {
            res.push(*addr);
        }
        Ok(res)
    }

    //    pub fn get_candidate(&self, addr: &u64) -> Result<&FunctionCandidate>{
    //        Ok(self.candidates.get(addr).ok_or(Error::LogicError(file!(), line!()))?)
    //    }

    pub fn get_function_start_candidates(&self) -> Result<Vec<u64>> {
        Ok(self.candidate_offsets.clone())
    }

    pub fn is_alignment_sequence(
        &self,
        instruction_sequence: &capstone::Instructions,
    ) -> Result<bool> {
        let mut is_alignment_sequence = false;
        if instruction_sequence.len() > 0 {
            let mut current_offset = instruction_sequence[0].address();
            for instruction in instruction_sequence.as_ref() {
                if self.gs.gs[&instruction.bytes().len()].contains(&instruction.bytes().to_vec()) {
                    current_offset += instruction.bytes().len() as u64;
                    if current_offset % 16 == 0 {
                        is_alignment_sequence = true;
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        Ok(is_alignment_sequence)
    }

    pub fn is_function_candidate(&self, addr: u64) -> Result<bool> {
        Ok(self.candidates.contains_key(&addr))
    }

    pub fn add_candidate(
        &mut self,
        addr: u64,
        is_gap: bool,                  /*False*/
        reference_source: Option<u64>, /*None*/
        disassembly: &DisassemblyResult,
    ) -> Result<()> {
        if !self.passes_code_filter(Some(addr))? {
            return Err(Error::LogicError(file!(), line!()));
        }
        self.ensure_candidate(addr, disassembly)?;
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_gap_candidate(is_gap)?;
        if let Some(reference_source) = reference_source {
            self.candidates
                .get_mut(&addr)
                .ok_or(Error::LogicError(file!(), line!()))?
                .add_call_ref(reference_source)?;
        }
        self.candidate_queue.push(addr);
        //        self.candidate_queue.update()?;
        Ok(())
    }

    pub fn update_analysis_aborted(&mut self, addr: &u64, reason: &str) -> Result<()> {
        //LOGGER.debug("function analysis of 0x%08x aborted: %s", addr, reason)
        if let Some(mm) = self.candidates.get_mut(addr) {
            mm.set_analysis_aborted(reason)?;
        }
        Ok(())
    }

    pub fn update_analysis_finished(&mut self, addr: &u64) -> Result<()> {
        //LOGGER.debug("function analysis of 0x%08x successfully completed.", addr)
        if let Some(mm) = self.candidates.get_mut(addr) {
            mm.set_analysis_completed()?;
        }
        Ok(())
    }

    pub fn update_candidates(&mut self, state: &FunctionAnalysisState) -> Result<()> {
        // if let Ok(_s) = std::env::var("HIGH_ACCURACY") {
        if let Ok(conflicts) = state.identify_call_conflicts(&self.all_call_refs) {
            for (candidate_addr, conflict) in conflicts {
                if let Some(c) = self.candidates.get_mut(&candidate_addr) {
                    c.remove_call_refs(conflict)?;
                }
            }

            // self.candidate_queue.update();
        }
        Ok(())
    }

    pub fn next_gap_candidate(
        &mut self,
        start_gap_pointer: Option<u64>,
        disassembly: &DisassemblyResult,
    ) -> Result<u64> {
        if let Some(s) = start_gap_pointer {
            self.gap_pointer = s;
        }
        if self.gap_pointer == 0 {
            self.init_gap_search(disassembly)?;
        }
        //LOGGER.debug("nextGapCandidate() finding new gap
        //candidate, current gap_ptr: 0x%08x", self.gap_pointer)
        loop {
            if disassembly.binary_info.base_addr + disassembly.binary_info.binary_size
                < self.gap_pointer
            {
                //LOGGER.debug("nextGapCandidate() gap_ptr: 0x%08x - finishing", self.gap_pointer)
                return Err(Error::LogicError(file!(), line!()));
            }
            let gap_offset = self.gap_pointer - disassembly.binary_info.base_addr;
            if gap_offset >= disassembly.binary_info.binary_size {
                return Err(Error::LogicError(file!(), line!()));
            }
            //compatibility with python2/3...
            let byte = disassembly.get_raw_byte(gap_offset)?;
            if self.gs.gs[&1].contains(&vec![byte]) {
                //LOGGER.debug("nextGapCandidate() found 0xCC / 0x00 - gap_ptr += 1: 0x%08x", self.gap_pointer)
                self.gap_pointer += 1;
                continue;
            }
            //try to find instructions that directly encode as NOP and
            // skip them
            let mut ins_buf = vec![];
            {
                let ins_bb = self
                    .cs
                    .as_ref()
                    .unwrap()
                    .disasm_all(&disassembly.get_raw_bytes(gap_offset, 15)?, gap_offset)
                    .map_err(|e| Error::CapstoneError(e))?;
                for ins in ins_bb.as_ref() {
                    ins_buf.push(ins);
                    break;
                }
                if ins_buf.len() > 0 {
                    //                i_address, i_size, i_mnemonic, i_op_str = ins.mnemonic()
                    if ins_buf[0].mnemonic() == Some("nop") {
                        //let nop_instruction = i_mnemonic + " " + i_op_str
                        //nop_length = i_size
                        //LOGGER.debug("nextGapCandidate() found nop instruction (%s) - gap_ptr += %d: 0x%08x", nop_instruction, nop_length, self.gap_pointer)
                        self.gap_pointer += ins_buf[0].bytes().len() as u64;
                        continue;
                    }
                }
                //# try to find effective NOPs and skip them.
                let mut found_multi_byte_nop = false;
                for gap_length in *self
                    .gs
                    .gs
                    .keys()
                    .max()
                    .ok_or(Error::LogicError(file!(), line!()))?
                    as u32..1
                {
                    if self.gs.gs[&(gap_length as usize)].contains(
                        &disassembly
                            .get_raw_bytes(gap_offset, gap_length as u64)?
                            .to_vec(),
                    ) {
                        //LOGGER.debug("nextGapCandidate() found %d byte effective nop - gap_ptr += %d: 0x%08x", gap_length, gap_length, self.gap_pointer)
                        self.gap_pointer += gap_length as u64;
                        found_multi_byte_nop = true;
                        break;
                    }
                }
                if found_multi_byte_nop {
                    continue;
                }
                //# we know this place from data already
                if disassembly.data_map.contains(&self.gap_pointer) {
                    //LOGGER.debug("nextGapCandidate() gap_ptr is already inside data map: 0x%08x", self.gap_pointer)
                    self.gap_pointer += 1;
                    continue;
                }
                if disassembly.code_map.contains_key(&self.gap_pointer) {
                    //LOGGER.debug("nextGapCandidate() gap_ptr is already inside code map: 0x%08x", self.gap_pointer)
                    self.gap_pointer = self.get_next_gap(false, disassembly)?;
                    continue;
                }
                //# we may have a candidate here
                //LOGGER.debug("nextGapCandidate() using 0x%08x as candidate", self.gap_pointer)
                let _start_byte = disassembly.get_raw_byte(gap_offset)?;
            }
            let has_common_prologue = true; //start_byte in
                                            // FunctionCandidate(self.gap_pointer, start_byte,
                                            // self.bitness).common_gap_starts[self.bitness]
            if self.previously_analyzed_gap == self.gap_pointer {
                //LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed", self.gap_pointer)
                self.gap_pointer = self.get_next_gap(true, disassembly)?;
            } else if !has_common_prologue {
                //LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x has no common prologue (0x%08x)", self.gap_pointer, ord(start_byte))
                self.gap_pointer = self.get_next_gap(true, disassembly)?;
            } else {
                self.previously_analyzed_gap = self.gap_pointer;
                self.add_gap_candidate(self.gap_pointer, disassembly)?;
                return Ok(self.gap_pointer);
            }
        }
    }

    pub fn get_next_gap(&self, dont_skip: bool, disassembly: &DisassemblyResult) -> Result<u64> {
        let mut next_gap = self.get_bitmask();
        for gap in &self.function_gaps {
            if gap.0 > self.gap_pointer {
                next_gap = gap.0;
                break;
            }
        }
        //LOGGER.debug("getNextGap(%s) for 0x%08x based on gap_map: 0x%08x", dont_skip, self.gap_pointer, next_gap)
        //# we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if dont_skip {
            if disassembly.code_map.contains_key(&self.gap_pointer) {
                let function = disassembly.ins2fn[&self.gap_pointer];
                if next_gap > disassembly.function_borders[&function].1 {
                    next_gap = disassembly.function_borders[&function].1;
                }
                //LOGGER.debug("getNextGap(%s) without skip => after checking versus code map: 0x%08x", dont_skip, next_gap)
            }
        }
        //LOGGER.debug("getNextGap(%s) final gap_ptr: 0x%08x", dont_skip, next_gap)
        Ok(next_gap)
    }

    pub fn add_tailcall_candidate(
        &mut self,
        addr: &u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(*addr))? {
            return Ok(false);
        }
        self.ensure_candidate(*addr, disassembly)?;
        self.candidates
            .get_mut(addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_tailcall_candidate(true)?;
        Ok(true)
    }

    pub fn get_aborted_candidates(&self) -> Result<Vec<u64>> {
        let mut aborted = vec![];
        for (addr, candidate) in &self.candidates {
            if candidate.analysis_aborted {
                aborted.push(*addr);
            }
        }
        Ok(aborted)
    }

    pub fn init_gap_search(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        if self.gap_pointer == 0 {
            //LOGGER.debug("initGapSearch()")
            self.gap_pointer = self.get_bitmask();
            self.update_function_gaps(disassembly)?;
            if self.function_gaps.len() > 0 {
                self.gap_pointer = self.function_gaps[0].0;
            }
        }
        //LOGGER.debug("initGapSearch() gaps are:")
        for _gap in &self.function_gaps {
            //LOGGER.debug("initGapSearch() 0x%08x - 0x%08x == %d",
            // gap[0], gap[1], gap[2])
        }
        Ok(())
    }

    pub fn add_gap_candidate(
        &mut self,
        addr: u64,
        disassembly: &DisassemblyResult,
    ) -> Result<bool> {
        if !self.passes_code_filter(Some(addr))? {
            return Ok(false);
        }
        self.ensure_candidate(addr, disassembly)?;
        self.candidates
            .get_mut(&addr)
            .ok_or(Error::LogicError(file!(), line!()))?
            .set_is_gap_candidate(true)?;
        Ok(true)
    }

    pub fn update_function_gaps(&mut self, disassembly: &DisassemblyResult) -> Result<()> {
        let mut gaps = vec![];
        let mut prev_ins = 0;
        let mut min_code = self.get_bitmask();
        let mut max_code = 0;
        for (f, _) in &disassembly.code_map {
            if min_code > *f {
                min_code = *f;
            }
            if max_code < *f {
                max_code = *f;
            }
        }
        for code_area in &self.code_areas {
            if code_area.0 < min_code && min_code < code_area.1 && min_code != code_area.0 {
                gaps.push((code_area.0, min_code, min_code - code_area.0));
            }
            if code_area.0 < max_code && max_code < code_area.1 && max_code != code_area.1 {
                gaps.push((max_code, code_area.1, code_area.1 - max_code));
            }
        }
        for (ins, _) in disassembly.code_map.iter().sorted() {
            if prev_ins != 0 {
                if ins - prev_ins > 1 {
                    gaps.push((prev_ins + 1, *ins, ins - prev_ins))
                }
            }
            prev_ins = *ins
        }
        self.function_gaps = gaps;
        Ok(())
    }
}
