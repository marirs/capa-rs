#[macro_use]
extern crate maplit;

pub mod function;
mod function_analysis_state;
mod function_candidate;
mod function_candidate_manager;
mod indirect_call_analyser;
mod jump_table_analyser;
mod label_provider;
mod label_providers;
mod mnemonic_tf_idf;
mod pe;
pub mod report;
mod statistics;
mod tail_call_analyser;

use capstone::prelude::*;
use data_encoding::HEXUPPER;
use function_analysis_state::FunctionAnalysisState;
use function_candidate::FunctionCandidate;
use function_candidate_manager::FunctionCandidateManager;
use goblin::Object;
use indirect_call_analyser::IndirectCallAnalyser;
use jump_table_analyser::JumpTableAnalyser;
use label_provider::LabelProvider;
use mnemonic_tf_idf::MnemonicTfIdf;
use regex::bytes::Regex;
use report::DisassemblyReport;
use ring::digest::{Context, SHA256};
use serde::Serialize;
use std::{convert::TryInto, io::Read, time::SystemTime};
use tail_call_analyser::TailCallAnalyser;

mod error;
pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

static CALL_INS: &'static [Option<&str>] = &[Some("call"), Some("ncall")];
static CJMP_INS: &'static [Option<&str>] = &[
    Some("je"),
    Some("jne"),
    Some("js"),
    Some("jns"),
    Some("jp"),
    Some("jnp"),
    Some("jo"),
    Some("jno"),
    Some("jl"),
    Some("jle"),
    Some("jg"),
    Some("jge"),
    Some("jb"),
    Some("jbe"),
    Some("ja"),
    Some("jae"),
    Some("jcxz"),
    Some("jecxz"),
    Some("jrcxz"),
];
static LOOP_INS: &'static [Option<&str>] = &[Some("loop"), Some("loopne"), Some("loope")];
static JMP_INS: &'static [Option<&str>] = &[Some("jmp"), Some("ljmp")];
static RET_INS: &'static [Option<&str>] = &[Some("ret"), Some("retn"), Some("retf"), Some("iret")];
static END_INS: &'static [Option<&str>] = &[
    Some("ret"),
    Some("retn"),
    Some("retf"),
    Some("iret"),
    Some("int3"),
    Some("hlt"),
];
static REGS_32BIT: &'static [&str] = &["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
static REGS_64BIT: &'static [&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15",
];

#[derive(Debug, Clone, Copy, Serialize)]
pub enum FileFormat {
    ELF,
    PE,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum FileArchitecture {
    I386,
    AMD64,
}

impl std::fmt::Display for FileArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileArchitecture::I386 => write!(f, "i386"),
            FileArchitecture::AMD64 => write!(f, "amd64"),
        }
    }
}

#[derive(Debug)]
pub struct BinaryInfo {
    file_format: FileFormat,
    file_architecture: FileArchitecture,
    base_addr: u64,
    binary: Vec<u8>,
    raw_data: Vec<u8>,
    binary_size: u64,
    bitness: u32,
    code_areas: Vec<(u64, u64)>,
    component: String,
    family: String,
    file_path: String,
    is_library: bool,
    is_buffer: bool,
    sha256: String,
    entry_point: u64,
    sections: Vec<(String, u64, usize)>,
    imports: Vec<(String, String, usize)>,
    exports: Vec<(String, usize)>,
}

impl BinaryInfo {
    fn sha256_digest(content: &Vec<u8>) -> Result<String> {
        let mut context = Context::new(&SHA256);
        context.update(&content[..]);
        Ok(HEXUPPER.encode(context.finish().as_ref()))
    }

    pub fn new() -> BinaryInfo {
        BinaryInfo {
            file_format: FileFormat::ELF,
            file_architecture: FileArchitecture::I386,
            base_addr: 0,
            binary: vec![],
            raw_data: vec![],
            binary_size: 0,
            bitness: 32,
            code_areas: vec![],
            component: String::from(""),
            family: String::from(""),
            file_path: String::from(""),
            is_library: false,
            is_buffer: false,
            sha256: String::from(""),
            entry_point: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
        }
    }

    pub fn init(&mut self, content: &Vec<u8>) -> Result<()> {
        //        self.binary = content.to_vec();
        self.raw_data = content.to_vec();
        self.binary_size = content.len() as u64;
        self.sha256 = BinaryInfo::sha256_digest(content)?;
        Ok(())
    }

    pub fn get_sections(&self) -> Result<Vec<(String, u64, u64)>> {
        match Object::parse(&self.raw_data)? {
            Object::PE(pe) => {
                let mut res = vec![];
                for sect in pe.sections {
                    res.push((
                        std::str::from_utf8(&sect.name)?.to_string(),
                        sect.pointer_to_raw_data as u64,
                        (sect.pointer_to_raw_data + sect.size_of_raw_data) as u64,
                    ));
                }
                return Ok(res);
            }
            _ => Ok(vec![]),
        }
    }

    pub fn get_oep(&self) -> Result<u64> {
        match Object::parse(&self.raw_data)? {
            Object::PE(pe) => {
                return Ok(pe.entry as u64);
            }
            _ => Ok(0),
        }
    }
}

#[derive(Debug)]
pub struct DisassemblyResult {
    analysis_start_ts: SystemTime,
    analysis_end_ts: SystemTime,
    analysis_timeout: bool,
    binary_info: BinaryInfo,
    identified_alignment: usize,
    code_map: std::collections::HashMap<u64, u64>,
    data_map: std::collections::HashSet<u64>,
    //    errors:
    functions: std::collections::HashMap<
        u64,
        Vec<Vec<(u64, u32, Option<String>, Option<String>, Vec<u8>)>>,
    >,
    recursive_functions: std::collections::HashSet<u64>,
    leaf_functions: std::collections::HashSet<u64>,
    thunk_functions: std::collections::HashSet<u64>,
    failed_analysis_addr: Vec<u64>,
    function_borders: std::collections::HashMap<u64, (u64, u64)>,
    instructions: std::collections::HashMap<u64, (String, u32)>,
    ins2fn: std::collections::HashMap<u64, u64>,
    language: std::collections::HashMap<i32, Vec<u8>>,
    data_refs_from: std::collections::HashMap<u64, Vec<u64>>,
    data_refs_to: std::collections::HashMap<u64, Vec<u64>>,
    code_refs_from: std::collections::HashMap<u64, Vec<u64>>,
    code_refs_to: std::collections::HashMap<u64, Vec<u64>>,
    apis: std::collections::HashMap<u64, label_providers::ApiEntry>,
    addr_to_api: std::collections::HashMap<u64, (Option<String>, Option<String>)>,
    function_symbols: std::collections::HashMap<u64, String>,
    candidates: std::collections::HashMap<u64, FunctionCandidate>,
    confidence_threshold: f32,
    code_areas: Vec<u8>,
}

impl DisassemblyResult {
    pub fn get_all_api_refs(
        &mut self,
    ) -> Result<std::collections::HashMap<u64, (Option<String>, Option<String>)>> {
        if self.addr_to_api.len() == 0 {
            self.init_api_refs()?;
        }
        let mut all_api_refs = std::collections::HashMap::new();
        for (function_addr, _) in &self.functions {
            for (k, v) in self.get_api_refs(function_addr)? {
                all_api_refs.insert(k, v);
            }
        }
        Ok(all_api_refs)
    }

    pub fn get_api_refs(
        &self,
        func_addr: &u64,
    ) -> Result<std::collections::HashMap<u64, (Option<String>, Option<String>)>> {
        let mut api_refs = std::collections::HashMap::new();
        for block in &self.functions[&func_addr] {
            for ins in block {
                if self.addr_to_api.contains_key(&ins.0) {
                    api_refs.insert(ins.0, self.addr_to_api[&ins.0].clone());
                }
            }
        }
        Ok(api_refs)
    }

    fn init_api_refs(&mut self) -> Result<()> {
        for (api_offset, _) in &self.apis {
            let api = self.apis[&api_offset].clone();
            for reference in api.referencing_addr {
                self.addr_to_api
                    .insert(reference, (api.dll_name.clone(), api.api_name.clone()));
            }
        }
        Ok(())
    }

    pub fn get_confidence_threshold(&self) -> Result<f32> {
        Ok(self.confidence_threshold)
    }

    pub fn get_byte(&self, addr: u64) -> Result<u8> {
        if self.is_addr_within_memory_image(addr)? {
            return Ok(self.binary_info.binary[addr as usize - self.binary_info.base_addr as usize]);
        }
        Err(Error::LogicError(file!(), line!()))
    }

    pub fn get_raw_byte(&self, addr: u64) -> Result<u8> {
        Ok(self.binary_info.binary[addr as usize])
    }

    pub fn get_raw_bytes(&self, offset: u64, bytes: u64) -> Result<&[u8]> {
        Ok(&self.binary_info.binary[offset as usize..(offset + bytes) as usize])
    }

    pub fn get_bytes(&self, addr: u64, num_bytes: u64) -> Result<&[u8]> {
        if self.is_addr_within_memory_image(addr)? {
            let rel_start_addr = addr - self.binary_info.base_addr;
            return Ok(&self.binary_info.binary
                [rel_start_addr as usize..(rel_start_addr + num_bytes) as usize]);
        }
        Err(Error::NotEnoughBytesError(addr, num_bytes))
    }

    pub fn is_addr_within_memory_image(&self, offset: u64) -> Result<bool> {
        let res = self.binary_info.base_addr <= offset
            && offset < self.binary_info.base_addr + self.binary_info.binary_size;
        Ok(res)
    }

    pub fn dereference_dword(&self, addr: u64) -> Result<u64> {
        if self.is_addr_within_memory_image(addr)? {
            let rel_start_addr = addr - self.binary_info.base_addr;
            let rel_end_addr = rel_start_addr + 4;
            let extracted_dword: &[u8; 4] = &self.binary_info.binary
                [rel_start_addr as usize..rel_end_addr as usize]
                .try_into()?;
            return Ok(u32::from_le_bytes(*extracted_dword) as u64);
        }
        Err(Error::DereferenceError(addr))
    }

    pub fn dereference_qword(&self, addr: u64) -> Result<u64> {
        if self.is_addr_within_memory_image(addr)? {
            let rel_start_addr = addr - self.binary_info.base_addr;
            let rel_end_addr = rel_start_addr + 8;
            let extracted_dword: &[u8; 8] = &self.binary_info.binary
                [rel_start_addr as usize..rel_end_addr as usize]
                .try_into()?;
            return Ok(u64::from_le_bytes(*extracted_dword));
        }
        Err(Error::DereferenceError(addr))
    }

    pub fn new() -> DisassemblyResult {
        DisassemblyResult {
            analysis_start_ts: SystemTime::now(),
            analysis_end_ts: SystemTime::now(),
            analysis_timeout: false,
            binary_info: BinaryInfo::new(),
            identified_alignment: 0,
            code_map: std::collections::HashMap::new(),
            data_map: std::collections::HashSet::new(),
            functions: std::collections::HashMap::new(),
            recursive_functions: std::collections::HashSet::new(),
            leaf_functions: std::collections::HashSet::new(),
            thunk_functions: std::collections::HashSet::new(),
            failed_analysis_addr: vec![],
            function_borders: std::collections::HashMap::new(),
            instructions: std::collections::HashMap::new(),
            ins2fn: std::collections::HashMap::new(),
            language: std::collections::HashMap::new(),
            data_refs_from: std::collections::HashMap::new(),
            data_refs_to: std::collections::HashMap::new(),
            code_refs_from: std::collections::HashMap::new(),
            code_refs_to: std::collections::HashMap::new(),
            apis: std::collections::HashMap::new(),
            addr_to_api: std::collections::HashMap::new(),
            function_symbols: std::collections::HashMap::new(),
            candidates: std::collections::HashMap::new(),
            confidence_threshold: 0.0,
            code_areas: vec![],
        }
    }

    pub fn init(&mut self, bi: BinaryInfo) -> Result<()> {
        self.analysis_start_ts = SystemTime::now();
        self.analysis_end_ts = SystemTime::now();
        self.binary_info = bi;
        Ok(())
    }

    pub fn add_code_refs(&mut self, addr_from: u64, addr_to: u64) -> Result<()> {
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
        Ok(())
    }

    pub fn add_data_refs(&mut self, addr_from: u64, addr_to: u64) -> Result<()> {
        let mut refs_from = match self.data_refs_from.remove(&addr_from) {
            Some(v) => v,
            _ => vec![],
        };
        refs_from.push(addr_to);
        self.data_refs_from.insert(addr_from, refs_from);
        let mut refs_to = match self.data_refs_to.remove(&addr_to) {
            Some(v) => v,
            _ => vec![],
        };
        refs_to.push(addr_from);
        self.data_refs_to.insert(addr_to, refs_to.clone());
        Ok(())
    }

    pub fn get_blocks_as_dict(
        &self,
        function_addr: &u64,
    ) -> Result<std::collections::HashMap<u64, Vec<(u64, String, String, Option<String>)>>> {
        let mut blocks = std::collections::HashMap::new();
        for block in &self.functions[function_addr] {
            let mut instructions = vec![];
            for ins in block {
                instructions.push(self.transform_instruction(&ins)?);
                blocks.insert(instructions[0].0, instructions.clone());
            }
        }
        Ok(blocks)
    }

    pub fn transform_instruction(
        &self,
        ins_tuple: &(u64, u32, Option<String>, Option<String>, Vec<u8>),
    ) -> Result<(u64, String, String, Option<String>)> {
        let (ins_addr, _, ins_mnem, ins_ops, ins_raw_bytes) = ins_tuple;
        Ok((
            *ins_addr,
            hex::encode(ins_raw_bytes),
            ins_mnem.as_ref().unwrap().to_string(),
            ins_ops.clone(),
        ))
    }

    pub fn get_block_refs(
        &self,
        func_addr: &u64,
    ) -> Result<std::collections::HashMap<u64, Vec<u64>>> {
        let mut block_refs = std::collections::HashMap::new();
        let mut ins_addrs = std::collections::HashSet::new();
        for block in &self.functions[func_addr] {
            for ins in block {
                ins_addrs.insert(ins.0.clone());
            }
        }
        for block in &self.functions[func_addr] {
            let last_ins_addr = block[block.len() - 1].0;
            if self.code_refs_from.contains_key(&last_ins_addr) {
                let mut code_refs_from_a = std::collections::HashSet::new();
                for dd in &self.code_refs_from[&last_ins_addr] {
                    code_refs_from_a.insert(dd.clone());
                }
                let mut verified_refs = vec![];
                for dd in ins_addrs.intersection(&code_refs_from_a) {
                    verified_refs.push(dd.clone());
                }
                if verified_refs.len() > 0 {
                    block_refs.insert(block[0].0, verified_refs.clone());
                }
            }
        }
        return Ok(block_refs);
    }

    pub fn get_in_refs(&self, func_addr: &u64) -> Result<Vec<u64>> {
        if self.code_refs_to.contains_key(func_addr) {
            return Ok(self.code_refs_to[func_addr].clone());
        }
        Ok(vec![])
    }

    pub fn get_out_refs(
        &self,
        func_addr: &u64,
    ) -> Result<std::collections::HashMap<u64, Vec<u64>>> {
        let mut ins_addrs = std::collections::HashSet::new();
        let mut code_refs = vec![];
        let mut out_refs = std::collections::HashMap::new();
        for block in &self.functions[func_addr] {
            for ins in block {
                let ins_addr = ins.0.clone();
                ins_addrs.insert(ins_addr.clone());
                if self.code_refs_from.contains_key(&ins_addr) {
                    for to_addr in &self.code_refs_from[&ins_addr] {
                        code_refs.push((ins_addr, to_addr))
                    }
                }
            }
        }
        //# function may be recursive
        if ins_addrs.contains(func_addr) {
            ins_addrs.remove(func_addr);
        }
        //# reduce outrefs to addresses within the memory image
        let max_addr = self.binary_info.base_addr + self.binary_info.binary_size;
        let mut image_refs = vec![];
        for reff in code_refs {
            if &self.binary_info.base_addr <= reff.1 && reff.1 <= &max_addr {
                image_refs.push(reff.clone());
            }
        }
        for reff in image_refs {
            if ins_addrs.contains(&reff.1) {
                continue;
            }
            if !out_refs.contains_key(&reff.0) {
                out_refs.insert(reff.0, reff.1);
            }
        }
        let mut res: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
        for (src, dst) in &out_refs {
            match res.get_mut(src) {
                Some(s) => {
                    s.push(*dst.clone());
                }
                _ => {
                    res.insert(src.clone(), vec![*dst.clone()]);
                }
            }
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct Disassembler {
    common_start_bytes: std::collections::HashMap<u32, std::collections::HashMap<u8, u32>>,
    tailcall_analyzer: TailCallAnalyser,
    indirect_call_analyser: IndirectCallAnalyser,
    jumptable_analyzer: JumpTableAnalyser,
    fc_manager: FunctionCandidateManager,
    tfidf: MnemonicTfIdf,
    disassembly: DisassemblyResult,
    label_providers: Vec<LabelProvider>,
}

impl Disassembler {
    pub fn get_bitmask(&self) -> u64 {
        return 0xFFFFFFFFFFFFFFFF;
    }

    pub fn new() -> Result<Disassembler> {
        let mut res = Disassembler {
            common_start_bytes: std::collections::HashMap::new(),
            tailcall_analyzer: TailCallAnalyser::new(),
            indirect_call_analyser: IndirectCallAnalyser::new(),
            jumptable_analyzer: JumpTableAnalyser::new(),
            fc_manager: FunctionCandidateManager::new(),
            tfidf: MnemonicTfIdf::new(),
            disassembly: DisassemblyResult::new(),
            label_providers: label_providers::init()?,
        };
        res.common_start_bytes.insert(
            32,
            hashmap! {0x55 => 8334,
            0x6a => 758,
            0x56 => 756,
            0x51 => 312,
            0x8d => 566,
            0x83 => 558,
            0x53 => 548},
        );
        res.common_start_bytes.insert(
            64,
            hashmap! {0x48 => 1341,
            0x40 => 349,
            0x4c => 59,
            0x33 => 56,
            0x44 => 18,
            0x45 => 17,
            0xe9 => 16},
        );
        Ok(res)
    }

    pub fn load_file(file_name: &str) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(file_name)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        return Ok(data);
    }

    fn determine_bitness(&mut self) -> Result<u32> {
        let binary = &self.disassembly.binary_info.binary;
        let mut candidate_first_bytes: std::collections::HashMap<
            u32,
            std::collections::HashMap<u8, u32>,
        > = [
            (32, std::collections::HashMap::new()),
            (64, std::collections::HashMap::new()),
        ]
        .iter()
        .cloned()
        .collect();
        for bitness in vec![32, 64] {
            let re = Regex::new(r"(?-u)\xE8").unwrap();
            for call_match in re.find_iter(binary) {
                if binary.len() - call_match.start() > 5 {
                    let packed_call: &[u8; 4] =
                        &binary[call_match.start() + 1..call_match.start() + 5].try_into()?;
                    let rel_call_offset = i32::from_le_bytes(*packed_call);
                    let call_destination = rel_call_offset
                        .overflowing_add(call_match.start() as i32)
                        .0
                        .overflowing_add(5)
                        .0;
                    if call_destination > 0 && (call_destination as usize) < binary.len() {
                        let first_byte = binary[call_destination as usize];
                        if let Some(s) = candidate_first_bytes.get_mut(&bitness) {
                            if let Some(ss) = s.get_mut(&first_byte) {
                                *ss += 1;
                            } else {
                                s.insert(first_byte, 1);
                            }
                        }
                    }
                }
            }
        }
        let mut score: std::collections::HashMap<u32, f32> =
            [(32, 0.0), (64, 0.0)].iter().cloned().collect();
        for bitness in vec![32, 64] {
            for (candidate_sequence, _) in &candidate_first_bytes[&(bitness as u32)] {
                for (common_sequence, sequence_score) in &self.common_start_bytes[&(bitness as u32)]
                {
                    if candidate_sequence == common_sequence {
                        *score
                            .get_mut(&(bitness as u32))
                            .ok_or(Error::LogicError(file!(), line!()))? +=
                            *sequence_score as f32 * 1.0;
                    }
                }
            }
        }
        let total_score = std::cmp::max((score[&32] + score[&64]) as u32, 1);
        *score
            .get_mut(&32)
            .ok_or(Error::LogicError(file!(), line!()))? /= total_score as f32;
        *score
            .get_mut(&64)
            .ok_or(Error::LogicError(file!(), line!()))? /= total_score as f32;
        if score[&32] < score[&64] {
            Ok(64)
        } else {
            Ok(32)
        }
    }

    pub fn disassemble_file(file_name: &str, high_accuracy: bool) -> Result<DisassemblyReport> {
        let mut disassembler = Disassembler::new()?;
        let file_content = Disassembler::load_file(file_name)?;
        let mut binary_info = BinaryInfo::new();
        binary_info.init(&file_content)?;
        binary_info.file_path = file_name.to_string();
        match Object::parse(&file_content)? {
            Object::Elf(_elf) => {
                //                binary_info.base_addr = elf::getBaseAddress();
                //                binary_info.bitness = elf::getBitness();
                //                binary_info.code_areas = elf::getCodeAreas();
                //                binary_info.sections = pe.sections.iter().map(|s| (std::str::from_utf8(&s.name).unwrap().to_string(), s.virtual_address as u64, s.virtual_size as usize)).collect();
                //                binary_info.imports = pe.imports.iter().map(|s| (s.dll.to_string(), s.name.to_string())).collect();
            }
            Object::PE(pe) => {
                binary_info.file_format = FileFormat::PE;
                binary_info.base_addr = pe::get_base_address(&file_content)?;
                binary_info.bitness = pe::get_bitness(&file_content)?;
                binary_info.code_areas = pe::get_code_areas(&file_content, &pe)?;
                binary_info.sections = pe
                    .sections
                    .iter()
                    .map(|s| {
                        (
                            std::str::from_utf8(&s.name).unwrap().to_string(),
                            s.virtual_address as u64,
                            s.virtual_size as usize,
                        )
                    })
                    .collect();
                binary_info.imports = pe
                    .imports
                    .iter()
                    .map(|s| (s.dll.to_string(), s.name.to_string(), s.offset))
                    .collect();
                binary_info.exports = pe
                    .exports
                    .iter()
                    .map(|s| (s.name.unwrap_or("").to_string(), s.offset))
                    .collect();
                binary_info.binary = pe::map_binary(&binary_info.raw_data)?;
                binary_info.binary_size = binary_info.binary.len() as u64;
            }
            _ => return Err(Error::UnsupportedFormatError),
        }
        disassembler.analyse_buffer(binary_info, high_accuracy)?;
        let report = DisassemblyReport::new(&mut disassembler.disassembly)?;
        Ok(report)
    }

    fn get_symbol_candidates(&self) -> Result<Vec<u64>> {
        let mut symbol_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for provider in &self.label_providers {
            if !provider.is_symbol_provider()? {
                continue;
            }
            for (s, _a) in provider.get_functions_symbols()? {
                symbol_offsets.insert(*s);
            }
        }
        Ok(symbol_offsets.iter().map(|a| *a).collect())
    }

    pub fn analyse_buffer(
        &mut self,
        bin: BinaryInfo,
        high_accuracy: bool,
    ) -> Result<&DisassemblyResult> {
        //LOGGER.debug("Analyzing buffer with %d bytes @0x%08x",
        // binary_info.binary_size, binary_info.base_addr)
        self.update_label_providers(&bin)?;
        self.disassembly.init(bin)?;
        self.disassembly.binary_info.bitness = self.determine_bitness()?;
        self.tailcall_analyzer.init()?;
        self.indirect_call_analyser.init()?;
        self.jumptable_analyzer.init(&self.disassembly)?;
        self.fc_manager.symbol_addresses = self.get_symbol_candidates()?;
        self.fc_manager.init(&self.disassembly)?;
        self.tfidf.init(self.disassembly.binary_info.bitness)?;
        let queue = self.fc_manager.get_queue()?;
        let mut state = None;
        for addr in queue {
            state = match self.analyse_function(addr, false, high_accuracy) {
                Ok(s) => Some(s),
                Err(_) => None,
            }
        }
        //LOGGER.debug("Finished heuristical analysis, functions: %d", len(self.disassembly.functions))
        //# second pass, analyze remaining gaps for additional
        // candidates in an iterative way
        let mut next_gap = 0;
        while let Ok(gap_candidate) = self
            .fc_manager
            .next_gap_candidate(Some(next_gap), &self.disassembly)
        {
            //LOGGER.debug("based on gap, performing function analysis of 0x%08x", gap_candidate)
            state = match self.analyse_function(gap_candidate, true, high_accuracy) {
                Ok(s) => {
                    if let Ok(_function_blocks) = s.get_blocks() {
                        //LOGGER.debug("+ got some blocks here -> 0x%08x", gap_candidate)
                    }
                    Some(s)
                }
                Err(_) => None,
            };
            if self.disassembly.functions.contains_key(&gap_candidate) {
                //LOGGER.debug("+++ YAY, is now a function! -> 0x%08x - 0x%08x", fn_min, fn_max)
                //start looking directly after our new function
            } else {
                self.fc_manager.update_analysis_aborted(
                    &gap_candidate,
                    &format!("Gap candidate did not fulfil function criteria."),
                )?;
            }
            next_gap = self.fc_manager.get_next_gap(true, &self.disassembly)?;
        }
        //LOGGER.debug("Finished gap analysis, functions: %d", len(self.disassembly.functions))
        //third pass, fix potential tailcall functions that were identified during analysis
        if let Ok(_) = std::env::var("CAPARS_RESOLVE_TAILCALLS") {
            let tailcalled_functions =
                TailCallAnalyser::resolve_tailcalls(self, &mut state.unwrap(), high_accuracy)?;
            for addr in tailcalled_functions {
                self.fc_manager
                    .add_tailcall_candidate(&addr, &self.disassembly)?;
            }
            //LOGGER.debug("Finished tailcall analysis, functions.")
        }
        self.disassembly.failed_analysis_addr = self.fc_manager.get_aborted_candidates()?;
        //# package up and finish
        for (addr, candidate) in &mut self.fc_manager.candidates {
            if self.disassembly.functions.contains_key(&addr) {
                let function_blocks = self.disassembly.get_blocks_as_dict(&addr)?;
                let function_tfidf = self.tfidf.get_tfidf_from_blocks(&function_blocks)?;
                candidate.set_tfidf(function_tfidf)?;
                candidate.init_confidence()?;
            }
            self.disassembly.candidates.insert(*addr, candidate.clone());
        }
        Ok(&self.disassembly)
    }

    fn get_disasm_window_buffer(&self, addr: u64) -> Vec<u8> {
        let relative_start = addr - self.disassembly.binary_info.base_addr;
        let relative_end = relative_start + 15;
        if relative_start >= self.disassembly.binary_info.binary.len() as u64 {
            return vec![];
        }
        if relative_end >= self.disassembly.binary_info.binary.len() as u64 {
            return self.disassembly.binary_info.binary[relative_start as usize..].to_vec();
        }
        self.disassembly.binary_info.binary[relative_start as usize..relative_end as usize].to_vec()
    }

    fn handle_call_target(
        &self,
        from_addr: u64,
        to_addr: u64,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        if self.disassembly.is_addr_within_memory_image(to_addr)? {
            state.add_code_ref(from_addr, to_addr, false)?;
        }
        if state.start_addr == to_addr {
            state.set_recursion(true)?;
        }
        Ok(())
    }

    fn handle_api_target(
        &mut self,
        from_addr: u64,
        to_addr: u64,
        dereferenced: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        if to_addr != 0 {
            let (dll, api) = self.resolve_api(to_addr, dereferenced)?;
            if dll != None || api != None {
                self.update_api_information(from_addr, dereferenced, &dll, &api)?;
                return Ok((dll, api));
            } else if !self.disassembly.is_addr_within_memory_image(to_addr)? {
            }
        }
        Ok((None, None))
    }

    fn get_referenced_addr(&self, op_str: &str) -> Result<u64> {
        let re = Regex::new(r"(?-u)0x[a-fA-F0-9]+").unwrap();
        for referenced_addr in re.find_iter(op_str.as_bytes()) {
            let z =
                u64::from_str_radix(std::str::from_utf8(&referenced_addr.as_bytes()[2..])?, 16)?;
            return Ok(z);
        }
        Ok(0)
    }

    fn resolve_api(
        &self,
        to_address: u64,
        api_address: u64,
    ) -> Result<(Option<String>, Option<String>)> {
        for provider in &self.label_providers {
            if !provider.is_api_provider()? {
                continue;
            }
            return Ok(provider.get_api(to_address, api_address)?);
        }
        Ok((None, None))
    }

    fn analyze_call_instruction(
        &mut self,
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        let i_address = i.address();
        let i_size = i.bytes().len();
        let i_op_str = i.op_str(); //strip
        state.set_leaf(false)?;
        match i_op_str {
            Some(op_str) => {
                // case = "FALLTHROUGH"
                let call_destination = self.get_referenced_addr(op_str)?;
                if op_str != "" && i_op_str.as_ref().unwrap().contains(":") {
                    // case = "LONG-CALL"
                }
                if op_str.starts_with("dword ptr [") {
                    //# case = "DWORD-PTR-REG"
                    if op_str.starts_with("dword ptr [0x") {
                        //# case = "DWORD-PTR"
                        if let Ok(dereferenced) =
                            self.disassembly.dereference_dword(call_destination)
                        {
                            state.add_code_ref(i_address, dereferenced, false)?;
                            self.handle_call_target(i_address, dereferenced, state)?;
                            self.handle_api_target(i_address, call_destination, dereferenced)?;
                        }
                    }
                } else if op_str.starts_with("qword ptr [rip") {
                    let rip = i_address + i_size as u64;
                    let call_destination = rip + self.get_referenced_addr(op_str)?;
                    state.add_code_ref(i_address, call_destination, false)?;
                    if let Ok(dereferenced) = self.disassembly.dereference_qword(call_destination) {
                        self.handle_api_target(i_address, call_destination, dereferenced)?;
                    }
                } else if op_str.starts_with("0x") {
                    //# case = "DIRECT"
                    self.handle_call_target(i_address, call_destination, state)?;
                    self.handle_api_target(i_address, call_destination, call_destination)?;
                } else if REGS_32BIT.contains(&op_str.to_lowercase().as_str())
                    || REGS_64BIT.contains(&op_str.to_lowercase().as_str())
                {
                    //# case = "REG"
                    state.call_register_ins.push(i_address);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn analyze_jmp_instruction(
        &mut self,
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut tailcall_jumps = vec![];
        let i_address = i.address();
        let i_size = i.bytes().len();
        let _i_mnemonic = i.mnemonic();
        let i_op_str = match i.op_str() {
            Some(op_str) => op_str,
            None => "",
        };

        //case = "FALLTHROUGH"
        if i_op_str.contains(":") {
            //case = "LONG-JMP"
        } else if i_op_str.starts_with("dword ptr [0x") {
            //case = "DWORD-PTR"
            //Handles mostly jmp-to-api, stubs or tailcalls, all
            // should be handled sanely this way.
            let jump_destination = self.get_referenced_addr(i_op_str)?;
            state.add_code_ref(i_address, jump_destination, true)?;
            tailcall_jumps.push((i_address, jump_destination));
            if let Ok(dereferenced) = self.disassembly.dereference_dword(jump_destination) {
                self.handle_api_target(i_address, jump_destination, dereferenced)?;
            }
        } else if i_op_str.starts_with("qword ptr [rip") {
            //case = "QWORD-PTR, RIP-relative"
            //Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            let rip = i_address + i_size as u64;
            let jump_destination = rip + self.get_referenced_addr(i_op_str)?;
            state.add_code_ref(i_address, jump_destination, true)?;
            tailcall_jumps.push((i_address, jump_destination));
            if let Ok(dereferenced) = self.disassembly.dereference_qword(jump_destination) {
                self.handle_api_target(i_address, jump_destination, dereferenced)?;
            }
        } else if i_op_str.starts_with("0x") {
            let jump_destination = self.get_referenced_addr(i_op_str)?;
            tailcall_jumps.push((i_address, jump_destination));
            if self.disassembly.functions.contains_key(&jump_destination) {
                // case = "TAILCALL!"
                state.set_sanely_ending(true)?;
            } else if self
                .fc_manager
                .get_function_start_candidates()?
                .contains(&jump_destination)
            {
                // case = "TAILCALL?"
            } else {
                if state.is_first_instruction()? {
                    // case = "STUB-TAILCALL!"
                } else {
                    // case = "OFFSET-QUEUE"
                    state.add_block_to_queue(u64::from_str_radix(
                        std::str::from_utf8(&i_op_str.as_bytes()[2..])?,
                        16,
                    )?)?;
                }
                state.add_code_ref(
                    i_address,
                    u64::from_str_radix(std::str::from_utf8(&i_op_str.as_bytes()[2..])?, 16)?,
                    true,
                )?;
            }
        } else {
            let jumptable_targets = self.jumptable_analyzer.get_jump_targets(i, self, state)?;
            for target in jumptable_targets {
                if self.disassembly.is_addr_within_memory_image(target)? {
                    state.add_block_to_queue(target)?;
                    state.add_code_ref(i_address, target, true)?;
                }
            }
        }
        state.set_next_instruction_reachable(false)?;
        state.set_block_ending_instruction(true)?;
        Ok(tailcall_jumps)
    }

    pub fn analyze_loop_instruction(
        &self,
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<()> {
        let i_address = i.address();
        let i_size = i.bytes().len();
        let _i_mnemonic = i.mnemonic();
        let i_op_str = match i.op_str() {
            Some(op_str) => op_str,
            None => "",
        };
        if let Ok(_jump_destination) = self.get_referenced_addr(i_op_str) {
            state.add_code_ref(i_address, u64::from_str_radix(&i_op_str[2..], 16)?, true)?;
        }
        //# loops have two exits and should thus be handled as block ending instruction
        state.add_block_to_queue(i_address + i_size as u64)?;
        state.set_block_ending_instruction(true)?;
        Ok(())
    }

    pub fn analyze_cond_jmp_instruction(
        &self,
        i: &capstone::Insn,
        state: &mut FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut tailcall_jumps = vec![];
        let i_address = i.address();
        let i_size = i.bytes().len();
        let _i_mnemonic = i.mnemonic();
        let i_op_str = match i.op_str() {
            Some(op_str) => op_str,
            None => "",
        };
        state.add_block_to_queue(i_address + i_size as u64)?;
        if let Ok(jump_destination) = self.get_referenced_addr(i_op_str) {
            //# case = "FALLTHROUGH"
            tailcall_jumps.push((i_address, jump_destination));
            if self.disassembly.functions.contains_key(&jump_destination) {
                //# case = "TAILCALL!"
                state.set_sanely_ending(true)?;
            } else if self
                .fc_manager
                .get_function_start_candidates()?
                .contains(&jump_destination)
            {
                //# it's tough to decide whether this should be disassembled here or not. topic of "code-sharing functions".
                //# case = "TAILCALL?"
            } else {
                //# case = "OFFSET-QUEUE"
                state.add_block_to_queue(u64::from_str_radix(&i_op_str[2..], 16)?)?;
            }
            state.add_code_ref(i_address, u64::from_str_radix(&i_op_str[2..], 16)?, true)?;
        }
        state.set_block_ending_instruction(true)?;
        Ok(tailcall_jumps)
    }

    pub fn analyze_end_instruction(&self, state: &mut FunctionAnalysisState) -> Result<()> {
        state.set_sanely_ending(true)?;
        state.set_next_instruction_reachable(false)?;
        state.set_block_ending_instruction(true)?;
        Ok(())
    }

    fn analyse_function(
        &mut self,
        start_addr: u64,
        as_gap: bool,
        high_accuracy: bool,
    ) -> Result<FunctionAnalysisState> {
        self.tailcall_analyzer.init()?;
        let mut _i = 0;
        let mut state = FunctionAnalysisState::new(start_addr)?;
        if state.is_processed_function(&self.disassembly) {
            self.fc_manager.update_analysis_aborted(
                &start_addr,
                &format!(
                    "collision with existing code of function 0x{:08x}",
                    self.disassembly.ins2fn[&start_addr]
                ),
            )?;
            return Err(Error::CollisionError(self.disassembly.ins2fn[&start_addr]));
        }
        let capstone = Capstone::new()
            .x86()
            .mode(if self.fc_manager.bitness == 32 {
                arch::x86::ArchMode::Mode32
            } else {
                arch::x86::ArchMode::Mode64
            })
            .syntax(arch::x86::ArchSyntax::Intel)
            //            .detail(true)
            .build()
            .map_err(|e| Error::CapstoneError(e))?;
        while state.has_unprocessed_blocks() {
            state.choose_next_block()?;
            let mut cache_pos = 0;
            let start_block = state.block_start;
            let mut cache = capstone
                .disasm_all(
                    &self.get_disasm_window_buffer(state.block_start),
                    start_block,
                )
                .map_err(|e| Error::CapstoneError(e))?;
            let mut previous_address: Option<u64> = None;
            let mut previous_mnemonic: Option<String> = None;
            let mut previous_op_str: Option<String> = None;
            loop {
                let mut exit_flag = false;
                for i in cache.as_ref() {
                    let i_address = i.address();
                    let i_size = i.bytes().len();
                    let i_mnemonic = i.mnemonic();
                    let i_op_str = i.op_str(); //strip
                    let i_relative_address = i_address - self.disassembly.binary_info.base_addr;
                    let i_bytes = &self.disassembly.binary_info.binary
                        [i_relative_address as usize..i_relative_address as usize + i_size]
                        .to_vec();
                    //LOGGER.debug("  analyzeFunction() now processing instruction @0x%08x: %s", i_address, i_mnemonic + " " + i_op_str)
                    cache_pos += i_size;
                    state.set_next_instruction_reachable(true)?;
                    if i_bytes == b"\x00\x00" {
                        state.suspicious_ins_count += 1;
                        if state.suspicious_ins_count > 1 {
                            self.fc_manager.update_analysis_aborted(
                                &start_addr,
                                &format!("too many suspicious instructions 0x{:08x}", i_address),
                            )?;
                            return Ok(state);
                        }
                    }
                    if CALL_INS.contains(&i_mnemonic) {
                        self.analyze_call_instruction(i, &mut state)?;
                    } else if JMP_INS.contains(&i_mnemonic) {
                        let jumps = self.analyze_jmp_instruction(i, &mut state)?;
                        for j in jumps {
                            self.tailcall_analyzer.add_jump(j.0, j.1)?;
                        }
                    } else if LOOP_INS.contains(&i_mnemonic) {
                        self.analyze_loop_instruction(i, &mut state)?;
                    } else if CJMP_INS.contains(&i_mnemonic) {
                        let jumps = self.analyze_cond_jmp_instruction(i, &mut state)?;
                        for j in jumps {
                            self.tailcall_analyzer.add_jump(j.0, j.1)?;
                        }
                    } else if i_mnemonic.as_ref().unwrap().starts_with("j") {
                        //LOGGER.error("unsupported jump @0x%08x (0x%08x): %s %s", i_address, start_addr, i_mnemonic, i_op_str)
                    } else if RET_INS.contains(&i_mnemonic) {
                        self.analyze_end_instruction(&mut state)?;
                        if previous_address != None
                            && previous_address != Some(0)
                            && previous_mnemonic == Some("push".to_string())
                        {
                            let push_ret_destination =
                                self.get_referenced_addr(previous_op_str.as_ref().unwrap())?;
                            if self
                                .disassembly
                                .is_addr_within_memory_image(push_ret_destination)?
                            {
                                state.add_block_to_queue(push_ret_destination)?;
                                state.add_code_ref(i_address, push_ret_destination, true)?;
                            }
                        }
                    } else if [Some("int3"), Some("hlt")].contains(&i_mnemonic) {
                        self.analyze_end_instruction(&mut state)?;
                    } else if previous_address != None
                        && previous_address != Some(0)
                        && i_address != start_addr
                        && previous_mnemonic == Some("call".to_string())
                    {
                        let instruction_sequence = capstone
                            .disasm_all(&self.get_disasm_window_buffer(i_address), i_address)
                            .map_err(|e| Error::CapstoneError(e))?;
                        if self
                            .fc_manager
                            .is_alignment_sequence(&instruction_sequence)?
                            || self.fc_manager.is_function_candidate(i_address)?
                        {
                            state.set_block_ending_instruction(true)?;
                            state.end_block()?;
                            state.set_sanely_ending(true)?;
                            if self
                                .fc_manager
                                .is_alignment_sequence(&instruction_sequence)?
                            {
                                let next_aligned_address = previous_address.as_ref().unwrap()
                                    + (16 - previous_address.as_ref().unwrap() % 16);
                                self.fc_manager.add_candidate(
                                    next_aligned_address,
                                    true,
                                    None,
                                    &self.disassembly,
                                )?;
                                exit_flag = true;
                                break;
                            }
                        }
                    }
                    previous_address = Some(i_address);
                    previous_mnemonic = Some(i_mnemonic.as_ref().unwrap().to_string());
                    previous_op_str = Some(i_op_str.as_ref().unwrap().to_string());
                    if !self.disassembly.code_map.contains_key(&i_address)
                        && !self.disassembly.data_map.contains(&i_address)
                        && !state.is_processed(&i_address)?
                    {
                        state.add_instruction(
                            i_address,
                            i_size,
                            if let Some(m) = i_mnemonic {
                                Some(m.to_string())
                            } else {
                                None
                            },
                            if let Some(m) = i_op_str {
                                Some(m.to_string())
                            } else {
                                None
                            },
                            i_bytes.to_vec(),
                        )?;
                    } else if self.disassembly.code_map.contains_key(&i_address) {
                        state.set_block_ending_instruction(true)?;
                        state.set_collision(true)?;
                    } else {
                        state.set_block_ending_instruction(true)?;
                    }
                    if state.is_block_ending_instruction()? {
                        state.end_block()?;
                        exit_flag = true;
                        break;
                    }
                }
                if !exit_flag {
                    cache = capstone
                        .disasm_all(
                            &self.get_disasm_window_buffer(state.block_start + cache_pos as u64),
                            state.block_start + cache_pos as u64,
                        )
                        .map_err(|e| Error::CapstoneError(e))?;
                    if cache.len() == 0 {
                        break;
                    }
                    continue;
                } else {
                    break;
                }
            }
            if !state.is_block_ending_instruction()? {
                //LOGGER.debug("No block submitted, last instruction:
                // 0x%08x -> 0x%08x %s || %s", start_addr, i_address, i_mnemonic + " " + i_op_str, self.fc_manager.getFunctionCandidate(start_addr))
            }
        }
        state.label = self.resolve_symbol(state.start_addr)?;
        if let Ok(_analysis_result) = state.finalize_analysis(as_gap, &mut self.disassembly) {
            let (api_e, cand_e) = self
                .indirect_call_analyser
                .resolve_register_calls(self, &mut state, 3)?;
            for a in api_e {
                match self.disassembly.apis.get_mut(&a.0) {
                    Some(s) => {
                        s.referencing_addr.extend(a.1.referencing_addr.clone());
                    }
                    None => {
                        self.disassembly.apis.insert(a.0, a.1);
                    }
                }
            }
            for a in cand_e {
                self.fc_manager
                    .add_candidate(a.0, false, Some(a.1), &self.disassembly)?;
            }
            self.tailcall_analyzer.finalize_function(&state)?;
        }
        self.fc_manager.update_analysis_finished(&start_addr)?;
        if high_accuracy {
            self.fc_manager.update_candidates(&state)?;
        }
        Ok(state)
    }

    fn update_api_information(
        &mut self,
        from_addr: u64,
        to_addr: u64,
        dll: &Option<String>,
        api: &Option<String>,
    ) -> Result<()> {
        let mut api_entry = label_providers::ApiEntry {
            referencing_addr: std::collections::HashSet::new(),
            dll_name: dll.clone(),
            api_name: api.clone(),
        };
        if self.disassembly.apis.contains_key(&to_addr) {
            api_entry = self.disassembly.apis[&to_addr].clone();
        }
        if !api_entry.referencing_addr.contains(&from_addr) {
            api_entry.referencing_addr.insert(from_addr);
        }
        self.disassembly.apis.insert(to_addr, api_entry);
        Ok(())
    }

    pub fn resolve_symbol(&self, address: u64) -> Result<String> {
        for provider in &self.label_providers {
            if !provider.is_symbol_provider()? {
                continue;
            }
            if let Ok(result) = provider.get_symbol(address) {
                return Ok(result);
            }
        }
        Ok(String::from(""))
        //        Err(Error::LogicError(file!(), line!()))
    }

    fn update_label_providers(&mut self, bi: &BinaryInfo) -> Result<()> {
        for provider in &mut self.label_providers {
            provider.update(bi)?;
        }
        Ok(())
    }
}
