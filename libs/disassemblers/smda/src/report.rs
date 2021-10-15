use crate::{
    error::Error, function::Function, statistics::DisassemblyStatistics, DisassemblyResult,
    FileArchitecture, FileFormat, Result,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct DisassemblyReport {
    pub format: FileFormat,
    pub architecture: FileArchitecture,
    pub base_addr: u64,
    binary_size: u64,
    binweight: u32,
    pub bitness: u32,
    pub buffer: Vec<u8>,
    code_areas: Vec<(u64, u64)>,
    pub code_sections: Vec<(String, u64, u64)>,
    empty_section: (String, u64, u64),
    component: String,
    confidence_threshold: f32,
    family: String,
    filename: String,
    identified_alignment: usize,
    is_library: bool,
    is_buffer: bool,
    message: String,
    sha256: String,
    statistics: DisassemblyStatistics,
    functions: HashMap<u64, Function>,
    pub sections: Vec<(String, u64, usize)>,
    pub imports: Vec<(String, String, usize)>,
    pub exports: Vec<(String, usize)>,
}

impl DisassemblyReport {
    pub fn new(disassembly: &mut DisassemblyResult) -> Result<DisassemblyReport> {
        let mut res = DisassemblyReport {
            format: disassembly.binary_info.file_format.clone(),
            architecture: disassembly.binary_info.file_architecture.clone(),
            base_addr: disassembly.binary_info.base_addr,
            binary_size: disassembly.binary_info.binary_size,
            binweight: 0,
            bitness: disassembly.binary_info.bitness,
            buffer: disassembly.binary_info.binary.clone(),
            code_areas: disassembly.binary_info.code_areas.clone(),
            code_sections: disassembly.binary_info.get_sections()?.clone(),
            empty_section: ("".to_string(), 0, 0),
            component: disassembly.binary_info.component.clone(),
            confidence_threshold: disassembly.get_confidence_threshold()?,
            family: disassembly.binary_info.family.clone(),
            filename: disassembly.binary_info.file_path.clone(),
            identified_alignment: disassembly.identified_alignment,
            is_library: disassembly.binary_info.is_library,
            is_buffer: disassembly.binary_info.is_buffer,
            message: "Analysis finished regularly.".to_string(),
            sha256: disassembly.binary_info.sha256.clone(),
            statistics: DisassemblyStatistics::new(disassembly)?,
            functions: HashMap::new(),
            sections: disassembly.binary_info.sections.clone(),
            imports: disassembly.binary_info.imports.clone(),
            exports: disassembly.binary_info.exports.clone(),
        };
        for (function_offset, _) in &disassembly.functions {
            if res.confidence_threshold > 0.0
                && disassembly.candidates.contains_key(&function_offset)
                && disassembly.candidates[&function_offset].get_confidence()?
                    < res.confidence_threshold
            {
                continue;
            }
            let function = Function::new(disassembly, function_offset)?;
            res.binweight += function.binweight;
            res.functions.insert(function_offset.clone(), function);
        }
        Ok(res)
    }

    pub fn get_functions(&self) -> Result<&HashMap<u64, Function>> {
        Ok(&self.functions)
    }

    pub fn get_function(&self, function_addr: u64) -> Result<&Function> {
        match self.functions.get(&function_addr) {
            Some(f) => Ok(f),
            _ => Err(Error::InvalidRule(line!(), file!().to_string())),
        }
    }

    pub fn is_addr_within_memory_image(&self, offset: &u64) -> Result<bool> {
        Ok(&self.base_addr <= offset && offset < &(self.base_addr + self.binary_size))
    }

    pub fn get_section(&self, offset: &u64) -> Result<&(String, u64, u64)> {
        for section in &self.code_sections {
            if section.1 <= *offset && *offset < section.2 {
                return Ok(&section);
            }
        }
        Ok(&self.empty_section)
    }
}
