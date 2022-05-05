use crate::Result;
use serde::{Deserialize, Serialize};

pub mod smda;
pub mod dnfile;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FileFormat{
    PE,
    ELF,
    DOTNET
}

pub trait Instruction{
    fn is_mov_imm_to_stack(&self) -> Result<bool>;
    fn get_printable_len(&self) -> Result<u64>;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait Function{
    fn inrefs(&self) -> &Vec<u64>;
    fn blockrefs(&self) -> &std::collections::HashMap<u64, Vec<u64>>;
    fn offset(&self) -> u64;
    fn get_blocks(&self) -> Result<std::collections::HashMap<u64, Vec<Box<dyn Instruction>>>>;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait Extractor{
    fn get_base_address(&self) -> Result<u64>;
    fn format(&self) -> FileFormat;
    fn bitness(&self) -> u32;
    fn extract_global_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn get_functions(&self) -> Result<std::collections::HashMap<u64, Box<dyn Function>>>;
    fn extract_function_features(&self, f: &Box<dyn Function>) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn get_basic_blocks(&self, f: &Box<dyn Function>) -> Result<std::collections::HashMap<u64, Vec<Box<dyn Instruction>>>>;
    fn get_instructions<'a>(&self, f: &Box<dyn Function>, bb: &'a (&u64, &Vec<Box<dyn Instruction>>)) -> Result<&'a Vec<Box<dyn Instruction>>>;
    fn extract_basic_block_features(&self, f: &Box<dyn Function>, bb: &(&u64, &Vec<Box<dyn Instruction>>)) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn extract_insn_features(&self, f: &Box<dyn Function>, insn: &Box<dyn Instruction>) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn is_dot_net(&self) -> bool;
}
