use crate::{Result, consts::FileFormat};

pub mod dnfile;
pub mod smda;

pub trait Instruction {
    fn is_mov_imm_to_stack(&self) -> Result<bool>;
    fn get_printable_len(&self) -> Result<u64>;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait Function {
    fn inrefs(&self) -> &Vec<u64>;
    fn blockrefs(&self) -> &std::collections::HashMap<u64, Vec<u64>>;
    fn offset(&self) -> u64;
    fn get_blocks(&self) -> Result<std::collections::BTreeMap<u64, Vec<Box<dyn Instruction>>>>;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait Extractor {
    // 0.4.0: `get_base_address` and `format` are only consumed by the
    // properties-feature-gated `FileCapabilities::new`. With
    // `--no-default-features` they'd warn as unused trait methods —
    // they're still part of the trait contract so downstream impls
    // need them, but cargo's reachability analysis can't see that.
    #[allow(dead_code)]
    fn get_base_address(&self) -> Result<u64>;
    #[allow(dead_code)]
    fn format(&self) -> FileFormat;
    fn bitness(&self) -> u32;
    fn extract_global_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn get_functions(&self) -> Result<std::collections::BTreeMap<u64, Box<dyn Function>>>;
    fn extract_function_features(
        &self,
        f: &Box<dyn Function>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn get_basic_blocks(
        &self,
        f: &Box<dyn Function>,
    ) -> Result<std::collections::BTreeMap<u64, Vec<Box<dyn Instruction>>>>;
    fn get_instructions<'a>(
        &self,
        f: &Box<dyn Function>,
        bb: &'a (&u64, &Vec<Box<dyn Instruction>>),
    ) -> Result<&'a Vec<Box<dyn Instruction>>>;
    fn extract_basic_block_features(
        &self,
        f: &Box<dyn Function>,
        bb: &(&u64, &Vec<Box<dyn Instruction>>),
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn extract_insn_features(
        &self,
        f: &Box<dyn Function>,
        insn: &Box<dyn Instruction>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>>;
    fn is_dot_net(&self) -> bool;
}
