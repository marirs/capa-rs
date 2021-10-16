use crate::{label_provider::LabelProvider, Result};

pub mod elf_api_resolver;
pub mod win_api_resolver;
//mod elf_symbol_provider;
pub mod pdb_symbol_provider;

pub fn init() -> Result<Vec<LabelProvider>> {
    Ok(vec![
        LabelProvider::WinApi(win_api_resolver::WinApiResolver::new()?),
        LabelProvider::ElfApi(elf_api_resolver::ElfApiResolver::new()?),
        LabelProvider::PdbSymbol(pdb_symbol_provider::PdbSymbolProvider::new()?),
    ])
}

#[derive(Debug, Clone)]
pub struct ApiEntry {
    pub referencing_addr: std::collections::HashSet<u64>,
    pub dll_name: Option<String>,
    pub api_name: Option<String>,
}
