use crate::result::Result;

pub mod elf_api_resolver;
pub mod win_api_resolver;
//mod elf_symbol_provider;
pub mod pdb_symbol_provider;

use crate::disassembler::label_provider::LabelProvider;

pub fn init() -> Result<Vec<LabelProvider>> {
    let mut res = vec![];
    res.push(LabelProvider::WinApi(
        win_api_resolver::WinApiResolver::new()?,
    ));
    res.push(LabelProvider::ElfApi(
        elf_api_resolver::ElfApiResolver::new()?,
    ));
    //        self.label_providers.append(ElfSymbolProvider(self.config))
    res.push(LabelProvider::PdbSymbol(
        pdb_symbol_provider::PdbSymbolProvider::new()?,
    ));
    Ok(res)
}

#[derive(Debug, Clone)]
pub struct ApiEntry {
    pub referencing_addr: std::collections::HashSet<u64>,
    pub dll_name: Option<String>,
    pub api_name: Option<String>,
}
