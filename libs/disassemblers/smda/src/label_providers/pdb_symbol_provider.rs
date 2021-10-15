use crate::{BinaryInfo, Result};

#[derive(Debug)]
pub struct PdbSymbolProvider {
    func_symbols: std::collections::HashMap<u64, String>,
}

impl PdbSymbolProvider {
    pub fn new() -> Result<PdbSymbolProvider> {
        Ok(PdbSymbolProvider {
            func_symbols: std::collections::HashMap::new(),
        })
    }

    pub fn update(&mut self, binary_info: &BinaryInfo) -> Result<()> {
        match goblin::Object::parse(&binary_info.raw_data)? {
            goblin::Object::PE(pe) => {
                self.func_symbols.insert(
                    binary_info.base_addr + pe.entry as u64,
                    "original_entry_point".to_string(),
                );
            }
            _ => {}
        }
        Ok(())
    }

    pub fn get_functions_symbols(&self) -> Result<&std::collections::HashMap<u64, String>> {
        Ok(&self.func_symbols)
    }
}
