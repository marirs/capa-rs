use crate::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct Instruction {
}

impl super::Instruction for Instruction{
    fn is_mov_imm_to_stack(&self) -> Result<bool>{
        unimplemented!()
    }
    fn get_printable_len(&self) -> Result<u64>{
        unimplemented!()
    }
    fn as_any(&self) -> &dyn std::any::Any{
        self
    }
}

#[derive(Debug, Clone)]
struct Function {
}

impl super::Function for Function{
    fn inrefs(&self) -> &Vec<u64>{
        unimplemented!()
    }
    fn blockrefs(&self) -> &HashMap<u64, Vec<u64>>{
        unimplemented!()
    }
    fn offset(&self) -> u64{
        unimplemented!()
    }

    fn get_blocks(&self) -> Result<HashMap<u64, Vec<Box<dyn super::Instruction>>>>{
        let mut res = HashMap::<u64, Vec<Box<dyn super::Instruction>>>::new();
        Ok(res)
    }
    fn as_any(&self) -> &dyn std::any::Any{
        self
    }
}

#[derive(Debug)]
struct Extractor<'a> {
    pe: dnfile::DnPe<'a>
}

impl super::Extractor for Extractor<'_>{
    fn get_base_address(&self) -> Result<u64>{
        Ok(0)
    }

    fn format(&self) -> super::FileFormat{
        super::FileFormat::PE
    }

    fn bitness(&self) -> u32{
        unimplemented!()
    }

    fn extract_global_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        Ok(vec![
            (
                crate::rules::features::Feature::Os(crate::rules::features::OsFeature::new(
                    &crate::consts::Os::WINDOWS.to_string(),
                    "",
                )?),
                0,
            ),
            (
                crate::rules::features::Feature::Arch(crate::rules::features::ArchFeature::new(
                    &self.extract_arch()?.to_string(),
                    "",
                )?),
                0,
            ),
        ])
    }

    fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        let mut ss = self.extract_file_import_names()?;
        ss.extend(self.extract_file_format()?);
        Ok(ss)
    }

    fn get_functions(&self) -> Result<std::collections::HashMap<u64, Box<dyn super::Function>>>{
        unimplemented!()
    }

    fn extract_function_features(&self, f: &Box<dyn super::Function>) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        unimplemented!()
    }

    fn get_basic_blocks(&self, f: &Box<dyn super::Function>) -> Result<std::collections::HashMap<u64, Vec<Box<dyn super::Instruction>>>>{
        unimplemented!()
    }

    fn get_instructions<'a>(&self, f: &Box<dyn super::Function>, bb: &'a (&u64, &Vec<Box<dyn super::Instruction>>)) -> Result<&'a Vec<Box<dyn super::Instruction>>>{
        unimplemented!()
    }

    fn extract_basic_block_features(&self, f: &Box<dyn super::Function>, bb: &(&u64, &Vec<Box<dyn super::Instruction>>)) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        unimplemented!()
    }

    fn extract_insn_features(&self, f: &Box<dyn super::Function>, insn: &Box<dyn super::Instruction>) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        unimplemented!()
    }
}

impl Extractor<'_>{
    pub fn new<'a>(file_path: &'a str, data: &'a [u8]) -> Result<Extractor<'a>>{
        let res = Extractor{
            pe: dnfile::DnPe::new(file_path, data)?
        };
        Ok(res)
    }

    pub fn extract_arch(&self) -> Result<crate::FileArchitecture> {
        if let Some(oh) = self.pe.pe.header.optional_header{
            if self.pe.net()?.flags.contains(&dnfile::ClrHeaderFlags::BitRequired32) && oh.standard_fields.magic == goblin::pe::optional_header::MAGIC_32{
                Ok(crate::FileArchitecture::I386)
            } else if !self.pe.net()?.flags.contains(&dnfile::ClrHeaderFlags::BitRequired32) && oh.standard_fields.magic == goblin::pe::optional_header::MAGIC_64{
                Ok(crate::FileArchitecture::AMD64)
            } else {
                Err(crate::Error::UnsupportedArchError)
            }
        } else {
            Err(crate::Error::UnsupportedArchError)
        }
    }

    pub fn extract_file_import_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        let mut res = vec![];
        for (token, imp) in self.get_dotnet_managed_imports()?.iter().chain(self.get_dotnet_unmanaged_imports()?.iter()){
            if imp.contains("::"){
                res.push((crate::rules::features::Feature::Import(crate::rules::features::ImportFeature::new(&imp, "")?), *token));
            } else {
                let ss = imp.split(".").collect::<Vec<&str>>();
                for symbol_variant in crate::extractor::smda::generate_symbols(&Some(ss[0].to_string()), &Some(ss[2].to_string()))?{
                    res.push((crate::rules::features::Feature::Import(crate::rules::features::ImportFeature::new(&symbol_variant, "")?), *token));
                }
            }
        }
        Ok(res)
    }

    pub fn get_dotnet_managed_imports(&self) -> Result<Vec<(u64, String)>>{
        let mut res = vec![];
        let memref = match self.pe.net()?.md_table("MemberRef"){
            Some(s) => s,
            None => return Ok(res)
        };
        let typeref = match self.pe.net()?.md_table("TypeRef"){
            Some(s) => s,
            None => return Ok(res)
        };
        for rid in 0..memref.row_count(){
            let row = memref.row::<dnfile::stream::meta_data_tables::mdtables::MemberRef>(rid)?;
            if row.class.table != "TypeRef"{
                continue;
            }
            let typeref_row = typeref.row::<dnfile::stream::meta_data_tables::mdtables::TypeRef>(row.class.row_index)?;
            let token = calculate_dotnet_token_value(dnfile::stream::meta_data_tables::mdtables::table_name_2_index("MemberRef")?, rid + 1);
            let imp = format!("{}.{}::{}", typeref_row.type_namespace, typeref_row.type_name, row.name);
            res.push((token, imp))
        }
        Ok(res)
    }

    pub fn get_dotnet_unmanaged_imports(&self) -> Result<Vec<(u64, String)>>{
        if not hasattr(pe.net.mdtables, "ImplMap"):
    return

        for row in pe.net.mdtables.ImplMap:
    dll: str = row.ImportScope.row.Name
        symbol: str = row.ImportName

                # ECMA says "Each row of the ImplMap table associates a row in the MethodDef table (MemberForwarded) with the
        # name of a routine (ImportName) in some unmanaged DLL (ImportScope)"; so we calculate and map the MemberForwarded
    # MethodDef table token to help us later record native import method calls made from CIL
    token: int = calculate_dotnet_token_value(row.MemberForwarded.table.number, row.MemberForwarded.row_index)

        # like Kernel32.dll
    if dll and "." in dll:
    dll = dll.split(".")[0]

        # like kernel32.CreateFileA
    imp: str = f"{dll}.{symbol}"

                yield token, imp
}

pub fn calculate_dotnet_token_value(table: usize, rid: usize) -> u64{
    unimplemented!()
//    return ((table & 0xFF) << Token.TABLE_SHIFT) | (rid & Token.RID_MASK)
}
