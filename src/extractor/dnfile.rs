use crate::Result;
use std::collections::HashMap;
use dnfile::{stream::meta_data_tables::mdtables::{*, codedindex::*},
             cil::cil::enums::*};

use crate::extractor::Extractor as BaseExtractor;

#[derive(Debug, Clone)]
struct Instruction {
    i: dnfile::cil::cil::instruction::Instruction
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
struct Function{
    f: dnfile::cil::cil::function::Function
}

impl super::Function for Function{
    fn inrefs(&self) -> &Vec<u64>{
        unimplemented!()
    }
    fn blockrefs(&self) -> &HashMap<u64, Vec<u64>>{
        unimplemented!()
    }
    fn offset(&self) -> u64{
        self.f.offset as u64
    }

    fn get_blocks(&self) -> Result<HashMap<u64, Vec<Box<dyn super::Instruction>>>>{
        let mut res = HashMap::<u64, Vec<Box<dyn super::Instruction>>>::new();
        let mut insts : Vec<Box<dyn super::Instruction>> = vec![];
        for i in &self.f.instructions{
            insts.push(Box::new(Instruction{i: i.clone()}));
        }
        res.insert(self.f.instructions[0].offset as u64, insts);
        Ok(res)
    }
    fn as_any(&self) -> &dyn std::any::Any{
        self
    }
}

#[derive(Debug)]
pub struct Extractor {
    pe: dnfile::DnPe
}

impl super::Extractor for Extractor{
    fn is_dot_net(&self) -> bool{
        true
    }

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
        let mut res : std::collections::HashMap<u64, Box<dyn super::Function>> = std::collections::HashMap::new();
        for f in self.pe.net()?.functions(){
            res.insert(f.offset as u64, Box::new(Function{f: f.clone()}));
        }
        Ok(res)
    }

    fn extract_function_features(&self, _f: &Box<dyn super::Function>) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        Ok(vec![])
    }

    fn get_basic_blocks(&self, f: &Box<dyn super::Function>) -> Result<std::collections::HashMap<u64, Vec<Box<dyn super::Instruction>>>>{
        f.get_blocks()
    }

    fn get_instructions<'a>(&self, _f: &Box<dyn super::Function>, bb: &'a (&u64, &Vec<Box<dyn super::Instruction>>)) -> Result<&'a Vec<Box<dyn super::Instruction>>>{
        Ok(bb.1)
    }

    fn extract_basic_block_features(&self, _f: &Box<dyn super::Function>, _bb: &(&u64, &Vec<Box<dyn super::Instruction>>)) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        Ok(vec![])
    }

    fn extract_insn_features(&self, f: &Box<dyn super::Function>, insn: &Box<dyn super::Instruction>) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        let f: &Function = f.as_any().downcast_ref::<Function>().unwrap();
        let insn: &Instruction = insn.as_any().downcast_ref::<Instruction>().unwrap();
        let mut ss = self.extract_insn_api_features(&f.f, &insn.i)?;
        ss.extend(self.extract_insn_number_features(&f.f, &insn.i)?);
        ss.extend(self.extract_insn_string_features(&f.f, &insn.i)?);
        Ok(ss)
    }
}

impl Extractor{
    pub fn new(file_path: &str) -> Result<Extractor>{
        let res = Extractor{
            pe: dnfile::DnPe::new(file_path)?
        };
        Ok(res)
    }

    pub fn extract_arch(&self) -> Result<crate::FileArchitecture> {
        if let Some(oh) = self.pe.pe()?.header.optional_header{
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

    pub fn extract_file_format(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        Ok(vec![(crate::rules::features::Feature::Os(crate::rules::features::OsFeature::new("dotnet", "")?), 0)])
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
        let memref = self.pe.net()?.md_table("MemberRef")?;
        let typeref = self.pe.net()?.md_table("TypeRef")?;
        for rid in 0..memref.row_count(){
            let row = memref.row::<MemberRef>(rid)?;
            if row.class.table != "TypeRef"{
                continue;
            }
            let typeref_row = typeref.row::<TypeRef>(row.class.row_index)?;
            let token = calculate_dotnet_token_value("MemberRef", rid + 1)?;
            let imp = format!("{}.{}::{}", typeref_row.type_namespace, typeref_row.type_name, row.name);
            res.push((token, imp))
        }
        Ok(res)
    }

    pub fn get_dotnet_unmanaged_imports(&self) -> Result<Vec<(u64, String)>>{
        let mut res = vec![];
        let implmap = self.pe.net()?.md_table("ImplMap")?;
        for rid in 0..implmap.row_count(){
            let row = implmap.row::<ImplMap>(rid)?;
            let import_scope = self.pe.net()?.resolve_coded_index::<MemberRef>(&row.import_scope)?;
            let mut dll = import_scope.name.clone();
            let symbol = row.import_name.clone();
            let token = calculate_dotnet_token_value(row.member_forwarded.table(), row.member_forwarded.row_index())?;
            if dll!="" && dll.contains('.'){
                dll = dll.split(".").collect::<Vec<&str>>()[0].to_string();
            }
            res.push((token, format!("{}.{}", dll, symbol)));
        }
        Ok(res)
    }

    pub fn extract_insn_api_features(&self, _f: &dnfile::cil::cil::function::Function, insn: &dnfile::cil::cil::instruction::Instruction) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        let mut res = vec![];
        if vec![OpCodeValue::Call, OpCodeValue::Callvirt, OpCodeValue::Jmp, OpCodeValue::Calli].contains(&insn.opcode.value){
            return Ok(vec![]);
        }
        let mut name = None;
        let managed_imports = self.get_dotnet_managed_imports()?;
        let unmanaged_imports = self.get_dotnet_unmanaged_imports()?;
        for (token, imp) in managed_imports.iter().chain(unmanaged_imports.iter()){
            if *token == insn.operand.value()? as u64{
                name = Some(imp);
            }
        }
        let name = match name{
            None => return Ok(vec![]),
            Some(s) => s
        };

        if name.contains("::"){
            res.push((crate::rules::features::Feature::Api(crate::rules::features::ApiFeature::new(&name, "")?), insn.offset as u64));
        } else {
            let ss = name.split(".").collect::<Vec<&str>>();
            for symbol_variant in crate::extractor::smda::generate_symbols(&Some(ss[0].to_string()), &Some(ss[2].to_string()))?{
                res.push((crate::rules::features::Feature::Api(crate::rules::features::ApiFeature::new(&symbol_variant, "")?), insn.offset as u64));
            }
        }
        Ok(res)
    }

    pub fn extract_insn_number_features(&self, _f: &dnfile::cil::cil::function::Function, insn: &dnfile::cil::cil::instruction::Instruction) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        let mut res = vec![];
        if insn.is_ldc(){
            res.push((crate::rules::features::Feature::Number(crate::rules::features::NumberFeature::new(self.bitness(), &(insn.get_ldc().unwrap() as i128), "")?), insn.offset as u64));
        }
        Ok(res)
    }

    pub fn extract_insn_string_features(&self, _f: &dnfile::cil::cil::function::Function, insn: &dnfile::cil::cil::instruction::Instruction) -> Result<Vec<(crate::rules::features::Feature, u64)>>{
        let mut res = vec![];
        if !insn.is_ldstr(){
            return Ok(res);
        }
        if let dnfile::cil::cil::instruction::Operand::StringToken(t) = &insn.operand{
            match self.pe.net()?.get_us(t.rid()){
                Err(_) => Ok(res),
                Ok(s) => {
                    res.push((crate::rules::features::Feature::String(crate::rules::features::StringFeature::new(&s, "")?), insn.offset as u64));
                    Ok(res)
                }
            }
        } else {
            Ok(res)
        }
    }
}

pub fn calculate_dotnet_token_value(table: &'static str, rid: usize) -> Result<u64>{
    let table_number = table_name_2_index(table)?;
    Ok((((table_number & 0xFF) << dnfile::cil::clr::token::TABLE_SHIFT) | (rid & dnfile::cil::clr::token::RID_MASK)) as u64)
}
