use crate::Result;
use dnfile::{
    lang::{
        cil::{self, enums::*},
        clr,
    },
    stream::meta_data_tables::mdtables::{codedindex::*, *},
    DnPe,
};
use std::collections::HashMap;

use crate::extractor::Extractor as BaseExtractor;

#[derive(Debug, Clone)]
struct Instruction {
    i: cil::instruction::Instruction,
}

impl super::Instruction for Instruction {
    fn is_mov_imm_to_stack(&self) -> Result<bool> {
        unimplemented!()
    }
    fn get_printable_len(&self) -> Result<u64> {
        unimplemented!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone)]
struct Function {
    f: cil::function::Function,
}

impl super::Function for Function {
    fn inrefs(&self) -> &Vec<u64> {
        unimplemented!()
    }
    fn blockrefs(&self) -> &HashMap<u64, Vec<u64>> {
        unimplemented!()
    }
    fn offset(&self) -> u64 {
        self.f.offset as u64
    }

    fn get_blocks(&self) -> Result<HashMap<u64, Vec<Box<dyn super::Instruction>>>> {
        let mut res = HashMap::<u64, Vec<Box<dyn super::Instruction>>>::new();
        let mut insts: Vec<Box<dyn super::Instruction>> = vec![];
        for i in &self.f.instructions {
            insts.push(Box::new(Instruction { i: i.clone() }));
        }
        res.insert(self.f.instructions[0].offset as u64, insts);
        Ok(res)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone)]
pub struct DnMethod {
    name: String,
    namespace: String,
    class_name: String,
    token: u64,
    access: Option<crate::rules::features::FeatureAccess>,
}

impl DnMethod {
    pub fn new(
        token: u64,
        namespace: &str,
        class_name: &str,
        method_name: &str,
        access: Option<crate::rules::features::FeatureAccess>,
    ) -> Self {
        Self {
            token,
            namespace: namespace.to_string(),
            class_name: class_name.to_string(),
            name: match method_name {
                ".ctor" => "ctor".to_string(),
                ".cctor" => "cctor".to_string(),
                _ => method_name.to_string(),
            },
            access,
        }
    }
}

impl std::fmt::Display for DnMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}::{}", self.namespace, self.class_name, self.name)
    }
}

enum Callee {
    Str(String),
    Method(DnMethod),
}

#[derive(Debug)]
pub struct Extractor {
    pe: DnPe,
}

impl super::Extractor for Extractor {
    fn is_dot_net(&self) -> bool {
        true
    }

    fn get_base_address(&self) -> Result<u64> {
        Ok(0)
    }

    fn format(&self) -> super::FileFormat {
        super::FileFormat::DOTNET
    }

    fn bitness(&self) -> u32 {
        match self.extract_arch() {
            Ok(crate::FileArchitecture::AMD64) => 64,
            _ => 32,
        }
    }

    fn extract_global_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
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

    fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut ss = self.extract_file_import_names()?;
        ss.extend(self.extract_file_function_names()?);
        //ss.extend(self.extract_file_string()?);
        ss.extend(self.extract_file_format()?);
        ss.extend(self.extract_file_mixed_mode_characteristic_features()?);
        ss.extend(self.extract_file_namespace_and_class_features()?);
        Ok(ss)
    }

    fn get_functions(&self) -> Result<std::collections::HashMap<u64, Box<dyn super::Function>>> {
        let mut res: std::collections::HashMap<u64, Box<dyn super::Function>> =
            std::collections::HashMap::new();
        for f in self.pe.net()?.functions() {
            res.insert(f.offset as u64, Box::new(Function { f: f.clone() }));
        }
        Ok(res)
    }

    fn extract_function_features(
        &self,
        _f: &Box<dyn super::Function>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        Ok(vec![])
    }

    fn get_basic_blocks(
        &self,
        f: &Box<dyn super::Function>,
    ) -> Result<std::collections::HashMap<u64, Vec<Box<dyn super::Instruction>>>> {
        f.get_blocks()
    }

    fn get_instructions<'a>(
        &self,
        _f: &Box<dyn super::Function>,
        bb: &'a (&u64, &Vec<Box<dyn super::Instruction>>),
    ) -> Result<&'a Vec<Box<dyn super::Instruction>>> {
        Ok(bb.1)
    }

    fn extract_basic_block_features(
        &self,
        _f: &Box<dyn super::Function>,
        _bb: &(&u64, &Vec<Box<dyn super::Instruction>>),
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        Ok(vec![])
    }

    fn extract_insn_features(
        &self,
        f: &Box<dyn super::Function>,
        insn: &Box<dyn super::Instruction>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let f: &Function = f.as_any().downcast_ref::<Function>().unwrap();
        let insn: &Instruction = insn.as_any().downcast_ref::<Instruction>().unwrap();
        let mut ss = self.extract_insn_api_features(&f.f, &insn.i)?;
        ss.extend(self.extract_insn_propery_features(&f.f, &insn.i)?);
        ss.extend(self.extract_insn_number_features(&f.f, &insn.i)?);
        ss.extend(self.extract_insn_string_features(&f.f, &insn.i)?);
        ss.extend(self.extract_insn_namespace_features(&f.f, &insn.i)?);
        ss.extend(self.extract_insn_class_features(&f.f, &insn.i)?);
        ss.extend(self.extract_unmanaged_call_characteristic_features(&f.f, &insn.i)?);
        Ok(ss)
    }
}

impl Extractor {
    pub fn new(file_path: &str) -> Result<Extractor> {
        let res = Extractor {
            pe: dnfile::DnPe::new(file_path)?,
        };
        Ok(res)
    }

    pub fn extract_arch(&self) -> Result<crate::FileArchitecture> {
        if let Some(oh) = self.pe.pe()?.header.optional_header {
            if self
                .pe
                .net()?
                .flags
                .contains(&dnfile::ClrHeaderFlags::BitRequired32)
                && oh.standard_fields.magic == goblin::pe::optional_header::MAGIC_32
            {
                Ok(crate::FileArchitecture::I386)
            } else {
                Ok(crate::FileArchitecture::AMD64)
            }
        } else {
            Err(crate::Error::UnsupportedArchError)
        }
    }

    pub fn extract_file_format(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        Ok(vec![(
            crate::rules::features::Feature::Os(crate::rules::features::OsFeature::new(
                "dotnet", "",
            )?),
            0,
        )])
    }

    pub fn extract_file_import_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (token, imp) in self
            .get_dotnet_managed_imports()?
            .iter()
            .chain(self.get_dotnet_unmanaged_imports()?.iter())
        {
            if imp.contains("::") {
                res.push((
                    crate::rules::features::Feature::Import(
                        crate::rules::features::ImportFeature::new(imp, "")?,
                    ),
                    *token,
                ));
            } else {
                let ss = imp.split('.').collect::<Vec<&str>>();
                for symbol_variant in crate::extractor::smda::generate_symbols(
                    &Some(ss[0].to_string()),
                    &Some(ss[1].to_string()),
                )? {
                    res.push((
                        crate::rules::features::Feature::Import(
                            crate::rules::features::ImportFeature::new(&symbol_variant, "")?,
                        ),
                        *token,
                    ));
                }
            }
        }
        Ok(res)
    }

    ///emit namespace features from TypeRef and TypeDef tables
    pub fn extract_file_namespace_and_class_features(
        &self,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        // namespaces may be referenced multiple times, so we need to filter
        let mut namespaces = std::collections::HashSet::new();
        let typedef = self.pe.net()?.md_table("TypeDef")?;
        for rid in 0..typedef.row_count() {
            let row = typedef.row::<TypeDef>(rid)?;
            namespaces.insert(row.type_namespace.clone());
            let token = calculate_dotnet_token_value("TypeDef", rid + 1)?;
            res.push((
                crate::rules::features::Feature::Class(crate::rules::features::ClassFeature::new(
                    &format!("{}.{}", row.type_namespace, row.type_name),
                    "",
                )?),
                token,
            ))
        }
        let typedef = self.pe.net()?.md_table("TypeRef")?;
        for rid in 0..typedef.row_count() {
            let row = typedef.row::<TypeRef>(rid)?;
            namespaces.insert(row.type_namespace.clone());
            let token = calculate_dotnet_token_value("TypeRef", rid + 1)?;
            res.push((
                crate::rules::features::Feature::Class(crate::rules::features::ClassFeature::new(
                    &format!("{}.{}", row.type_namespace, row.type_name),
                    "",
                )?),
                token,
            ))
        }
        for ns in namespaces {
            res.push((
                crate::rules::features::Feature::Namespace(
                    crate::rules::features::NamespaceFeature::new(&ns, "")?,
                ),
                0,
            ))
        }
        Ok(res)
    }

    pub fn extract_file_function_names(
        &self,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (_, method) in self.get_dotnet_managed_methods()? {
            res.push((
                crate::rules::features::Feature::FunctionName(
                    crate::rules::features::FunctionNameFeature::new(&method.to_string(), "")?,
                ),
                method.token,
            ));
        }
        Ok(res)
    }

    pub fn get_dotnet_managed_methods(&self) -> Result<HashMap<u64, DnMethod>> {
        let mut res = HashMap::new();
        let typedef = self.pe.net()?.md_table("TypeDef")?;
        for rid in 0..typedef.row_count() {
            let row = typedef.row::<TypeDef>(rid)?;
            for metdef in &row.method_list {
                let token = calculate_dotnet_token_value("MemberRef", rid + 1)?;
                res.insert(
                    token,
                    DnMethod::new(
                        token,
                        &row.type_namespace,
                        &row.type_name,
                        &self
                            .pe
                            .net()?
                            .resolve_coded_index::<MethodDef>(metdef)?
                            .name,
                        None,
                    ),
                );
            }
        }
        Ok(res)
    }

    pub fn get_dotnet_property_map(&self, property_row: &Property) -> Result<Option<TypeDef>> {
        let property_map = self.pe.net()?.md_table("PropertyMap")?;
        for rid in 0..property_map.row_count() {
            let row = property_map.row::<PropertyMap>(rid)?;
            for i in &row.property_list {
                if i.name == property_row.name {
                    return Ok(Some(
                        self.pe
                            .net()?
                            .resolve_coded_index::<TypeDef>(&row.parent)?
                            .clone(),
                    ));
                }
            }
        }
        Ok(None)
    }

    pub fn get_dotnet_properties(&self) -> Result<HashMap<u64, DnMethod>> {
        let mut res = HashMap::new();
        let method_semantics = if let Ok(s) = self.pe.net()?.md_table("MethodSemantics") {
            s
        } else {
            return Ok(res);
        };
        for rid in 0..method_semantics.row_count() {
            let row = method_semantics.row::<MethodSemantics>(rid)?;
            let typedef_row = match self.get_dotnet_property_map(
                self.pe
                    .net()?
                    .resolve_coded_index::<Property>(&row.association)?,
            )? {
                Some(s) => s,
                None => continue,
            };
            let token = calculate_dotnet_token_value("MethodSemantics", rid + 1)?;
            let access = if row
                .semantics
                .contains(&enums::ClrMethodSemanticsAttr::Setter)
            {
                Some(crate::rules::features::FeatureAccess::Write)
            } else if row
                .semantics
                .contains(&enums::ClrMethodSemanticsAttr::Getter)
            {
                Some(crate::rules::features::FeatureAccess::Read)
            } else {
                None
            };
            res.insert(
                token,
                DnMethod::new(
                    token,
                    &typedef_row.type_namespace,
                    &typedef_row.type_name,
                    &self
                        .pe
                        .net()?
                        .resolve_coded_index::<Property>(&row.association)?
                        .name,
                    access,
                ),
            );
        }
        Ok(res)
    }

    /// get fields from TypeDef table
    pub fn get_dotnet_fields(&self) -> Result<HashMap<u64, DnMethod>> {
        let mut res = HashMap::new();
        let type_defs = self.pe.net()?.md_table("TypeDef")?;
        for rid in 0..type_defs.row_count() {
            let row = type_defs.row::<TypeDef>(rid)?;
            for index in &row.field_list {
                let ss = self.pe.net()?.resolve_coded_index::<Field>(index)?;
                let token = calculate_dotnet_token_value("TypeDef", rid + 1)?;
                res.insert(
                    token,
                    DnMethod::new(token, &row.type_namespace, &row.type_name, &ss.name, None),
                );
            }
        }
        Ok(res)
    }

    pub fn get_dotnet_managed_imports(&self) -> Result<HashMap<u64, String>> {
        let mut res = HashMap::new();
        let memref = self.pe.net()?.md_table("MemberRef")?;
        let typeref = self.pe.net()?.md_table("TypeRef")?;
        for rid in 0..memref.row_count() {
            let row = memref.row::<MemberRef>(rid)?;
            if row.class.table != "TypeRef" {
                continue;
            }
            let typeref_row = typeref.row::<TypeRef>(row.class.row_index - 1)?;
            let token = calculate_dotnet_token_value("MemberRef", rid + 1)?;
            let imp = format!(
                "{}.{}::{}",
                typeref_row.type_namespace, typeref_row.type_name, row.name
            );
            res.insert(token, imp);
        }
        Ok(res)
    }

    pub fn get_dotnet_unmanaged_imports(&self) -> Result<HashMap<u64, String>> {
        let mut res = HashMap::new();
        if let Ok(implmap) = self.pe.net()?.md_table("ImplMap") {
            for rid in 0..implmap.row_count() {
                let row = implmap.row::<ImplMap>(rid)?;
                let import_scope = self
                    .pe
                    .net()?
                    .resolve_coded_index::<ModuleRef>(&row.import_scope)?;
                let mut dll = import_scope.name.clone();
                let symbol = row.import_name.clone();
                let token = calculate_dotnet_token_value(
                    row.member_forwarded.table(),
                    row.member_forwarded.row_index(),
                )?;
                if !dll.is_empty() && dll.contains('.') {
                    dll = dll.split('.').collect::<Vec<&str>>()[0].to_string();
                }
                res.insert(token, format!("{}.{}", dll, symbol));
            }
        }
        Ok(res)
    }

    pub fn extract_file_mixed_mode_characteristic_features(
        &self,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        if is_dotnet_mixed_mode(&self.pe)? {
            Ok(vec![(
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("mixed mode", "")?,
                ),
                0,
            )])
        } else {
            Ok(vec![])
        }
    }

    fn get_callee(&self, token: u64) -> Result<Option<Callee>> {
        // map dotnet token to un/managed method
        match self.get_dotnet_managed_imports()?.get(&token) {
            None => {
                // we must check unmanaged imports before managed methods because we map forwarded managed methods
                // to their unmanaged imports; we prefer a forwarded managed method be mapped to its unmanaged import for analysis
                match self.get_dotnet_unmanaged_imports()?.get(&token) {
                    None => match self.get_dotnet_managed_methods()?.get(&token) {
                        None => Ok(None),
                        Some(s) => Ok(Some(Callee::Method(s.clone()))),
                    },
                    Some(s) => Ok(Some(Callee::Str(s.clone()))),
                }
            }
            Some(s) => Ok(Some(Callee::Str(s.clone()))),
        }
    }

    pub fn extract_insn_api_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if !vec![
            OpCodeValue::Call,
            OpCodeValue::Callvirt,
            OpCodeValue::Jmp,
            OpCodeValue::Calli,
            OpCodeValue::Newobj,
        ]
        .contains(&insn.opcode.value)
        {
            return Ok(vec![]);
        }

        match self.get_callee(insn.operand.value()? as u64)? {
            None => {}
            Some(Callee::Str(s)) => {
                let ss = s.split('.').collect::<Vec<&str>>();
                for symbol_variant in crate::extractor::smda::generate_symbols(
                    &Some(ss[0].to_string()),
                    &Some(ss[1].to_string()),
                )? {
                    res.push((
                        crate::rules::features::Feature::Api(
                            crate::rules::features::ApiFeature::new(&symbol_variant, "")?,
                        ),
                        insn.offset as u64,
                    ));
                }
            }
            Some(Callee::Method(m)) => {
                if m.name.starts_with("get_") || m.name.starts_with("set_") {
                    let row = resolve_dotnet_token(
                        &self.pe,
                        &cil::instruction::Operand::Token(clr::token::Token::new(
                            insn.operand.value()?,
                        )),
                    )?;
                    if row.downcast_ref::<MethodDef>().is_some() {
                        if self
                            .get_dotnet_properties()?
                            .get(&(insn.operand.value()? as u64)).is_some()
                        {
                            return Ok(res);
                        }
                    } else if row.downcast_ref::<MemberRef>().is_some() {
                        return Ok(res);
                    }
                    res.push((
                        crate::rules::features::Feature::Api(
                            crate::rules::features::ApiFeature::new(&m.to_string(), "")?,
                        ),
                        insn.offset as u64,
                    ));
                }
            }
        }
        Ok(res)
    }

    /// parse instruction property features
    pub fn extract_insn_propery_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        if vec![
            OpCodeValue::Call,
            OpCodeValue::Callvirt,
            OpCodeValue::Jmp,
            OpCodeValue::Calli,
        ]
        .contains(&insn.opcode.value)
        {
            let operand = resolve_dotnet_token(
                &self.pe,
                &cil::instruction::Operand::Token(clr::token::Token::new(insn.operand.value()?)),
            )?;
            if let Some(_operand) = operand.downcast_ref::<MethodDef>() {
                // check if the method belongs to the MethodDef table and whether it is used to access a property
                if let Some(prop) = self
                    .get_dotnet_properties()?
                    .get(&(insn.operand.value()? as u64))
                {
                    return Ok(vec![(
                        crate::rules::features::Feature::Property(
                            crate::rules::features::PropertyFeature::new(
                                &prop.to_string(),
                                prop.access.clone(),
                                "",
                            )?,
                        ),
                        insn.offset as u64,
                    )]);
                }
            } else if let Some(operand) = operand.downcast_ref::<MemberRef>() {
                if !operand.name.starts_with("get_") && !operand.name.starts_with("set_") {
                    return Ok(vec![]);
                }
                // if the method belongs to the MemberRef table, we
                // assume it is used to access a property
                let (operand_class_type_namespace, operand_class_type_name) =
                    match operand.class.table() {
                        "TypeRef" => {
                            let rr = self
                                .pe
                                .net()?
                                .resolve_coded_index::<TypeRef>(&operand.class)?;
                            (rr.type_namespace.clone(), rr.type_name.clone())
                        }
                        "TypeDef" => {
                            let rr = self
                                .pe
                                .net()?
                                .resolve_coded_index::<TypeDef>(&operand.class)?;
                            (rr.type_namespace.clone(), rr.type_name.clone())
                        }
                        _ => {
                            return Ok(vec![]);
                        }
                    };
                return Ok(vec![(
                    crate::rules::features::Feature::Property(
                        crate::rules::features::PropertyFeature::new(
                            &format!(
                                "{}.{}::{}",
                                operand_class_type_namespace,
                                operand_class_type_name,
                                &operand.name[4..]
                            ),
                            if operand.name.starts_with("get_") {
                                Some(crate::rules::features::FeatureAccess::Read)
                            } else if operand.name.starts_with("set_") {
                                Some(crate::rules::features::FeatureAccess::Write)
                            } else {
                                None
                            },
                            "",
                        )?,
                    ),
                    insn.offset as u64,
                )]);
            }
        } else if vec![
            OpCodeValue::Ldfld,
            OpCodeValue::Ldflda,
            OpCodeValue::Ldsfld,
            OpCodeValue::Ldsflda,
        ]
        .contains(&insn.opcode.value)
        {
            let operand = resolve_dotnet_token(
                &self.pe,
                &cil::instruction::Operand::Token(clr::token::Token::new(insn.operand.value()?)),
            )?;
            if let Some(_operand) = operand.downcast_ref::<Field>() {
                // determine whether the operand is a field by checking if it belongs to the Field table
                if let Some(field) = self
                    .get_dotnet_fields()?
                    .get(&(insn.operand.value()? as u64))
                {
                    return Ok(vec![(
                        crate::rules::features::Feature::Property(
                            crate::rules::features::PropertyFeature::new(
                                &field.to_string(),
                                Some(crate::rules::features::FeatureAccess::Read),
                                "",
                            )?,
                        ),
                        insn.offset as u64,
                    )]);
                }
            }
        } else if vec![OpCodeValue::Stfld, OpCodeValue::Stsfld].contains(&insn.opcode.value) {
            let operand = resolve_dotnet_token(
                &self.pe,
                &cil::instruction::Operand::Token(clr::token::Token::new(insn.operand.value()?)),
            )?;
            if let Some(_operand) = operand.downcast_ref::<Field>() {
                // determine whether the operand is a field by checking if it belongs to the Field table
                if let Some(field) = self
                    .get_dotnet_fields()?
                    .get(&(insn.operand.value()? as u64))
                {
                    return Ok(vec![(
                        crate::rules::features::Feature::Property(
                            crate::rules::features::PropertyFeature::new(
                                &field.to_string(),
                                Some(crate::rules::features::FeatureAccess::Write),
                                "",
                            )?,
                        ),
                        insn.offset as u64,
                    )]);
                }
            }
        }
        Ok(vec![])
    }

    pub fn extract_insn_number_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if insn.is_ldc() {
            res.push((
                crate::rules::features::Feature::Number(
                    crate::rules::features::NumberFeature::new(
                        self.bitness(),
                        &(insn.get_ldc().unwrap() as i128),
                        "",
                    )?,
                ),
                insn.offset as u64,
            ));
        }
        Ok(res)
    }

    pub fn extract_insn_string_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if !insn.is_ldstr() {
            return Ok(res);
        }
        if let cil::instruction::Operand::StringToken(t) = &insn.operand {
            match self.pe.net()?.get_us(t.rid()) {
                Err(_) => Ok(res),
                Ok(s) => {
                    res.push((
                        crate::rules::features::Feature::String(
                            crate::rules::features::StringFeature::new(&s, "")?,
                        ),
                        insn.offset as u64,
                    ));
                    Ok(res)
                }
            }
        } else {
            Ok(res)
        }
    }

    ///parse instruction namespace features
    pub fn extract_insn_namespace_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        if !vec![
            OpCodeValue::Call,
            OpCodeValue::Callvirt,
            OpCodeValue::Jmp,
            OpCodeValue::Calli,
            OpCodeValue::Ldfld,
            OpCodeValue::Ldflda,
            OpCodeValue::Ldsfld,
            OpCodeValue::Ldsflda,
            OpCodeValue::Stfld,
            OpCodeValue::Stsfld,
            OpCodeValue::Newobj,
        ]
        .contains(&insn.opcode.value)
        {
            return Ok(vec![]);
        }
        let mut res = vec![];
        let operand = resolve_dotnet_token(
            &self.pe,
            &cil::instruction::Operand::Token(clr::token::Token::new(insn.operand.value()?)),
        )?;
        if let Some(s) = operand.downcast_ref::<MemberRef>() {
            if let Ok(ss) = &self.pe.net()?.resolve_coded_index::<TypeDef>(&s.class) {
                res.push((
                    crate::rules::features::Feature::Namespace(
                        crate::rules::features::NamespaceFeature::new(&ss.type_namespace, "")?,
                    ),
                    insn.offset as u64,
                ))
            } else if let Ok(ss) = &self.pe.net()?.resolve_coded_index::<TypeRef>(&s.class) {
                res.push((
                    crate::rules::features::Feature::Namespace(
                        crate::rules::features::NamespaceFeature::new(&ss.type_namespace, "")?,
                    ),
                    insn.offset as u64,
                ));
            }
        } else if operand.downcast_ref::<MethodDef>().is_some() {
            if let Some(Callee::Method(dm)) = self.get_callee(insn.operand.value()? as u64)? {
                res.push((
                    crate::rules::features::Feature::Namespace(
                        crate::rules::features::NamespaceFeature::new(&dm.namespace, "")?,
                    ),
                    insn.offset as u64,
                ));
            }
        } else if operand.downcast_ref::<Field>().is_some() {
            if let Some(field) = self
                .get_dotnet_fields()?
                .get(&(insn.operand.value()? as u64))
            {
                res.push((
                    crate::rules::features::Feature::Namespace(
                        crate::rules::features::NamespaceFeature::new(&field.namespace, "")?,
                    ),
                    insn.offset as u64,
                ));
            }
        }
        Ok(res)
    }

    ///parse instruction class features
    pub fn extract_insn_class_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        if !vec![
            OpCodeValue::Call,
            OpCodeValue::Callvirt,
            OpCodeValue::Jmp,
            OpCodeValue::Calli,
            OpCodeValue::Ldfld,
            OpCodeValue::Ldflda,
            OpCodeValue::Ldsfld,
            OpCodeValue::Ldsflda,
            OpCodeValue::Stfld,
            OpCodeValue::Stsfld,
            OpCodeValue::Newobj,
        ]
        .contains(&insn.opcode.value)
        {
            return Ok(vec![]);
        }
        let mut res = vec![];
        let operand = resolve_dotnet_token(
            &self.pe,
            &cil::instruction::Operand::Token(clr::token::Token::new(insn.operand.value()?)),
        )?;
        if let Some(s) = operand.downcast_ref::<MemberRef>() {
            if let Ok(ss) = &self.pe.net()?.resolve_coded_index::<TypeDef>(&s.class) {
                res.push((
                    crate::rules::features::Feature::Class(
                        crate::rules::features::ClassFeature::new(
                            &format!("{}.{}", ss.type_namespace, ss.type_name),
                            "",
                        )?,
                    ),
                    insn.offset as u64,
                ))
            } else if let Ok(ss) = &self.pe.net()?.resolve_coded_index::<TypeRef>(&s.class) {
                res.push((
                    crate::rules::features::Feature::Class(
                        crate::rules::features::ClassFeature::new(
                            &format!("{}.{}", ss.type_namespace, ss.type_name),
                            "",
                        )?,
                    ),
                    insn.offset as u64,
                ));
            }
        } else if operand.downcast_ref::<MethodDef>().is_some() {
            if let Some(Callee::Method(dm)) = self.get_callee(insn.operand.value()? as u64)? {
                res.push((
                    crate::rules::features::Feature::Class(
                        crate::rules::features::ClassFeature::new(
                            &format!("{}.{}", dm.namespace, dm.class_name),
                            "",
                        )?,
                    ),
                    insn.offset as u64,
                ));
            }
        } else if operand.downcast_ref::<Field>().is_some() {
            if let Some(field) = self
                .get_dotnet_fields()?
                .get(&(insn.operand.value()? as u64))
            {
                res.push((
                    crate::rules::features::Feature::Class(
                        crate::rules::features::ClassFeature::new(
                            &format!("{}.{}", field.namespace, field.class_name),
                            "",
                        )?,
                    ),
                    insn.offset as u64,
                ));
            }
        }
        Ok(res)
    }

    pub fn extract_unmanaged_call_characteristic_features(
        &self,
        _f: &cil::function::Function,
        insn: &cil::instruction::Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        if !vec![
            OpCodeValue::Call,
            OpCodeValue::Callvirt,
            OpCodeValue::Jmp,
            OpCodeValue::Calli,
        ]
        .contains(&insn.opcode.value)
        {
            return Ok(vec![]);
        }
        let mut res = vec![];
        let token = resolve_dotnet_token(&self.pe, &insn.operand)?;
        if let Some(s) = token.downcast_ref::<MethodDef>() {
            if s.flags.contains(&dnfile::stream::meta_data_tables::mdtables::enums::ClrMethodAttr::AttrFlag(dnfile::stream::meta_data_tables::mdtables::enums::CorMethodAttrFlag::PinvokeImpl))
                || s.impl_flags.contains(&dnfile::stream::meta_data_tables::mdtables::enums::ClrMethodImpl::MethodManaged(dnfile::stream::meta_data_tables::mdtables::enums::CorMethodManaged::Unmanaged))
                || s.impl_flags.contains(&dnfile::stream::meta_data_tables::mdtables::enums::ClrMethodImpl::MethodCodeType(dnfile::stream::meta_data_tables::mdtables::enums::CorMethodCodeType::Native)){
                res.push((crate::rules::features::Feature::Characteristic(crate::rules::features::CharacteristicFeature::new("unmanaged call", "")?),
                          insn.offset as u64,
                ));
            }
        }
        Ok(res)
    }
}

pub fn calculate_dotnet_token_value(table: &'static str, rid: usize) -> Result<u64> {
    let table_number = table_name_2_index(table)?;
    Ok((((table_number & 0xFF) << clr::token::TABLE_SHIFT) | (rid & clr::token::RID_MASK)) as u64)
}

pub fn is_dotnet_mixed_mode(pe: &dnfile::DnPe) -> Result<bool> {
    Ok(!pe.net()?.flags.contains(&dnfile::ClrHeaderFlags::IlOnly))
}

///map generic token to string or table row
pub fn resolve_dotnet_token<'a>(
    pe: &'a dnfile::DnPe,
    token: &cil::instruction::Operand,
) -> Result<&'a dyn std::any::Any> {
    //    if let cil::instruction::Operand::StringToken(t) = token{
    //        let user_string = read_dotnet_user_string(pe, t);
    //        if let Ok(s) = user_string{
    //            return Ok(s);
    //        } else {
    //            return Err(crate::Error::InvalidToken(format!("{:?}", token)));
    //        }
    //    }
    if let cil::instruction::Operand::Token(t) = token {
        let table = pe.net()?.md_table_by_index(&t.table())?;
        return Ok(table.get_row(t.rid() - 1)?.get_row().as_any());
    }
    Err(crate::Error::InvalidToken(format!("{:?}", token)))
}

///read user string from #US stream
pub fn _read_dotnet_user_string(pe: &dnfile::DnPe, token: &clr::token::Token) -> Result<String> {
    Ok(pe.net()?.metadata.get_us(token.rid())?)
}
