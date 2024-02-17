use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
};

use crate::{rules::Value, Error, Result};

use super::{Scope, Scopes};

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum ComType {
    Class,
    Interface,
}

impl TryInto<ComType> for &str {
    type Error = Error;

    fn try_into(self) -> std::result::Result<ComType, Self::Error> {
        match self {
            "class" => Ok(ComType::Class),
            "interface" => Ok(ComType::Interface),
            _ => Err(Error::UndefinedComType(self.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum FeatureAccess {
    Read,
    Write,
}

#[derive(Debug)]
pub enum RuleFeatureType {
    PropretyRead,
    PropretyWrite,
    Api,
    StringFactory,
    String,
    Regex,
    Substring,
    Bytes,
    Number(u32),
    Offset(u32),
    Mnemonic,
    BasicBlock,
    Characteristic,
    Export,
    Import,
    Section,
    MatchedRule,
    FunctionName,
    Os,
    Format,
    Arch,
    Namespace,
    Class,
    OperandNumber(usize),
    OperandOffset(usize),
    ComType(ComType),
}

pub trait FeatureT {
    fn scopes(&self) -> &HashSet<Scope>;

    fn is_supported_in_scope(&self, scopes: &Scopes) -> Result<bool> {
        if self.scopes().contains(&scopes.r#static.scope) {
            return Ok(true);
        }
        if self.scopes().contains(&scopes.dynamic.scope) {
            return Ok(true);
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Feature {
    Property(PropertyFeature),
    Api(ApiFeature),
    String(StringFeature),
    Regex(RegexFeature),
    Substring(SubstringFeature),
    Bytes(BytesFeature),
    Number(NumberFeature),
    Offset(OffsetFeature),
    Mnemonic(MnemonicFeature),
    BasicBlock(BasicBlockFeature),
    Characteristic(CharacteristicFeature),
    Export(ExportFeature),
    Import(ImportFeature),
    Section(SectionFeature),
    MatchedRule(MatchedRuleFeature),
    FunctionName(FunctionNameFeature),
    Os(OsFeature),
    Format(FormatFeature),
    Arch(ArchFeature),
    Namespace(NamespaceFeature),
    Class(ClassFeature),
    OperandNumber(OperandNumberFeature),
    OperandOffset(OperandOffsetFeature),
}

impl Feature {
    pub fn new(t: RuleFeatureType, value: &Value, description: &str) -> Result<Feature> {
        // let readpro = "property/read".to_string();

        match t {
            RuleFeatureType::Api => Ok(Feature::Api(ApiFeature::new(
                &value.get_str()?,
                description,
            )?)),
            //            RuleFeatureType::Property => Ok(Feature::Property(PropertyFeature::new(
            //                &value.get_str()?,
            //                None,
            //                description,
            //            )?)),
            RuleFeatureType::PropretyRead => Ok(Feature::Property(PropertyFeature::new(
                &value.get_str()?,
                Some(FeatureAccess::Read),
                description,
            )?)),
            RuleFeatureType::PropretyWrite => Ok(Feature::Property(PropertyFeature::new(
                &value.get_str()?,
                Some(FeatureAccess::Write),
                description,
            )?)),
            RuleFeatureType::StringFactory => {
                let vv = value.get_str()?;
                if vv.starts_with('/') && (vv.ends_with('/') || vv.ends_with("/i")) {
                    Ok(Feature::Regex(RegexFeature::new(
                        &value.get_str()?,
                        description,
                    )?))
                } else {
                    Ok(Feature::String(StringFeature::new(
                        &value.get_str()?,
                        description,
                    )?))
                }
            }
            RuleFeatureType::String => Ok(Feature::String(StringFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Regex => Ok(Feature::Regex(RegexFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Substring => Ok(Feature::Substring(SubstringFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Bytes => Ok(Feature::Bytes(BytesFeature::new(
                &value.get_bytes()?,
                description,
            )?)),
            crate::rules::RuleFeatureType::Number(s) => Ok(Feature::Number(NumberFeature::new(
                s,
                &value.get_int()?,
                description,
            )?)),
            crate::rules::RuleFeatureType::Offset(s) => Ok(Feature::Offset(OffsetFeature::new(
                s,
                &value.get_int()?,
                description,
            )?)),
            RuleFeatureType::Mnemonic => Ok(Feature::Mnemonic(MnemonicFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::BasicBlock => Ok(Feature::BasicBlock(BasicBlockFeature::new()?)),
            crate::rules::RuleFeatureType::Characteristic => Ok(Feature::Characteristic(
                CharacteristicFeature::new(&value.get_str()?, description)?,
            )),
            RuleFeatureType::Export => Ok(Feature::Export(ExportFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Import => Ok(Feature::Import(ImportFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Section => Ok(Feature::Section(SectionFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::MatchedRule => Ok(Feature::MatchedRule(MatchedRuleFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::FunctionName => Ok(Feature::FunctionName(FunctionNameFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Os => Ok(Feature::Os(OsFeature::new(&value.get_str()?, description)?)),
            RuleFeatureType::Format => Ok(Feature::Format(FormatFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Arch => Ok(Feature::Arch(ArchFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Namespace => Ok(Feature::Namespace(NamespaceFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::Class => Ok(Feature::Class(ClassFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::OperandNumber(a) => Ok(Feature::OperandNumber(
                OperandNumberFeature::new(&a, &value.get_int()?, description)?,
            )),
            RuleFeatureType::OperandOffset(a) => Ok(Feature::OperandOffset(
                OperandOffsetFeature::new(&a, &value.get_int()? as &i128, description)?,
            )),
            RuleFeatureType::ComType(_ct) => {
                //TODO
                unimplemented!()
            }
        }
    }

    pub fn is_supported_in_scope(&self, scopes: &crate::rules::Scopes) -> Result<bool> {
        match self {
            Feature::Property(a) => a.is_supported_in_scope(scopes),
            Feature::Api(a) => a.is_supported_in_scope(scopes),
            Feature::Regex(a) => a.is_supported_in_scope(scopes),
            Feature::String(a) => a.is_supported_in_scope(scopes),
            Feature::Substring(a) => a.is_supported_in_scope(scopes),
            Feature::Bytes(a) => a.is_supported_in_scope(scopes),
            Feature::Number(a) => a.is_supported_in_scope(scopes),
            Feature::Offset(a) => a.is_supported_in_scope(scopes),
            Feature::Mnemonic(a) => a.is_supported_in_scope(scopes),
            Feature::BasicBlock(a) => a.is_supported_in_scope(scopes),
            Feature::Characteristic(a) => a.is_supported_in_scope(scopes),
            Feature::Export(a) => a.is_supported_in_scope(scopes),
            Feature::Import(a) => a.is_supported_in_scope(scopes),
            Feature::Section(a) => a.is_supported_in_scope(scopes),
            Feature::MatchedRule(a) => a.is_supported_in_scope(scopes),
            Feature::FunctionName(a) => a.is_supported_in_scope(scopes),
            Feature::Os(a) => a.is_supported_in_scope(scopes),
            Feature::Format(a) => a.is_supported_in_scope(scopes),
            Feature::Arch(a) => a.is_supported_in_scope(scopes),
            Feature::Namespace(a) => a.is_supported_in_scope(scopes),
            Feature::Class(a) => a.is_supported_in_scope(scopes),
            Feature::OperandNumber(a) => a.is_supported_in_scope(scopes),
            Feature::OperandOffset(a) => a.is_supported_in_scope(scopes),
        }
    }

    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        match self {
            Feature::Property(a) => a.evaluate(features),
            Feature::Api(a) => a.evaluate(features),
            Feature::String(a) => a.evaluate(features),
            Feature::Regex(a) => a.evaluate(features),
            Feature::Substring(a) => a.evaluate(features),
            Feature::Bytes(a) => a.evaluate(features),
            Feature::Number(a) => a.evaluate(features),
            Feature::Offset(a) => a.evaluate(features),
            Feature::Mnemonic(a) => a.evaluate(features),
            Feature::BasicBlock(a) => a.evaluate(features),
            Feature::Characteristic(a) => a.evaluate(features),
            Feature::Export(a) => a.evaluate(features),
            Feature::Import(a) => a.evaluate(features),
            Feature::Section(a) => a.evaluate(features),
            Feature::MatchedRule(a) => a.evaluate(features),
            Feature::FunctionName(a) => a.evaluate(features),
            Feature::Os(a) => a.evaluate(features),
            Feature::Format(a) => a.evaluate(features),
            Feature::Arch(a) => a.evaluate(features),
            Feature::Namespace(a) => a.evaluate(features),
            Feature::Class(a) => a.evaluate(features),
            Feature::OperandNumber(a) => a.evaluate(features),
            Feature::OperandOffset(a) => a.evaluate(features),
        }
    }

    pub fn get_value(&self) -> Result<String> {
        match self {
            Feature::Property(a) => Ok(a.value.clone()),
            Feature::Api(a) => Ok(a.value.clone()),
            Feature::String(a) => Ok(a.value.clone()),
            Feature::Regex(a) => Ok(a.value.clone()),
            Feature::Substring(a) => Ok(a.value.clone()),
            Feature::Bytes(a) => Ok(hex::encode(a.value.clone())),
            Feature::Number(a) => Ok(a.value.to_string()),
            Feature::Offset(a) => Ok(a.value.to_string()),
            Feature::Mnemonic(a) => Ok(a.value.clone()),
            Feature::BasicBlock(_) => Ok("".to_string()),
            Feature::Characteristic(a) => Ok(a.value.clone()),
            Feature::Export(a) => Ok(a.value.clone()),
            Feature::Import(a) => Ok(a.value.clone()),
            Feature::Section(a) => Ok(a.value.clone()),
            Feature::MatchedRule(a) => Ok(a.value.clone()),
            Feature::FunctionName(a) => Ok(a.value.clone()),
            Feature::Os(a) => Ok(a.value.clone()),
            Feature::Format(a) => Ok(a.value.clone()),
            Feature::Arch(a) => Ok(a.value.clone()),
            Feature::Namespace(a) => Ok(a.value.clone()),
            Feature::Class(a) => Ok(a.value.clone()),
            Feature::OperandNumber(a) => Ok(a.value.to_string()),
            Feature::OperandOffset(a) => Ok(a.value.to_string()),
        }
    }
    pub fn get_name(&self) -> String {
        match self {
            Feature::Property(_) => "PropertyFeature",
            Feature::Api(_) => "ApiFeature",
            Feature::String(_) => "StringFeature",
            Feature::Regex(_) => "RegexFeature",
            Feature::Substring(_) => "SubstringFeature",
            Feature::Bytes(_) => "BytesFeature",
            Feature::Number(_) => "NumberFeature",
            Feature::Offset(_) => "OffsetFeature",
            Feature::Mnemonic(_) => "MnemonicFeature",
            Feature::BasicBlock(_) => "BasicBlockFeature",
            Feature::Characteristic(_) => "CharacteristicFeature",
            Feature::Export(_) => "ExportFeature",
            Feature::Import(_) => "ImportFeature",
            Feature::Section(_) => "SectionFeature",
            Feature::MatchedRule(_) => "MatchedRuleFeature",
            Feature::FunctionName(_) => "FunctionNameFeature",
            Feature::Os(_) => "OsFeature",
            Feature::Format(_) => "FormatFeature",
            Feature::Arch(_) => "ArchFeature",
            Feature::Namespace(_) => "NamespaceFeature",
            Feature::Class(_) => "ClassFeature",
            Feature::OperandNumber(_) => "OperandNumberFeature",
            Feature::OperandOffset(_) => "OperandOffsetFeature",
        }
        .to_string()
    }
}

#[derive(Debug, Clone, Eq)]
pub struct FunctionNameFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for FunctionNameFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "function_name_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for FunctionNameFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for FunctionNameFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl FunctionNameFeature {
    pub fn new(value: &str, description: &str) -> Result<FunctionNameFeature> {
        Ok(FunctionNameFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::File),
        })
    }

    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::FunctionName(self.clone())) {
            return Ok((true, features[&Feature::FunctionName(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct SectionFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for SectionFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "section_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for SectionFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for SectionFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl SectionFeature {
    pub fn new(value: &str, description: &str) -> Result<SectionFeature> {
        Ok(SectionFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::File),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Section(self.clone())) {
            return Ok((true, features[&Feature::Section(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ImportFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for ImportFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "import_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for ImportFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for ImportFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl ImportFeature {
    pub fn new(value: &str, description: &str) -> Result<ImportFeature> {
        Ok(ImportFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::File),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Import(self.clone())) {
            return Ok((true, features[&Feature::Import(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ExportFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for ExportFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "export_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for ExportFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for ExportFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl ExportFeature {
    pub fn new(value: &str, description: &str) -> Result<ExportFeature> {
        Ok(ExportFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::File),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Export(self.clone())) {
            return Ok((true, features[&Feature::Export(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct BasicBlockFeature {
    scopes: HashSet<Scope>,
}

impl Hash for BasicBlockFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "basic_block_feature".hash(state);
    }
}

impl PartialEq for BasicBlockFeature {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl FeatureT for BasicBlockFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl BasicBlockFeature {
    pub fn new() -> Result<BasicBlockFeature> {
        Ok(BasicBlockFeature {
            scopes: maplit::hashset!(Scope::Function),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::BasicBlock(self.clone())) {
            return Ok((true, features[&Feature::BasicBlock(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct MnemonicFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl MnemonicFeature {
    pub fn new(value: &str, description: &str) -> Result<MnemonicFeature> {
        Ok(MnemonicFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::Instruction, Scope::BasicBlock),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Mnemonic(self.clone())) {
            return Ok((true, features[&Feature::Mnemonic(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for MnemonicFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "mnemonic_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for MnemonicFeature {
    fn eq(&self, other: &MnemonicFeature) -> bool {
        self.value == other.value
    }
}

impl FeatureT for MnemonicFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct OffsetFeature {
    _bits: u32,
    value: i128,
    _description: String,
    scopes: HashSet<Scope>,
}

impl OffsetFeature {
    pub fn new(bitness: u32, value: &i128, description: &str) -> Result<OffsetFeature> {
        Ok(OffsetFeature {
            _bits: bitness,
            value: *value,
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::Function, Scope::Instruction, Scope::BasicBlock),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Offset(self.clone())) {
            return Ok((true, features[&Feature::Offset(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for OffsetFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "offset_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for OffsetFeature {
    fn eq(&self, other: &OffsetFeature) -> bool {
        self.value == other.value
    }
}

impl FeatureT for OffsetFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct OperandOffsetFeature {
    index: usize,
    value: i128,
    _description: String,
    scopes: HashSet<Scope>,
}

impl OperandOffsetFeature {
    pub fn new(index: &usize, value: &i128, description: &str) -> Result<Self> {
        Ok(Self {
            index: *index,
            value: *value,
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::Function, Scope::Instruction, Scope::BasicBlock),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::OperandOffset(self.clone())) {
            return Ok((
                true,
                features[&Feature::OperandOffset(self.clone())].clone(),
            ));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for OperandOffsetFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "operand_offset_feature".hash(state);
        self.index.hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for OperandOffsetFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.index == other.index
    }
}

impl FeatureT for OperandOffsetFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct NumberFeature {
    _bits: u32,
    value: i128,
    _description: String,
    scopes: HashSet<Scope>,
}

impl NumberFeature {
    pub fn new(bitness: u32, value: &i128, description: &str) -> Result<NumberFeature> {
        Ok(NumberFeature {
            _bits: bitness,
            value: *value,
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::Call,
                Scope::Thread,
                Scope::Process
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Number(self.clone())) {
            return Ok((true, features[&Feature::Number(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for NumberFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "number_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for NumberFeature {
    fn eq(&self, other: &NumberFeature) -> bool {
        self.value == other.value
    }
}

impl FeatureT for NumberFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct OperandNumberFeature {
    index: usize,
    value: i128,
    _description: String,
    scopes: HashSet<Scope>,
}

impl OperandNumberFeature {
    pub fn new(index: &usize, value: &i128, description: &str) -> Result<Self> {
        Ok(Self {
            index: *index,
            value: *value,
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::Function, Scope::Instruction, Scope::BasicBlock),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::OperandNumber(self.clone())) {
            return Ok((
                true,
                features[&Feature::OperandNumber(self.clone())].clone(),
            ));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for OperandNumberFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "operand_number_feature".hash(state);
        self.index.hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for OperandNumberFeature {
    fn eq(&self, other: &OperandNumberFeature) -> bool {
        self.value == other.value && self.index == other.index
    }
}

impl FeatureT for OperandNumberFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ApiFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for ApiFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "api_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for ApiFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for ApiFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl ApiFeature {
    pub fn new(value: &str, description: &str) -> Result<ApiFeature> {
        Ok(ApiFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::Call,
                Scope::Thread,
                Scope::Process
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Api(self.clone())) {
            return Ok((true, features[&Feature::Api(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct PropertyFeature {
    value: String,
    access: Option<FeatureAccess>,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for PropertyFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "property_feature".hash(state);
        self.value.hash(state);
        self.access.hash(state);
    }
}

impl PartialEq for PropertyFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.access == other.access
    }
}

impl FeatureT for PropertyFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl PropertyFeature {
    pub fn new(value: &str, access: Option<FeatureAccess>, description: &str) -> Result<Self> {
        Ok(Self {
            value: value.to_string(),
            access,
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::Function, Scope::Instruction, Scope::BasicBlock),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Property(self.clone())) {
            return Ok((true, features[&Feature::Property(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct MatchedRuleFeature {
    pub value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for MatchedRuleFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "matched_rule_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for MatchedRuleFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for MatchedRuleFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl MatchedRuleFeature {
    pub fn new(value: &str, description: &str) -> Result<MatchedRuleFeature> {
        Ok(MatchedRuleFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::Call,
                Scope::Thread,
                Scope::Process,
                Scope::File
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::MatchedRule(self.clone())) {
            return Ok((true, features[&Feature::MatchedRule(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct CharacteristicFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for CharacteristicFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "characteristic_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for CharacteristicFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for CharacteristicFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl CharacteristicFeature {
    pub fn new(value: &str, description: &str) -> Result<CharacteristicFeature> {
        Ok(CharacteristicFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: match value {
                "calls from" => maplit::hashset!(Scope::Function),
                "calls to" => maplit::hashset!(Scope::Function),
                "loop" => maplit::hashset!(Scope::Function),
                "recursive call" => maplit::hashset!(Scope::Function),
                "nzxor" => maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction),
                "peb access" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "fs access" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "gs access" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "cross section flow" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "tight loop" => maplit::hashset!(Scope::Function, Scope::BasicBlock),
                "stack string" => maplit::hashset!(Scope::Function, Scope::BasicBlock),
                "indirect call" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "call $+5" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "unmanaged call" => {
                    maplit::hashset!(Scope::Function, Scope::BasicBlock, Scope::Instruction)
                }
                "embedded pe" => maplit::hashset!(Scope::File),
                "mixed mode" => maplit::hashset!(Scope::File),
                "forwarded export" => maplit::hashset!(Scope::File),
                _ => maplit::hashset!(),
            },
        })
    }

    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Characteristic(self.clone())) {
            return Ok((
                true,
                features[&Feature::Characteristic(self.clone())].clone(),
            ));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct StringFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for StringFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "string_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for StringFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for StringFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl StringFeature {
    pub fn new(value: &str, description: &str) -> Result<StringFeature> {
        Ok(StringFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File,
                Scope::Call,
                Scope::Thread,
                Scope::Process
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::String(self.clone())) {
            return Ok((true, features[&Feature::String(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct SubstringFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl Hash for SubstringFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "substring_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for SubstringFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl FeatureT for SubstringFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

impl SubstringFeature {
    pub fn new(value: &str, description: &str) -> Result<SubstringFeature> {
        Ok(SubstringFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File,
                Scope::Call,
                Scope::Thread,
                Scope::Process
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        //# mapping from string value to list of locations.
        //# will unique the locations later on.
        let mut matches: std::collections::HashMap<String, Vec<u64>> =
            std::collections::HashMap::new();
        for (feature, locations) in features {
            if let Feature::String(_) = feature {
                if feature.get_value()?.contains(&self.value) {
                    match matches.get_mut(&feature.get_value()?) {
                        Some(ss) => {
                            ss.extend(locations);
                        }
                        _ => {
                            matches.insert(feature.get_value()?, locations.clone());
                        }
                    }
                }
            }
        }
        if !matches.is_empty() {
            //finalize: defaultdict -> dict
            //which makes json serialization easier

            //# collect all locations
            let mut locations: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for (_, locs) in matches {
                for loc in locs {
                    locations.insert(loc);
                }
            }
            //# unlike other features, we cannot return put a reference to `self` directly in a `Result`.
            //# this is because `self` may match on many strings, so we can't stuff the matched value into it.
            //# instead, return a new instance that has a reference to both the substring and the matched values.
            return Ok((true, locations.iter().copied().collect()));
        } else {
            Ok((false, vec![]))
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegexFeature {
    value: String,
    _description: String,
    re: fancy_regex::Regex,
    scopes: HashSet<Scope>,
}

impl RegexFeature {
    pub fn new(value: &str, description: &str) -> Result<RegexFeature> {
        let mut rre = r"(?-u)(?s)".to_string() + &value["/".len()..value.len() - "/".len()];
        if value.ends_with("/i") {
            rre = r"(?-u)(?s)(?i)".to_string() + &value["/".len()..value.len() - "/i".len()];
        }
        //        rre = rre.replace("\\/", "/");
        //        rre = rre.replace("\\\"", "\"");
        //        rre = rre.replace("\\'", "'");
        //        rre = rre.replace("\\%", "%");
        let rr = match fancy_regex::Regex::new(&rre) {
            Ok(s) => s,
            Err(e) => {
                println!("{:?}", e);
                return Err(Error::FancyRegexError(Box::new(e)));
            }
        };
        Ok(RegexFeature {
            value: value.to_string(),
            _description: description.to_string(),
            re: rr,
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File,
                Scope::Call,
                Scope::Thread,
                Scope::Process
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        //# mapping from string value to list of locations.
        //# will unique the locations later on.
        let mut ll = vec![];
        for (feature, locations) in features {
            if let Feature::String(s) = feature {
                if let Ok(Some(_)) = self.re.find(s.value.as_bytes()) {
                    //                    eprintln!("true {}\t{}", self.re.as_str(), s.value);
                    ll.extend(locations);
                } else {
                    //                    eprintln!("false {}\t{}", self.re.as_str(), s.value);
                }
            }
        }
        if !ll.is_empty() {
            return Ok((true, ll));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for RegexFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "regex_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for RegexFeature {
    fn eq(&self, other: &RegexFeature) -> bool {
        self.value == other.value
    }
}

impl Eq for RegexFeature {}

impl FeatureT for RegexFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

// #[derive(Debug, Clone, Hash, PartialEq, Eq)]
// pub struct StringFactoryFeature{
//     value: String,
//     description: String
// }

// impl StringFactoryFeature{
//     pub fn new(value: &str, description: &str) -> Result<StringFactoryFeature>{
// //         Ok(StringFactoryFeature{
// //             value: value.to_string(),
// //             description: description.to_string(),
// //         })
// //     }
// //     pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool>{
// //         match scope{
// //             crate::rules::Scope::Function => {
// //                 Ok(true)
// //             },
// //             crate::rules::Scope::File => {
// //                 Ok(true)
// //             },
// //             crate::rules::Scope::BasicBlock => {
// //                 Ok(true)
// //             }
// //         }
// //     }
// //     pub fn evaluate(&self, features: std::collections::HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)>{
// //         if features.contains_key(&Feature::StringFactoryFeature(*self)){
// //             return Ok((true, features[&Feature::StringFactoryFeature(*self)]));
// //         }
// //         Ok((false, vec![]))
// //     }
// // }

#[derive(Debug, Clone, Eq)]
pub struct BytesFeature {
    value: Vec<u8>,
    _description: String,
    scopes: HashSet<Scope>,
}

impl BytesFeature {
    pub fn new(value: &[u8], description: &str) -> Result<BytesFeature> {
        Ok(BytesFeature {
            value: value.to_owned(),
            _description: description.to_string(),
            scopes: maplit::hashset!(Scope::Function, Scope::Instruction, Scope::BasicBlock,),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        for (feature, locations) in features {
            if let Feature::Bytes(s) = feature {
                if s.value
                    .windows(self.value.len())
                    .any(|window| window == self.value)
                {
                    return Ok((true, locations.clone()));
                }
            } else {
                continue;
            }
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for BytesFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "bytes_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for BytesFeature {
    fn eq(&self, other: &BytesFeature) -> bool {
        self.value == other.value
    }
}

impl FeatureT for BytesFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ArchFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl ArchFeature {
    pub fn new(value: &str, description: &str) -> Result<ArchFeature> {
        Ok(ArchFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File,
                Scope::Call,
                Scope::Thread,
                Scope::Process,
                Scope::Global
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Arch(self.clone())) {
            return Ok((true, features[&Feature::Arch(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for ArchFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "arch_feature".hash(state);
        self.value.to_lowercase().hash(state);
    }
}

impl PartialEq for ArchFeature {
    fn eq(&self, other: &ArchFeature) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl FeatureT for ArchFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct NamespaceFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl NamespaceFeature {
    pub fn new(value: &str, description: &str) -> Result<Self> {
        Ok(Self {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Namespace(self.clone())) {
            return Ok((true, features[&Feature::Namespace(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for NamespaceFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "namespace_feature".hash(state);
        self.value.to_lowercase().hash(state);
    }
}

impl PartialEq for NamespaceFeature {
    fn eq(&self, other: &NamespaceFeature) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl FeatureT for NamespaceFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ClassFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl ClassFeature {
    pub fn new(value: &str, description: &str) -> Result<Self> {
        Ok(Self {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Class(self.clone())) {
            return Ok((true, features[&Feature::Class(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for ClassFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "class_feature".hash(state);
        self.value.to_lowercase().hash(state);
    }
}

impl PartialEq for ClassFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl FeatureT for ClassFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct OsFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl OsFeature {
    pub fn new(value: &str, description: &str) -> Result<OsFeature> {
        Ok(OsFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File,
                Scope::Call,
                Scope::Thread,
                Scope::Process,
                Scope::Global
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Os(self.clone())) {
            return Ok((true, features[&Feature::Os(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for OsFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "os_feature".hash(state);
        self.value.to_lowercase().hash(state);
    }
}

impl PartialEq for OsFeature {
    fn eq(&self, other: &OsFeature) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl FeatureT for OsFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[derive(Debug, Clone, Eq)]
pub struct FormatFeature {
    value: String,
    _description: String,
    scopes: HashSet<Scope>,
}

impl FormatFeature {
    pub fn new(value: &str, description: &str) -> Result<FormatFeature> {
        Ok(FormatFeature {
            value: value.to_string(),
            _description: description.to_string(),
            scopes: maplit::hashset!(
                Scope::Function,
                Scope::Instruction,
                Scope::BasicBlock,
                Scope::File,
                Scope::Call,
                Scope::Thread,
                Scope::Process,
                Scope::Global
            ),
        })
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if features.contains_key(&Feature::Format(self.clone())) {
            return Ok((true, features[&Feature::Format(self.clone())].clone()));
        }
        Ok((false, vec![]))
    }
}

impl std::hash::Hash for FormatFeature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "format_feature".hash(state);
        self.value.to_lowercase().hash(state);
    }
}

impl PartialEq for FormatFeature {
    fn eq(&self, other: &FormatFeature) -> bool {
        self.value.to_lowercase() == other.value.to_lowercase()
    }
}

impl FeatureT for FormatFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}
