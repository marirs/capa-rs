use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
};

use crate::{Error, Result, rules::Value};

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
    // 0.4.1: bare `Property` form (no access) added — Python capa's
    // `parse_feature` returns this for unqualified `property:` keys
    // (used in `count(property(...))` contexts and similar).
    // Reference: capa/rules/__init__.py:446.
    // Typo fix: `PropretyRead`/`PropretyWrite` → `PropertyRead`/`PropertyWrite`.
    Property,
    PropertyRead,
    PropertyWrite,
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
    /// 0.5.2 (upstream parity #2929): is this a "global" feature —
    /// one that's constant per binary (OS, architecture, file
    /// format), determined once from headers, and therefore
    /// suitable for pre-pruning rules whose constraints can't be
    /// satisfied?
    ///
    /// Mirrors Python capa's `capa.features.common.is_global_feature`.
    pub fn is_global_feature(&self) -> bool {
        matches!(self, Feature::Os(_) | Feature::Arch(_) | Feature::Format(_))
    }

    pub fn new(t: RuleFeatureType, value: &Value, description: &str) -> Result<Feature> {
        // let readpro = "property/read".to_string();

        match t {
            RuleFeatureType::Api => Ok(Feature::Api(ApiFeature::new(
                &value.get_str()?,
                description,
            )?)),
            // 0.4.1: bare `property:` — unqualified property access.
            // `access: None` means "any access" (read or write); matches
            // Python's behaviour for `parse_feature("property")` and
            // makes the `count(property(...))` count-context work.
            RuleFeatureType::Property => Ok(Feature::Property(PropertyFeature::new(
                &value.get_str()?,
                None,
                description,
            )?)),
            RuleFeatureType::PropertyRead => Ok(Feature::Property(PropertyFeature::new(
                &value.get_str()?,
                Some(FeatureAccess::Read),
                description,
            )?)),
            RuleFeatureType::PropertyWrite => Ok(Feature::Property(PropertyFeature::new(
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
            RuleFeatureType::Number(s) => Ok(Feature::Number(NumberFeature::new(
                s,
                &value.get_int()?,
                description,
            )?)),
            RuleFeatureType::Offset(s) => Ok(Feature::Offset(OffsetFeature::new(
                s,
                &value.get_int()?,
                description,
            )?)),
            RuleFeatureType::Mnemonic => Ok(Feature::Mnemonic(MnemonicFeature::new(
                &value.get_str()?,
                description,
            )?)),
            RuleFeatureType::BasicBlock => Ok(Feature::BasicBlock(BasicBlockFeature::new()?)),
            RuleFeatureType::Characteristic => Ok(Feature::Characteristic(
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
                // 0.5.0: `com/class:` and `com/interface:` are
                // rewritten at rule-load time by `translate_com_features`
                // in `mod.rs` — they become an `OrStatement` of
                // `Feature::Bytes` over each known CLSID/IID for the
                // named class. By the time we'd reach this match
                // arm, the CommandType::ComType branch in
                // `Rule::parse_feature_type`'s caller has already
                // produced the rewrite, so this is dead. Loud
                // unreachable so any future refactor that misroutes
                // a ComType through Feature::new gets caught.
                unreachable!(
                    "RuleFeatureType::ComType should be handled by \
                     translate_com_features at rule load, not via \
                     Feature::new"
                )
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
        if let Some(locations) = features.get(&Feature::FunctionName(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::Section(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::Import(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::Export(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::BasicBlock(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::Mnemonic(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for MnemonicFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
        if let Some(locations) = features.get(&Feature::Offset(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for OffsetFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
        if let Some(locations) = features.get(&Feature::OperandOffset(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for OperandOffsetFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
        if let Some(locations) = features.get(&Feature::Number(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for NumberFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
        if let Some(locations) = features.get(&Feature::OperandNumber(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for OperandNumberFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
        if let Some(locations) = features.get(&Feature::Api(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::Property(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::MatchedRule(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::Characteristic(self.clone())) {
            return Ok((true, locations.clone()));
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
        if let Some(locations) = features.get(&Feature::String(self.clone())) {
            return Ok((true, locations.clone()));
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
            Ok((true, locations.iter().copied().collect()))
        } else {
            Ok((false, vec![]))
        }
    }
}

/// 0.4.2: regex engine handle — linear-time `regex` crate where
/// possible (no ReDoS surface), fall back to backtracking
/// `fancy_regex` only when the rule actually uses
/// lookbehind / backreferences / atomic groups (features the
/// linear engine doesn't support).
///
/// Rationale: a hostile rule pattern like `(a+)+b` against
/// `fancy_regex` is a textbook ReDoS — it can hang the analyzer
/// for hours. The vast majority of `capa-rules` regex features
/// are simple substring / character-class patterns the linear
/// engine handles in O(n). Routing those through `regex` removes
/// the DoS surface for them. Only the genuinely-fancy patterns
/// (lookbehind, backrefs) need the backtracking engine.
#[derive(Debug, Clone)]
enum RegexEngine {
    /// Linear-time matcher. Pattern parsed successfully into the
    /// `regex` crate, which guarantees O(n) match time.
    Linear(regex::Regex),
    /// Fallback for patterns the linear engine can't compile
    /// (lookbehind, backrefs, atomic groups). Subject to
    /// catastrophic backtracking on hostile inputs — accept the
    /// risk because the rule author opted into the feature.
    Fancy(fancy_regex::Regex),
}

impl RegexEngine {
    fn is_match(&self, hay: &str) -> bool {
        match self {
            RegexEngine::Linear(re) => re.is_match(hay),
            RegexEngine::Fancy(re) => matches!(re.find(hay), Ok(Some(_))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegexFeature {
    value: String,
    _description: String,
    re: RegexEngine,
    scopes: HashSet<Scope>,
}

/// (0.3.21) Translate non-ASCII `\xHH` byte escapes to Unicode
/// code-point escapes `\u{HH}` so crates.io `fancy-regex 0.18` parses
/// them.
///
/// Background: capa-rs used to depend on the `mnaza/fancy-regex` git
/// fork that patched out a `NonUnicodeUnsupported` parser check.
/// Swapping to upstream crates.io `fancy-regex` (the no-git-deps
/// cleanup) re-introduced that strictness: any pattern containing
/// `\x80`-`\xff` is rejected at parse time, even with an inline
/// `(?-u)` flag. Many `capa-rules` patterns rely on high byte
/// escapes for malware signature matching.
///
/// `\xHH` and `\u{HH}` match the same code point at the regex-match
/// level. ASCII range (`\x00`-`\x7F`) is left alone — fancy-regex
/// accepts those as-is. Escaped backslashes (`\\x80` = literal
/// `\x80`, not a byte escape) are preserved.
///
/// Pure string transform — does not try to parse the full regex
/// grammar, only the `\xHH` token. Runs once per `RegexFeature`
/// construction (i.e. once per rule load), so allocation cost is
/// negligible.
fn unicode_safe_byte_escapes(pat: &str) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = String::with_capacity(pat.len());
    let mut i = 0;
    while i < chars.len() {
        // `\\` — escaped backslash. Emit both verbatim so the next
        // iteration doesn't misread the trailing `\` as an escape lead.
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == '\\' {
            out.push('\\');
            out.push('\\');
            i += 2;
            continue;
        }
        // `\xHH` where HH is exactly two hex digits.
        if chars[i] == '\\'
            && i + 3 < chars.len()
            && chars[i + 1] == 'x'
            && chars[i + 2].is_ascii_hexdigit()
            && chars[i + 3].is_ascii_hexdigit()
        {
            let mut hex = String::with_capacity(2);
            hex.push(chars[i + 2]);
            hex.push(chars[i + 3]);
            // SAFETY: both chars are ASCII hex by the check above.
            let v = u8::from_str_radix(&hex, 16).unwrap();
            if v >= 0x80 {
                out.push_str(&format!("\\u{{{v:x}}}"));
            } else {
                // ASCII byte — leave as `\xHH`, fancy-regex accepts.
                out.push('\\');
                out.push('x');
                out.push(chars[i + 2]);
                out.push(chars[i + 3]);
            }
            i += 4;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

impl RegexFeature {
    pub fn new(value: &str, description: &str) -> Result<RegexFeature> {
        let body = &value["/".len()..value.len() - "/".len()];
        // 0.3.21: pre-0.3.21 we prepended `(?-u)` to put the regex into
        // byte mode (matched the `mnaza/fancy-regex` fork's behaviour).
        // Crates.io `fancy-regex 0.18` rejects `(?-u)` outright
        // (`NonUnicodeUnsupported` at parse position 3) because its
        // lookbehind/backreference engine needs Unicode mode. Stay in
        // Unicode mode and let `unicode_safe_byte_escapes` convert the
        // problematic `\xHH` byte escapes to `\u{HH}` Unicode escapes,
        // which match the same code point either way.
        let mut rre = r"(?s)".to_string() + body;
        if value.ends_with("/i") {
            let body_i = &value["/".len()..value.len() - "/i".len()];
            rre = r"(?s)(?i)".to_string() + body_i;
        }
        rre = unicode_safe_byte_escapes(&rre);
        // 0.4.2: try the linear-time `regex` crate first; fall back
        // to `fancy_regex` only when the pattern uses features the
        // linear engine doesn't support (lookbehind, backrefs,
        // atomic groups). Closes the ReDoS surface for the ~95% of
        // capa-rules patterns that don't actually need backtracking.
        // Fancy-only-feature errors surface as Error::ParseError
        // variants in the regex crate; we treat ANY parse failure as
        // "try fancy" rather than introspecting the error type, so
        // future regex-crate updates can't accidentally lock us out.
        let re = match regex::Regex::new(&rre) {
            Ok(linear) => RegexEngine::Linear(linear),
            Err(_) => match fancy_regex::Regex::new(&rre) {
                Ok(fancy) => RegexEngine::Fancy(fancy),
                Err(e) => {
                    eprintln!("regex parse failed for `{}`: {:?}", rre, e);
                    return Err(Error::FancyRegexError(Box::new(e)));
                }
            },
        };
        Ok(RegexFeature {
            value: value.to_string(),
            _description: description.to_string(),
            re,
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
        // 0.5.0 (E4): also iterate `Feature::Substring` for parity
        // with Python capa. Python's evaluator runs
        // `isinstance(feature, (String,))` which catches both `String`
        // and `Substring` because `Substring(String)` inherits from
        // `String` in Python's class hierarchy. In capa-rs they're
        // distinct enum variants, so the dispatch has to enumerate
        // both explicitly. No capa-rs extractor currently emits
        // `Feature::Substring`, so this is behaviour-neutral today —
        // defensive widening to keep parity if a future extractor
        // does.
        let mut ll = vec![];
        for (feature, locations) in features {
            let value: Option<&str> = match feature {
                Feature::String(s) => Some(s.value.as_str()),
                Feature::Substring(s) => Some(s.value.as_str()),
                _ => None,
            };
            if let Some(value) = value {
                if self.re.is_match(value) {
                    ll.extend(locations);
                }
            }
        }
        if !ll.is_empty() {
            return Ok((true, ll));
        }
        Ok((false, vec![]))
    }
}

impl Hash for RegexFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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

// 0.4.2: removed the commented-out `StringFactoryFeature` block —
// dead since the StringFactory dispatch was inlined into
// `Feature::new` (it parses `string:` into either Regex or String
// based on the leading `/`).

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
                // 0.4.2: equal-length fast path. Capa-rules `bytes:`
                // features are almost always exactly the length of
                // the binary's extracted bytes (rule authors quote
                // the full byte slice they're matching), so checking
                // equality first avoids the O(s*self) windows-scan
                // for the common case. Falls through to the scan when
                // lengths differ (e.g. a substring-style bytes rule).
                if s.value.len() == self.value.len() {
                    if s.value == self.value {
                        return Ok((true, locations.clone()));
                    }
                    continue;
                }
                if self.value.len() > s.value.len() {
                    continue;
                }
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

impl Hash for BytesFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
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
            // 0.4.2: canonicalise to lowercase once at construction.
            // Pre-0.4.2 `Hash` and `PartialEq` both called
            // `.to_lowercase()` on each invocation — hot in the rule
            // engine's HashMap lookups (tens of thousands per
            // analysis × 5 case-insensitive feature types).
            value: value.to_lowercase(),
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
        if let Some(locations) = features.get(&Feature::Arch(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }

    /// 0.5.2 (upstream parity #2929): see `OsFeature::value`.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Hash for ArchFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "arch_feature".hash(state);
        // 0.4.2: value already lowercased at construction.
        self.value.hash(state);
    }
}

impl PartialEq for ArchFeature {
    fn eq(&self, other: &ArchFeature) -> bool {
        // 0.4.2: both values already lowercased at construction.
        self.value == other.value
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
            // 0.4.2: canonicalise once at construction — see ArchFeature.
            value: value.to_lowercase(),
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
        if let Some(locations) = features.get(&Feature::Namespace(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for NamespaceFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "namespace_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for NamespaceFeature {
    fn eq(&self, other: &NamespaceFeature) -> bool {
        self.value == other.value
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
            // 0.4.2: canonicalise once at construction — see ArchFeature.
            value: value.to_lowercase(),
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
        if let Some(locations) = features.get(&Feature::Class(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }
}

impl Hash for ClassFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "class_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for ClassFeature {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
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
            // 0.4.2: canonicalise once at construction — see ArchFeature.
            value: value.to_lowercase(),
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
        if let Some(locations) = features.get(&Feature::Os(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }

    /// 0.5.2 (upstream parity #2929): expose the canonicalised
    /// (lowercased) OS string so the `filter_rules_by_meta_features`
    /// pre-prune walker can detect the `os: any` wildcard.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Hash for OsFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "os_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for OsFeature {
    fn eq(&self, other: &OsFeature) -> bool {
        self.value == other.value
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
            // 0.4.2: canonicalise once at construction — see ArchFeature.
            value: value.to_lowercase(),
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
        if let Some(locations) = features.get(&Feature::Format(self.clone())) {
            return Ok((true, locations.clone()));
        }
        Ok((false, vec![]))
    }

    /// 0.5.2 (upstream parity #2929): see `OsFeature::value`.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Hash for FormatFeature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "format_feature".hash(state);
        self.value.hash(state);
    }
}

impl PartialEq for FormatFeature {
    fn eq(&self, other: &FormatFeature) -> bool {
        self.value == other.value
    }
}

impl FeatureT for FormatFeature {
    fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }
}

#[cfg(test)]
mod tests {
    use super::unicode_safe_byte_escapes;

    #[test]
    fn passes_ascii_byte_escapes_through_unchanged() {
        // fancy-regex 0.18 accepts \xHH where HH <= 0x7F directly.
        assert_eq!(unicode_safe_byte_escapes(r"\x00"), r"\x00");
        assert_eq!(unicode_safe_byte_escapes(r"\x7F"), r"\x7F");
        assert_eq!(unicode_safe_byte_escapes(r"foo\x41bar"), r"foo\x41bar");
    }

    #[test]
    fn translates_high_byte_escapes_to_code_points() {
        // The actual fix — these would otherwise hit NonUnicodeUnsupported.
        assert_eq!(unicode_safe_byte_escapes(r"\x80"), r"\u{80}");
        assert_eq!(unicode_safe_byte_escapes(r"\xFF"), r"\u{ff}");
        assert_eq!(unicode_safe_byte_escapes(r"\xC2"), r"\u{c2}");
    }

    #[test]
    fn preserves_escaped_backslashes() {
        // `\\x80` is `\` then literal `x80` text — not a byte escape.
        // The escaped-backslash branch must consume two chars.
        assert_eq!(unicode_safe_byte_escapes(r"\\x80"), r"\\x80");
        assert_eq!(unicode_safe_byte_escapes(r"\\\\xFF"), r"\\\\xFF");
    }

    #[test]
    fn handles_mixed_patterns() {
        // Realistic capa-rules-style snippet.
        assert_eq!(
            unicode_safe_byte_escapes(r"(?-u)(?s)foo\x80bar\x7Fbaz"),
            r"(?-u)(?s)foo\u{80}bar\x7Fbaz"
        );
    }

    #[test]
    fn leaves_non_xhh_escapes_alone() {
        // \d, \n, \w etc. — only \xHH is touched.
        assert_eq!(unicode_safe_byte_escapes(r"\d+"), r"\d+");
        assert_eq!(unicode_safe_byte_escapes(r"foo\nbar"), r"foo\nbar");
        assert_eq!(unicode_safe_byte_escapes(r"\u{80}"), r"\u{80}");
    }

    #[test]
    fn ignores_invalid_xhh_sequences() {
        // \xZZ is invalid — pass through verbatim.
        assert_eq!(unicode_safe_byte_escapes(r"\xZZ"), r"\xZZ");
        // \x with no hex after — pass through.
        assert_eq!(unicode_safe_byte_escapes(r"\x"), r"\x");
        // \xH (one digit) — pass through.
        assert_eq!(unicode_safe_byte_escapes(r"\xA"), r"\xA");
    }

    #[test]
    fn preserves_multibyte_utf8_literals() {
        // A regex pattern can literally contain Unicode characters
        // outside the escape syntax; those must survive.
        let pat = "中文\\x80";
        let expected = "中文\\u{80}";
        assert_eq!(unicode_safe_byte_escapes(pat), expected);
    }
}
