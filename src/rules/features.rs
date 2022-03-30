use crate::{rules::Value, Error, Result};

#[derive(Debug)]
pub enum RuleFeatureType {
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
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Feature {
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
}

impl Feature {
    pub fn new(t: RuleFeatureType, value: &Value, description: &str) -> Result<Feature> {
        match t {
            RuleFeatureType::Api => Ok(Feature::Api(ApiFeature::new(
                &value.get_str()?,
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
        }
    }

    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match self {
            Feature::Api(a) => a.is_supported_in_scope(scope),
            Feature::Regex(a) => a.is_supported_in_scope(scope),
            Feature::String(a) => a.is_supported_in_scope(scope),
            Feature::Substring(a) => a.is_supported_in_scope(scope),
            Feature::Bytes(a) => a.is_supported_in_scope(scope),
            Feature::Number(a) => a.is_supported_in_scope(scope),
            Feature::Offset(a) => a.is_supported_in_scope(scope),
            Feature::Mnemonic(a) => a.is_supported_in_scope(scope),
            Feature::BasicBlock(a) => a.is_supported_in_scope(scope),
            Feature::Characteristic(a) => a.is_supported_in_scope(scope),
            Feature::Export(a) => a.is_supported_in_scope(scope),
            Feature::Import(a) => a.is_supported_in_scope(scope),
            Feature::Section(a) => a.is_supported_in_scope(scope),
            Feature::MatchedRule(a) => a.is_supported_in_scope(scope),
            Feature::FunctionName(a) => a.is_supported_in_scope(scope),
            Feature::Os(a) => a.is_supported_in_scope(scope),
            Feature::Format(a) => a.is_supported_in_scope(scope),
            Feature::Arch(a) => a.is_supported_in_scope(scope),
        }
    }

    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        match self {
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
        }
    }

    pub fn get_value(&self) -> Result<String> {
        match self {
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
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FunctionNameFeature {
    value: String,
    description: String,
}

impl FunctionNameFeature {
    pub fn new(value: &str, description: &str) -> Result<FunctionNameFeature> {
        Ok(FunctionNameFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }

    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(false),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(false),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SectionFeature {
    value: String,
    description: String,
}

impl SectionFeature {
    pub fn new(value: &str, description: &str) -> Result<SectionFeature> {
        Ok(SectionFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(false),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(false),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ImportFeature {
    value: String,
    description: String,
}

impl ImportFeature {
    pub fn new(value: &str, description: &str) -> Result<ImportFeature> {
        Ok(ImportFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(false),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(false),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ExportFeature {
    value: String,
    description: String,
}

impl ExportFeature {
    pub fn new(value: &str, description: &str) -> Result<ExportFeature> {
        Ok(ExportFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(false),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(false),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct BasicBlockFeature {}

impl BasicBlockFeature {
    pub fn new() -> Result<BasicBlockFeature> {
        Ok(BasicBlockFeature {})
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(false),
            crate::rules::Scope::BasicBlock => Ok(false),
        }
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

#[derive(Debug, Clone)]
pub struct MnemonicFeature {
    value: String,
    _description: String,
}

impl MnemonicFeature {
    pub fn new(value: &str, description: &str) -> Result<MnemonicFeature> {
        Ok(MnemonicFeature {
            value: value.to_string(),
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(false),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

impl Eq for MnemonicFeature {}

#[derive(Debug, Clone)]
pub struct OffsetFeature {
    _bits: u32,
    value: i128,
    _description: String,
}

impl OffsetFeature {
    pub fn new(bitness: u32, value: &i128, description: &str) -> Result<OffsetFeature> {
        Ok(OffsetFeature {
            _bits: bitness,
            value: *value,
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(false),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

impl Eq for OffsetFeature {}

#[derive(Debug, Clone)]
pub struct NumberFeature {
    _bits: u32,
    value: i128,
    _description: String,
}

impl NumberFeature {
    pub fn new(bitness: u32, value: &i128, description: &str) -> Result<NumberFeature> {
        Ok(NumberFeature {
            _bits: bitness,
            value: *value,
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(false),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

impl Eq for NumberFeature {}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ApiFeature {
    value: String,
    description: String,
}

impl ApiFeature {
    pub fn new(value: &str, description: &str) -> Result<ApiFeature> {
        Ok(ApiFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(false),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MatchedRuleFeature {
    pub value: String,
    description: String,
}

impl MatchedRuleFeature {
    pub fn new(value: &str, description: &str) -> Result<MatchedRuleFeature> {
        Ok(MatchedRuleFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CharacteristicFeature {
    value: String,
    description: String,
}

impl CharacteristicFeature {
    pub fn new(value: &str, description: &str) -> Result<CharacteristicFeature> {
        Ok(CharacteristicFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }

    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => match self.value.as_str() {
                "calls from" => Ok(true),
                "calls to" => Ok(true),
                "loop" => Ok(true),
                "recursive call" => Ok(true),
                "nzxor" => Ok(true),
                "peb access" => Ok(true),
                "fs access" => Ok(true),
                "gs access" => Ok(true),
                "cross section flow" => Ok(true),
                "tight loop" => Ok(true),
                "stack string" => Ok(true),
                "indirect call" => Ok(true),
                "call $+5" => Ok(true),
                _ => Ok(false),
            },
            crate::rules::Scope::File => match self.value.as_str() {
                "embedded pe" => Ok(true),
                _ => Ok(false),
            },
            crate::rules::Scope::BasicBlock => match self.value.as_str() {
                "nzxor" => Ok(true),
                "peb access" => Ok(true),
                "fs access" => Ok(true),
                "gs access" => Ok(true),
                "cross section flow" => Ok(true),
                "tight loop" => Ok(true),
                "stack string" => Ok(true),
                "indirect call" => Ok(true),
                "call $+5" => Ok(true),
                _ => Ok(false),
            },
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StringFeature {
    value: String,
    description: String,
}

impl StringFeature {
    pub fn new(value: &str, description: &str) -> Result<StringFeature> {
        Ok(StringFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }

    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SubstringFeature {
    value: String,
    description: String,
}

impl SubstringFeature {
    pub fn new(value: &str, description: &str) -> Result<SubstringFeature> {
        Ok(SubstringFeature {
            value: value.to_string(),
            description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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
    re: regex::bytes::Regex,
}

impl RegexFeature {
    pub fn new(value: &str, description: &str) -> Result<RegexFeature> {
        let mut rre = r"(?-u)(?s)".to_string() + &value["/".len()..value.len() - "/".len()];
        if value.ends_with("/i") {
            rre = r"(?-u)(?s)(?i)".to_string() + &value["/".len()..value.len() - "/i".len()];
        }
        rre = rre.replace("\\/", "/");
        rre = rre.replace("\\\"", "\"");
        rre = rre.replace("\\'", "'");
        rre = rre.replace("\\%", "%");
        let rr = match regex::bytes::Regex::new(&rre) {
            Ok(s) => s,
            Err(e) => {
                println!("{:?}", e);
                return Err(Error::RegexError(e));
            }
        };
        Ok(RegexFeature {
            value: value.to_string(),
            _description: description.to_string(),
            re: rr,
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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
                if self.re.find(s.value.as_bytes()).is_some() {
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

#[derive(Debug, Clone)]
pub struct BytesFeature {
    value: Vec<u8>,
    _description: String,
}

impl BytesFeature {
    pub fn new(value: &[u8], description: &str) -> Result<BytesFeature> {
        Ok(BytesFeature {
            value: value.to_owned(),
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(false),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
    }
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        for (feature, locations) in features {
            if let Feature::Bytes(s) = feature {
                if s.value.starts_with(&self.value) {
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

impl Eq for BytesFeature {}

#[derive(Debug, Clone)]
pub struct ArchFeature {
    value: String,
    _description: String,
}

impl ArchFeature {
    pub fn new(value: &str, description: &str) -> Result<ArchFeature> {
        Ok(ArchFeature {
            value: value.to_string(),
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

impl Eq for ArchFeature {}

#[derive(Debug, Clone)]
pub struct OsFeature {
    value: String,
    _description: String,
}

impl OsFeature {
    pub fn new(value: &str, description: &str) -> Result<OsFeature> {
        Ok(OsFeature {
            value: value.to_string(),
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(true),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(true),
        }
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

impl Eq for OsFeature {}

#[derive(Debug, Clone)]
pub struct FormatFeature {
    value: String,
    _description: String,
}

impl FormatFeature {
    pub fn new(value: &str, description: &str) -> Result<FormatFeature> {
        Ok(FormatFeature {
            value: value.to_string(),
            _description: description.to_string(),
        })
    }
    pub fn is_supported_in_scope(&self, scope: &crate::rules::Scope) -> Result<bool> {
        match scope {
            crate::rules::Scope::Function => Ok(false),
            crate::rules::Scope::File => Ok(true),
            crate::rules::Scope::BasicBlock => Ok(false),
        }
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

impl Eq for FormatFeature {}
