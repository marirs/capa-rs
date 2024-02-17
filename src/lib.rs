#![allow(clippy::type_complexity, clippy::borrowed_box)]
pub(crate) mod consts;
mod extractor;
pub mod rules;
mod sede;
use consts::{FileFormat, Os};
use sede::{from_hex, to_hex};
use serde::{Deserialize, Serialize};
use smda::FileArchitecture;
use std::collections::HashSet;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    thread::spawn,
};

mod error;
pub use crate::error::Error;
use serde_json::{json, Value};
use yaml_rust::Yaml;

pub type Result<T> = std::result::Result<T, Error>;

impl FileCapabilities {
    pub fn from_file(
        file_name: &str,
        rule_path: &str,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        logger: &dyn Fn(&str),
        features_dump: bool,
    ) -> Result<Self> {
        //! Loads a binary from a given file for capability analysis
        //! ## Example
        //! ```rust
        //! use capa::FileCapabilities;
        //!
        //! let rules_path = "./rules";
        //! let file_to_analyse = "./demo.exe";
        //! let result = FileCapabilities::from_file(file_to_analyse, rules_path, true, true, &|_s| {}, false);
        //! println!("{:?}", result);
        //! ```
        let f = file_name.to_string();
        let r = rule_path.to_string();
        let (format, buffer) = get_format(&f)?;
        let extractor = get_file_extractors(&f, format, &buffer, high_accuracy, resolve_tailcalls)?;
        let rules_thread_handle = spawn(move || rules::RuleSet::new(&r));
        let rules = rules_thread_handle.join().unwrap()?;

        let mut file_capabilities;
        #[cfg(not(feature = "properties"))]
        {
            file_capabilities = FileCapabilities::new()?;
        }
        #[cfg(feature = "properties")]
        {
            file_capabilities = FileCapabilities::new(&extractor)?;
        }
        #[cfg(not(feature = "verbose"))]
        {
            let (capabilities, _counts, _map_features) =
                find_capabilities(&rules, &extractor, logger, features_dump)?;
            if features_dump {
                file_capabilities.map_features = _map_features;
            }
            file_capabilities.update_capabilities(&capabilities)?;
        }
        #[cfg(feature = "verbose")]
        {
            let (capabilities, counts, _map_features) =
                find_capabilities(&rules, &extractor, logger, features_dump)?;
            if features_dump {
                file_capabilities.map_features = _map_features;
            }
            file_capabilities.update_capabilities(&capabilities, &counts)?;
        }

        Ok(file_capabilities)
    }

    fn new(
        #[cfg(feature = "properties")] extractor: &Box<dyn extractor::Extractor>,
    ) -> Result<FileCapabilities> {
        Ok(FileCapabilities {
            #[cfg(feature = "properties")]
            properties: Properties {
                format: FileCapabilities::get_format(extractor)?,
                arch: FileCapabilities::get_arch(extractor)?,
                os: FileCapabilities::get_os(extractor)?,
                base_address: extractor.get_base_address()? as usize,
            },
            attacks: BTreeMap::new(),
            mbc: BTreeMap::new(),
            capability_namespaces: BTreeMap::new(),
            #[cfg(feature = "verbose")]
            features: 0,
            #[cfg(feature = "verbose")]
            functions_capabilities: BTreeMap::new(),
            tags: BTreeSet::new(),
            map_features: HashMap::new(),
            capabilities_associations: BTreeMap::new(),
        })
    }

    fn update_capabilities(
        &mut self,
        capabilities: &HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
        #[cfg(feature = "verbose")] counts: &HashMap<u64, usize>,
    ) -> Result<()> {
        let re = regex::Regex::new(r##"[^]]*\[(?P<tag>[^]]*)]"##)?;
        for (rule, caps) in capabilities {
            let mut local_attacks_set: BTreeSet<Attacks> = BTreeSet::new();
            let mut local_mbc_set: BTreeSet<Mbc> = BTreeSet::new();

            if let Some(Yaml::Array(attacks)) = rule.meta.get(&Yaml::String("att&ck".to_string())) {
                for p in attacks.iter().filter_map(|item| item.as_str()) {
                    if let Ok(attack) = Attacks::from_str(p) {
                        local_attacks_set.insert(attack);
                    }

                    let parts: Vec<&str> = p.split("::").collect();
                    if parts.len() > 1 {
                        let detail = parts[1..].join("::");
                        if let Some(caps) = re.captures(&detail) {
                            if let Some(tag_match) = caps.name("tag") {
                                self.tags.insert(tag_match.as_str().to_string());
                            }
                        }

                        self.attacks
                            .entry(parts[0].to_string())
                            .or_default()
                            .insert(detail);
                    }
                }
            }

            if let Some(Yaml::Array(mbcs)) = rule.meta.get(&Yaml::String("mbc".to_string())) {
                for p in mbcs.iter().filter_map(|item| item.as_str()) {
                    if let Ok(mbc) = Mbc::from_str(p) {
                        local_mbc_set.insert(mbc);
                    }

                    let parts: Vec<&str> = p.split("::").collect();
                    if parts.len() > 1 {
                        let detail = parts[1..].join("::");
                        if let Some(caps) = re.captures(&detail) {
                            if let Some(tag_match) = caps.name("tag") {
                                self.tags.insert(tag_match.as_str().to_string());
                            }
                        }

                        self.mbc
                            .entry(parts[0].to_string())
                            .or_default()
                            .insert(detail);
                    }
                }
            }

            if let Some(namespace) = rule.meta.get(&Yaml::String("namespace".to_string())) {
                if let Yaml::String(s) = namespace {
                    self.capability_namespaces
                        .insert(rule.name.clone(), s.clone());
                    let first_non_zero_address = caps
                        .iter()
                        .find(|&&(addr, _)| addr != 0)
                        .map(|&(addr, _)| addr)
                        .unwrap_or(0);

                    let _ = self
                        .capabilities_associations
                        .entry(rule.name.clone())
                        .or_insert_with(|| CapabilityAssociation {
                            attack: local_attacks_set.clone(),
                            mbc: local_mbc_set.clone(),
                            namespace: s.clone(),
                            name: rule.name.clone(),
                            address: first_non_zero_address as usize,
                        });
                }
            }
            #[cfg(feature = "verbose")]
            {
                for &(addr, _) in caps {
                    if addr != 0 {
                        self.functions_capabilities
                            .entry(addr)
                            .and_modify(|fc| {
                                fc.capabilities.push(rule.name.clone());
                            })
                            .or_insert_with(|| FunctionCapabilities {
                                address: addr as usize,
                                features: *counts.get(&addr).unwrap_or(&0),
                                capabilities: vec![rule.name.clone()],
                            });
                    }
                }
                self.features = counts[&0];
            }
        }

        Ok(())
    }

    pub fn construct_json_for_capabilities_associations(
        &mut self,
        filter: Option<String>,
    ) -> Value {
        if let Some(f) = filter {
            let filters: Vec<&str> = f.split('|').collect();
            self.map_features
                .retain(|k, _v| filters.iter().any(|filter| k.contains(filter)));
        }

        let mut rules = serde_json::Map::new();
        for (name, association) in &self.capabilities_associations {
            let attacks_json = association
                .attack
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "subtechnique": a.subtechnique,
                        "tactic": a.tactic,
                        "technique": a.technique,
                    })
                })
                .collect::<Vec<_>>();

            let mbc_json = association
                .mbc
                .iter()
                .map(|m| {
                    json!({
                        "objective": m.objective,
                        "behavior": m.behavior,
                        "method": m.method,
                        "id": m.id,
                    })
                })
                .collect::<Vec<_>>();

            let association_json = json!({
                "attacks": attacks_json,
                "mbc": mbc_json,
                "namespace": association.namespace,
                "name": association.name,
                "address": association.address,
            });

            rules.insert(name.clone(), association_json);
        }
        Value::Object(rules)
    }
    pub fn serialize_file_capabilities(
        &mut self,
        filter: Option<String>,
    ) -> serde_json::Result<String> {
        let associations_json = self.construct_json_for_capabilities_associations(filter);
        let mut fc_json = serde_json::to_value(self.clone())?;
        fc_json
            .as_object_mut()
            .unwrap()
            .insert("rules".to_string(), associations_json);
        if let Some(map_features) = fc_json.get("map_features") {
            if map_features.as_object().map_or(false, |m| m.is_empty()) {
                fc_json.as_object_mut().unwrap().remove("map_features");
            }
        }

        serde_json::to_string(&fc_json)
    }

    fn get_format(extractor: &Box<dyn extractor::Extractor>) -> Result<FileFormat> {
        Ok(extractor.format())
    }

    fn get_arch(extractor: &Box<dyn extractor::Extractor>) -> Result<FileArchitecture> {
        if extractor.bitness() == 32 {
            return Ok(FileArchitecture::I386);
        } else if extractor.bitness() == 64 {
            return Ok(FileArchitecture::AMD64);
        }
        Err(Error::UnsupportedArchError)
    }

    fn get_os(extractor: &Box<dyn extractor::Extractor>) -> Result<Os> {
        match extractor.format() {
            FileFormat::PE | FileFormat::DOTNET => Ok(Os::WINDOWS),
            _ => Ok(Os::LINUX),
        }
    }
}

fn find_function_capabilities<'a>(
    ruleset: &'a crate::rules::RuleSet,
    extractor: &Box<dyn crate::extractor::Extractor>,
    f: &Box<dyn extractor::Function>,
    logger: &dyn Fn(&str),
    map_features: &mut HashMap<crate::rules::features::Feature, Vec<u64>>,
    features_dump: bool,
) -> Result<(
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut function_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();

    for (feature, va) in extractor.extract_global_features()? {
        function_features.entry(feature).or_default().push(va);
    }

    for (feature, va) in extractor.extract_function_features(f)? {
        function_features.entry(feature).or_default().push(va);
    }

    // Condition for .NET and add file features if necessary
    if extractor.is_dot_net() {
        for (feature, va) in extractor.extract_file_features()? {
            function_features.entry(feature).or_default().push(va);
        }
    }

    let blocks = extractor.get_basic_blocks(f)?;
    let mut bb_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();
    for bb in blocks.iter() {
        let mut bb_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();
        for (feature, va) in itertools::chain!(
            extractor.extract_basic_block_features(f, &bb)?,
            extractor.extract_global_features()?
        ) {
            bb_features.entry(feature.clone()).or_default().push(va);
            function_features.entry(feature).or_default().push(va);
        }

        let insns = extractor.get_instructions(f, &bb)?;
        for insn in insns.iter() {
            for (feature, va) in extractor.extract_insn_features(f, insn)? {
                bb_features.entry(feature.clone()).or_default().push(va);
                function_features.entry(feature).or_default().push(va);
            }
        }

        let (_, matches) = match_fn(&ruleset.basic_block_rules, &bb_features, bb.0, logger)?;
        for (rule, res) in matches {
            bb_matches
                .entry(rule)
                .or_default()
                .extend(res.iter().cloned());
            index_rule_matches(
                &mut function_features,
                rule,
                res.iter().map(|&(va, _)| va).collect(),
            )?;
        }
    }

    let (_, function_matches) = match_fn(
        &ruleset.function_rules,
        &function_features,
        &f.offset(),
        logger,
    )?;

    if features_dump {
        map_features.extend(function_features.clone());
    }

    Ok((function_matches, bb_matches, function_features.len()))
}
fn aggregate_matches<'a, T: Clone>(
    all_matches: &mut HashMap<&'a crate::rules::Rule, Vec<T>>,
    new_matches: &HashMap<&'a crate::rules::Rule, Vec<T>>,
) {
    for (rule, res) in new_matches {
        all_matches.entry(rule).or_default().extend(res.clone());
    }
}

fn find_capabilities(
    ruleset: &crate::rules::RuleSet,
    extractor: &Box<dyn crate::extractor::Extractor>,
    logger: &dyn Fn(&str),
    features_dump: bool,
) -> Result<(
    HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    HashMap<u64, usize>,
    HashMap<String, HashMap<String, HashSet<u64>>>,
)> {
    let mut all_function_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> =
        HashMap::new();
    let mut all_bb_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> =
        HashMap::new();

    let mut meta = HashMap::new();

    let functions = extractor.get_functions()?;
    logger("functions capabilities started");

    let mut map_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();

    for (index, (function_address, f)) in functions.iter().enumerate() {
        let (function_matches, bb_matches, feature_count) = find_function_capabilities(
            ruleset,
            extractor,
            f,
            logger,
            &mut map_features,
            features_dump,
        )?;
        meta.insert(*function_address, feature_count);

        aggregate_matches(&mut all_function_matches, &function_matches);
        aggregate_matches(&mut all_bb_matches, &bb_matches);

        logger(&format!(
            "function 0x{:02x} {} from {} processed",
            function_address,
            index,
            functions.len()
        ));
    }

    logger("functions capabilities finish");
    //# collection of features that captures the rule matches within function and BB scopes.
    //# mapping from feature (matched rule) to set of addresses at which it matched.
    let mut function_and_lower_features = HashMap::new();
    for (rule, results) in itertools::chain!(&all_function_matches, &all_bb_matches) {
        let locations: Vec<u64> = results.iter().map(|a| a.0).collect();
        index_rule_matches(&mut function_and_lower_features, rule, locations)?;
    }

    let (all_file_matches, feature_count) = find_file_capabilities(
        ruleset,
        extractor,
        &function_and_lower_features,
        logger,
        &mut map_features,
        features_dump,
    )?;

    let mut matches = HashMap::new();
    for (rule, res) in itertools::chain!(&all_bb_matches, &all_function_matches, &all_file_matches)
    {
        matches.insert((*rule).clone(), res.clone());
    }

    meta.insert(0, feature_count);
    let mut map_features_string: HashMap<String, HashMap<String, HashSet<u64>>> = HashMap::new();

    for (key, offsets) in &map_features {
        let feature_type = key.get_name();
        let feature_value = key.get_value()?;

        let feature_map = map_features_string.entry(feature_type).or_default();

        let offsets_set = feature_map.entry(feature_value).or_default();

        for offset in offsets {
            offsets_set.insert(*offset);
        }
    }

    Ok((matches, meta, map_features_string))
}

fn find_file_capabilities<'a>(
    ruleset: &'a crate::rules::RuleSet,
    extractor: &Box<dyn crate::extractor::Extractor>,
    function_features: &HashMap<crate::rules::features::Feature, Vec<u64>>,
    logger: &dyn Fn(&str),
    map_features: &mut HashMap<crate::rules::features::Feature, Vec<u64>>,
    features_dump: bool,
) -> Result<(
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut file_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();
    for (feature, va) in itertools::chain!(
        extractor.extract_file_features()?,
        extractor.extract_global_features()?
    ) {
        file_features.entry(feature.clone()).or_default().push(va);
    }

    for (feature, addresses) in function_features {
        file_features
            .entry(feature.clone())
            .or_default()
            .extend(addresses.iter().cloned());
    }

    let mut matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();
    for rule_set in [&ruleset.file_rules, &ruleset.function_rules].iter() {
        for (rule, matched) in match_fn(rule_set, &file_features, &0, logger)?.1 {
            matches
                .entry(rule)
                .or_default()
                .extend(matched.iter().cloned());
        }
    }

    if features_dump {
        map_features.extend(file_features.clone());
    }

    Ok((matches, file_features.len()))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionCapabilities {
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    address: usize,
    features: usize,
    capabilities: Vec<String>,
}

fn parse_parts_id(s: &str) -> Result<(Vec<String>, String)> {
    let re = regex::Regex::new(r"^(.*?)(?:\s*\[(.*?)])?$").unwrap();
    if let Some(caps) = re.captures(s) {
        let parts_str = caps.get(1).map_or("", |m| m.as_str());
        let parts: Vec<String> = parts_str
            .split("::")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let id = caps.get(2).map_or("", |m| m.as_str()).to_string();
        Ok((parts, id))
    } else {
        Err(Error::InvalidRule(0, s.to_string()))
    }
}
#[cfg(feature = "properties")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Properties {
    pub format: FileFormat,
    pub arch: FileArchitecture,
    pub os: Os,
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    pub base_address: usize,
}
#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Attacks {
    pub id: String,
    pub subtechnique: String,
    pub tactic: String,
    pub technique: String,
}
impl Attacks {
    fn from_str(s: &str) -> Result<Self> {
        let (parts, id) = parse_parts_id(s)?;
        let tactic = parts.first().cloned().unwrap_or_default();
        let technique = parts.get(1).cloned().unwrap_or_default();
        let subtechnique = parts.get(2).cloned().unwrap_or_default();

        Ok(Self {
            tactic,
            technique,
            subtechnique,
            id,
        })
    }
}

impl Default for Attacks {
    fn default() -> Self {
        Attacks {
            id: "".to_string(),
            subtechnique: "".to_string(),
            tactic: "".to_string(),
            technique: "".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Mbc {
    pub behavior: String,
    pub id: String,
    pub objective: String,
    pub method: String,
}
impl Default for Mbc {
    fn default() -> Self {
        Mbc {
            behavior: "".to_string(),
            id: "".to_string(),
            objective: "".to_string(),
            method: "".to_string(),
        }
    }
}
impl Mbc {
    fn from_str(s: &str) -> Result<Self> {
        let (parts, id) = parse_parts_id(s)?;
        let objective = parts.first().cloned().unwrap_or_default();
        let behavior = parts.get(1).cloned().unwrap_or_default();
        let method = parts.get(2).cloned().unwrap_or_default();

        Ok(Self {
            objective,
            behavior,
            method,
            id,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CapabilityAssociation {
    pub attack: BTreeSet<Attacks>,
    pub mbc: BTreeSet<Mbc>,
    pub namespace: String,
    pub name: String,
    pub address: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileCapabilities {
    #[cfg(feature = "properties")]
    pub properties: Properties,
    pub attacks: BTreeMap<String, BTreeSet<String>>,
    pub mbc: BTreeMap<String, BTreeSet<String>>,
    pub capability_namespaces: BTreeMap<String, String>,
    #[cfg(feature = "verbose")]
    pub features: usize,
    #[cfg(feature = "verbose")]
    pub functions_capabilities: BTreeMap<u64, FunctionCapabilities>,
    pub tags: BTreeSet<String>,
    pub map_features: HashMap<String, HashMap<String, HashSet<u64>>>,
    pub capabilities_associations: BTreeMap<String, CapabilityAssociation>,
}

fn match_fn<'a>(
    rules: &'a [crate::rules::Rule],
    features: &HashMap<crate::rules::features::Feature, Vec<u64>>,
    va: &u64,
    logger: &dyn Fn(&str),
) -> Result<(
    HashMap<crate::rules::features::Feature, Vec<u64>>,
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
)> {
    let mut results: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();
    let mut features = features.clone();
    for (_index, rule) in rules.iter().enumerate() {
        logger(&format!(
            "\t\t\tmatches rule {} from {}",
            _index,
            rules.len()
        ));
        if let Ok(res) = rule.evaluate(&features) {
            if res.0 {
                match results.get_mut(rule) {
                    Some(s) => {
                        s.push((*va, res));
                    }
                    _ => {
                        results.insert(rule, vec![(*va, res)]);
                    }
                }
                index_rule_matches(&mut features, rule, vec![*va])?;
            }
        }
    }
    Ok((features, results))
}

fn index_rule_matches(
    features: &mut HashMap<crate::rules::features::Feature, Vec<u64>>,
    rule: &crate::rules::Rule,
    locations: Vec<u64>,
) -> Result<()> {
    let matched_rule_feature = crate::rules::features::Feature::MatchedRule(
        crate::rules::features::MatchedRuleFeature::new(&rule.name, "")?,
    );

    features
        .entry(matched_rule_feature.clone())
        .or_default()
        .extend(locations.iter().cloned());

    if let Some(Yaml::String(namespace)) = rule.meta.get(&Yaml::String("namespace".to_string())) {
        let parts: Vec<&str> = namespace.split('/').collect();
        for i in 0..parts.len() {
            let sub_namespace = parts[..=i].join("/");
            let ns_feature = crate::rules::features::Feature::MatchedRule(
                crate::rules::features::MatchedRuleFeature::new(&sub_namespace, "")?,
            );
            features
                .entry(ns_feature)
                .or_default()
                .extend(locations.iter().cloned());
        }
    }
    Ok(())
}

fn get_format(f: &str) -> Result<(FileFormat, Vec<u8>)> {
    let buffer = std::fs::read(f)?;
    if buffer.starts_with(b"MZ") {
        Ok((FileFormat::PE, buffer))
    } else if buffer.starts_with(b"\x7fELF") {
        Ok((FileFormat::ELF, buffer))
    } else {
        Err(Error::UnsupportedFormatError)
    }
}

fn get_file_extractors(
    f: &str,
    format: FileFormat,
    data: &Vec<u8>,
    high_accuracy: bool,
    resolve_tailcalls: bool,
) -> Result<Box<dyn extractor::Extractor>> {
    match format {
        FileFormat::PE => {
            if let Ok(e) = extractor::dnfile::Extractor::new(f) {
                Ok(Box::new(e))
            } else {
                Ok(Box::new(extractor::smda::Extractor::new(
                    f,
                    high_accuracy,
                    resolve_tailcalls,
                    data,
                )?))
            }
        }
        FileFormat::ELF => Ok(Box::new(extractor::smda::Extractor::new(
            f,
            high_accuracy,
            resolve_tailcalls,
            data,
        )?)),
        _ => Ok(Box::new(extractor::smda::Extractor::new(
            f,
            high_accuracy,
            resolve_tailcalls,
            data,
        )?)),
    }
}
