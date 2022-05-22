#![allow(clippy::type_complexity)]
pub(crate) mod consts;
//#[macro_use]
//extern crate maplit;
mod extractor;
pub mod rules;
mod sede;

use consts::{Format, Os};
use sede::{from_hex, to_hex};
use serde::{Deserialize, Serialize};
use smda::{FileArchitecture, FileFormat};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    thread::spawn,
};

mod error;
pub use crate::error::Error;
pub type Result<T> = std::result::Result<T, Error>;

impl FileCapabilities {
    pub fn from_file(
        file_name: &str,
        rule_path: &str,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        logger: &dyn Fn(&str),
    ) -> Result<Self> {
        //! Loads a binary from a given file for capability analysis
        //! ## Example
        //! ```rust
        //! use capa::FileCapabilities;
        //!
        //! let rules_path = "./rules";
        //! let file_to_analyse = "./demo.exe";
        //! let result = FileCapabilities::from_file(file_to_analyse, rules_path, true, true, &|_s| {});
        //! println!("{:?}", result);
        //! ```
        let f = file_name.to_string();
        let r = rule_path.to_string();
        let mut format = get_format(&f)?;
        let file_extractors = get_file_extractors(&f, format)?;
        for extractor in file_extractors {
            if extractor.is_dot_net() {
                format = Format::DOTNET;
            }
        }

        let rules_thread_handle = spawn(move || rules::RuleSet::new(&r));
        let extractor = get_extractor(&f, format, high_accuracy, resolve_tailcalls)?;
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
            let (capabilities, _counts) = find_capabilities(&rules, &extractor, logger)?;
            file_capabilities.update_capabilities(&capabilities)?;
        }
        #[cfg(feature = "verbose")]
        {
            let (capabilities, counts) = find_capabilities(&rules, &extractor, logger)?;
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
        })
    }

    fn update_capabilities(
        &mut self,
        capabilities: &HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
        #[cfg(feature = "verbose")] counts: &HashMap<u64, usize>,
    ) -> Result<()> {
        for rule in capabilities.keys() {
            if rule
                .meta
                .contains_key(&yaml_rust::Yaml::String("att&ck".to_string()))
            {
                if let yaml_rust::Yaml::Array(s) =
                    &rule.meta[&yaml_rust::Yaml::String("att&ck".to_string())]
                {
                    for p in s {
                        let parts: Vec<&str> = p
                            .as_str()
                            .ok_or_else(|| Error::InvalidRule(line!(), file!().to_string()))?
                            .split("::")
                            .collect();
                        if parts.len() > 1 {
                            let ss = parts[1..].join("::");
                            let re = regex::Regex::new(r##"[^\]]*\[(?P<tag>[^\]]*)\]"##)?;
                            if let Some(s) = re.captures(&ss) {
                                if let Some(t) = s.name("tag") {
                                    self.tags.insert(t.as_str().to_string());
                                }
                            }
                            match self.attacks.get_mut(parts[0]) {
                                Some(s) => {
                                    s.insert(ss);
                                }
                                _ => {
                                    self.attacks.insert(
                                        parts[0].to_string(),
                                        vec![ss.to_string()].iter().cloned().collect(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if rule
                .meta
                .contains_key(&yaml_rust::Yaml::String("mbc".to_string()))
            {
                if let yaml_rust::Yaml::Array(s) =
                    &rule.meta[&yaml_rust::Yaml::String("mbc".to_string())]
                {
                    for p in s {
                        let parts: Vec<&str> = p
                            .as_str()
                            .ok_or_else(|| Error::InvalidRule(line!(), file!().to_string()))?
                            .split("::")
                            .collect();
                        if parts.len() > 1 {
                            let ss = parts[1..].join("::");
                            let re = regex::Regex::new(r##"[^\]]*\[(?P<tag>[^\]]*)\]"##)?;
                            if let Some(s) = re.captures(&ss) {
                                if let Some(t) = s.name("tag") {
                                    self.tags.insert(t.as_str().to_string());
                                }
                            }
                            match self.mbc.get_mut(parts[0]) {
                                Some(s) => {
                                    s.insert(ss);
                                }
                                _ => {
                                    self.mbc.insert(
                                        parts[0].to_string(),
                                        vec![ss.to_string()].iter().cloned().collect(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if rule
                .meta
                .contains_key(&yaml_rust::Yaml::String("namespace".to_string()))
            {
                if let yaml_rust::Yaml::String(s) =
                    &rule.meta[&yaml_rust::Yaml::String("namespace".to_string())]
                {
                    self.capability_namespaces
                        .insert(rule.name.clone(), s.clone());
                }
            }
        }
        #[cfg(feature = "verbose")]
        {
            self.features = counts[&0];
        }

        #[cfg(feature = "verbose")]
        for (addr, count) in counts {
            if addr == &0 {
                continue;
            }
            let mut fc = FunctionCapabilities {
                address: *addr as usize,
                features: *count,
                capabilities: vec![],
            };
            for (rule, caps) in capabilities {
                for cap in caps {
                    if &cap.0 == addr {
                        fc.capabilities.push(rule.name.clone());
                    }
                }
            }
            if fc.capabilities.len() > 0 {
                self.functions_capabilities.insert(addr.clone(), fc);
            }
        }
        Ok(())
    }

    fn get_format(extractor: &Box<dyn extractor::Extractor>) -> Result<extractor::FileFormat> {
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
            extractor::FileFormat::PE | extractor::FileFormat::DOTNET => Ok(Os::WINDOWS),
            _ => Ok(Os::LINUX),
        }
    }
}

fn find_function_capabilities<'a>(
    ruleset: &'a crate::rules::RuleSet,
    extractor: &Box<dyn crate::extractor::Extractor>,
    f: &Box<dyn extractor::Function>,
    logger: &dyn Fn(&str),
) -> Result<(
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    //    println!("0x{:02x}", f.offset);
    let mut function_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();
    let mut bb_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();

    for (feature, va) in itertools::chain!(
        extractor.extract_function_features(f)?,
        extractor.extract_global_features()?
    ) {
        match function_features.get_mut(&feature) {
            Some(s) => s.push(va),
            _ => {
                function_features.insert(feature.clone(), vec![va]);
            }
        }
    }
    let blocks = extractor.get_basic_blocks(f)?;
    let _n_blocks = blocks.len();
    for (index, bb) in blocks.iter().enumerate() {
        logger(&format!("\tblock {} from {}", index, _n_blocks));
        let mut bb_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();
        for (feature, va) in extractor.extract_basic_block_features(f, &bb)? {
            match bb_features.get_mut(&feature) {
                Some(s) => s.push(va),
                _ => {
                    bb_features.insert(feature.clone(), vec![va]);
                }
            }
            match function_features.get_mut(&feature) {
                Some(s) => s.push(va),
                _ => {
                    function_features.insert(feature.clone(), vec![va]);
                }
            }
        }
        for (feature, va) in extractor.extract_global_features()? {
            match bb_features.get_mut(&feature) {
                Some(s) => s.push(va),
                _ => {
                    bb_features.insert(feature.clone(), vec![va]);
                }
            }
            match function_features.get_mut(&feature) {
                Some(s) => s.push(va),
                _ => {
                    function_features.insert(feature.clone(), vec![va]);
                }
            }
        }

        let insns = extractor.get_instructions(f, &bb)?;
        let _n_insns = insns.len();
        for (_insn_index, insn) in insns.iter().enumerate() {
            //            println!("0x{:02x}, {:?}", insn.offset, insn);
            //            logger(&format!("\t\tinstruction {} from {}", insn_index, _n_insns));
            for (feature, va) in extractor.extract_insn_features(f, insn)? {
                match bb_features.get_mut(&feature) {
                    Some(s) => s.push(va),
                    _ => {
                        bb_features.insert(feature.clone(), vec![va]);
                    }
                }
                match function_features.get_mut(&feature) {
                    Some(s) => s.push(va),
                    _ => {
                        function_features.insert(feature.clone(), vec![va]);
                    }
                }
            }
            for (feature, va) in extractor.extract_global_features()? {
                match bb_features.get_mut(&feature) {
                    Some(s) => s.push(va),
                    _ => {
                        bb_features.insert(feature.clone(), vec![va]);
                    }
                }
                match function_features.get_mut(&feature) {
                    Some(s) => s.push(va),
                    _ => {
                        function_features.insert(feature.clone(), vec![va]);
                    }
                }
            }
        }
        let (_, matches) = match_fn(&ruleset.basic_block_rules, &bb_features, bb.0, logger)?;
        for (rule, res) in &matches {
            match bb_matches.get_mut(rule) {
                Some(s) => {
                    for r in res {
                        s.push(r.clone());
                    }
                }
                _ => {
                    bb_matches.insert(rule, res.clone());
                }
            }
            for (va, _) in res {
                index_rule_matches(&mut function_features, rule, vec![*va])?;
            }
        }
    }
    //    println!("{:?}", function_features);
    let (_, function_matches) = match_fn(
        &ruleset.function_rules,
        &function_features,
        &f.offset(),
        logger,
    )?;
    Ok((function_matches, bb_matches, function_features.len()))
}

fn find_capabilities(
    ruleset: &crate::rules::RuleSet,
    extractor: &Box<dyn crate::extractor::Extractor>,
    logger: &dyn Fn(&str),
) -> Result<(
    HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    HashMap<u64, usize>,
)> {
    let mut all_function_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> =
        HashMap::new();
    let mut all_bb_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> =
        HashMap::new();

    let mut meta = HashMap::new();
    let functions = extractor.get_functions()?;
    let _n_funcs = functions.len();
    logger(&"functions capabilities started".to_string());
    for (index, (function_address, f)) in functions.iter().enumerate() {
        logger(&format!(
            "function 0x{:02x} {} from {} started",
            function_address, index, _n_funcs
        ));
        //TODO capstone not understand this
        //if extractor.is_library_function(function_address){
        //let function_name = extractor.get_function_name(function_address)?;
        //}
        let (function_matches, bb_matches, feature_count) =
            find_function_capabilities(ruleset, extractor, f, logger)?;
        meta.insert(*function_address, feature_count);
        for (rule, res) in &function_matches {
            match all_function_matches.get_mut(rule) {
                Some(s) => {
                    s.extend(res.clone());
                }
                _ => {
                    all_function_matches.insert(rule, res.clone());
                }
            }
        }
        for (rule, res) in &bb_matches {
            match all_bb_matches.get_mut(rule) {
                Some(s) => {
                    s.extend(res.clone());
                }
                _ => {
                    all_bb_matches.insert(rule, res.clone());
                }
            }
        }
        logger(&format!(
            "function 0x{:02x} {} from {} started",
            function_address, index, _n_funcs
        ));
    }
    logger(&"functions capabilities finish".to_string());
    //# collection of features that captures the rule matches within function and BB scopes.
    //# mapping from feature (matched rule) to set of addresses at which it matched.
    let mut function_and_lower_features = HashMap::new();
    for (rule, results) in itertools::chain!(&all_function_matches, &all_bb_matches) {
        let locations: Vec<u64> = results.iter().map(|a| a.0).collect();
        index_rule_matches(&mut function_and_lower_features, rule, locations)?;
    }

    let (all_file_matches, feature_count) =
        find_file_capabilities(ruleset, extractor, &function_and_lower_features, logger)?;

    let mut matches = HashMap::new();
    for (rule, res) in itertools::chain!(&all_bb_matches, &all_function_matches, &all_file_matches)
    {
        matches.insert((*rule).clone(), res.clone());
    }

    meta.insert(0, feature_count);
    Ok((matches, meta))
}

fn find_file_capabilities<'a>(
    ruleset: &'a crate::rules::RuleSet,
    extractor: &Box<dyn crate::extractor::Extractor>,
    function_features: &HashMap<crate::rules::features::Feature, Vec<u64>>,
    logger: &dyn Fn(&str),
) -> Result<(
    HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut file_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();
    for (feature, va) in itertools::chain!(
        extractor.extract_file_features()?,
        extractor.extract_global_features()?
    ) {
        // not all file features may have virtual addresses.
        // if not, then at least ensure the feature shows up in the index.
        // the set of addresses will still be empty.
        if va > 0 {
            match file_features.get_mut(&feature) {
                Some(s) => {
                    s.push(va);
                }
                _ => {
                    file_features.insert(feature.clone(), vec![va]);
                }
            }
        } else {
            file_features
                .entry(feature)
                .or_insert_with(std::vec::Vec::new);
        }
    }

    for (f1, f2) in function_features {
        file_features.insert(f1.clone(), f2.clone());
    }

    let (_, matches) = match_fn(&ruleset.file_rules, &file_features, &0x0, logger)?;
    Ok((matches, file_features.len()))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionCapabilities {
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    address: usize,
    features: usize,
    capabilities: Vec<String>,
}

#[cfg(feature = "properties")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Properties {
    pub format: extractor::FileFormat,
    pub arch: FileArchitecture,
    pub os: Os,
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    pub base_address: usize,
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
    for location in &locations {
        match features.get_mut(&crate::rules::features::Feature::MatchedRule(
            crate::rules::features::MatchedRuleFeature::new(&rule.name, "")?,
        )) {
            Some(s) => {
                s.push(*location);
            }
            None => {
                features.insert(
                    crate::rules::features::Feature::MatchedRule(
                        crate::rules::features::MatchedRuleFeature::new(&rule.name, "")?,
                    ),
                    vec![*location],
                );
            }
        }
    }
    if rule
        .meta
        .contains_key(&yaml_rust::Yaml::String("namespace".to_string()))
    {
        if let yaml_rust::Yaml::String(namespace) =
            &rule.meta[&yaml_rust::Yaml::String("namespace".to_string())]
        {
            let mut ns = Some(namespace.clone());
            while let Some(namespace) = ns {
                for location in &locations {
                    match features.get_mut(&crate::rules::features::Feature::MatchedRule(
                        crate::rules::features::MatchedRuleFeature::new(&namespace, "")?,
                    )) {
                        Some(s) => {
                            s.push(*location);
                        }
                        None => {
                            features.insert(
                                crate::rules::features::Feature::MatchedRule(
                                    crate::rules::features::MatchedRuleFeature::new(
                                        &namespace, "",
                                    )?,
                                ),
                                vec![*location],
                            );
                        }
                    }
                }
                let parts: Vec<&str> = namespace.split('/').collect();
                if parts.len() == 1 {
                    ns = None;
                } else {
                    let mut nss = "".to_string();
                    for item in parts.iter().take(parts.len() - 1) {
                        nss += "/";
                        nss += item;
                    }
                    ns = Some(nss[1..].to_string());
                }
            }
        }
    }
    Ok(())
}

fn get_format(f: &str) -> Result<Format> {
    let buffer = std::fs::read(f)?;
    if buffer.starts_with(b"MZ") {
        Ok(Format::PE)
    } else if buffer.starts_with(b"\x7fELF") {
        Ok(Format::ELF)
    } else {
        Err(error::Error::UnsupportedFormatError)
    }
}

fn get_file_extractors(f: &str, format: Format) -> Result<Vec<Box<dyn extractor::Extractor>>> {
    let mut res: Vec<Box<dyn extractor::Extractor>> = vec![];
    match format {
        Format::PE => {
            res.push(Box::new(extractor::smda::Extractor::new(f, false, false)?));
            if let Ok(e) = extractor::dnfile::Extractor::new(f) {
                res.push(Box::new(e));
            }
            Ok(res)
        }
        Format::ELF => {
            res.push(Box::new(extractor::smda::Extractor::new(f, false, false)?));
            Ok(res)
        }
        _ => Ok(res),
    }
}

fn get_extractor(
    f: &str,
    format: Format,
    high_accuracy: bool,
    resolve_tailcalls: bool,
) -> Result<Box<dyn extractor::Extractor>> {
    match format {
        Format::PE => Ok(Box::new(extractor::smda::Extractor::new(
            f,
            high_accuracy,
            resolve_tailcalls,
        )?)),
        Format::DOTNET => Ok(Box::new(extractor::dnfile::Extractor::new(f)?)),
        Format::ELF => Ok(Box::new(extractor::smda::Extractor::new(
            f,
            high_accuracy,
            resolve_tailcalls,
        )?)),
    }
}
