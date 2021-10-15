mod error;
mod helpers;
use error::Error;
mod result;
use result::Result;
mod extractor;
pub mod rules;
use goblin::Object;
use md5::Digest;

use smda::{function::Function, Arch, Format};

#[derive(Debug, Clone, serde::Serialize)]
pub enum Os {
    WINDOWS,
    HPUX,
    NETBSD,
    LINUX,
    HURD,
    _86OPEN,
    SOLARIS,
    AIX,
    IRIX,
    FREEBSD,
    TRU64,
    MODESTO,
    OPENBSD,
    OPENVMS,
    NSK,
    AROS,
    FENIXOS,
    CLOUD,
    UNDEFINED,
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Os::WINDOWS => write!(f, "Windows"),
            Os::HPUX => write!(f, "HP Unix"),
            Os::NETBSD => write!(f, "NetBSD"),
            Os::LINUX => write!(f, "Linux"),
            Os::HURD => write!(f, "Hurd"),
            Os::_86OPEN => write!(f, "86Open"),
            Os::SOLARIS => write!(f, "Solaris"),
            Os::AIX => write!(f, "Aix"),
            Os::IRIX => write!(f, "Irix"),
            Os::FREEBSD => write!(f, "FreeBSD"),
            Os::TRU64 => write!(f, "Tru64"),
            Os::MODESTO => write!(f, "Modesto"),
            Os::OPENBSD => write!(f, "OpenBSD"),
            Os::OPENVMS => write!(f, "OpenVMS"),
            Os::NSK => write!(f, "NSK"),
            Os::AROS => write!(f, "Aros"),
            Os::FENIXOS => write!(f, "FenixOS"),
            Os::CLOUD => write!(f, "Cloud"),
            Os::UNDEFINED => write!(f, "undefined"),
        }
    }
}

#[derive(Debug)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Debug)]
pub struct CapabilityExtractorSettings {}

#[derive(Debug)]
pub struct CapabilityExtractor {
    format: Format,
    arch: Arch,
    endian: Endian,
    os: Os,
}

impl CapabilityExtractor {
    pub fn new(
        file_name: &str,
        _settings: Option<CapabilityExtractorSettings>,
    ) -> result::Result<CapabilityExtractor> {
        let path = std::path::Path::new(file_name);
        let buffer = std::fs::read(path)?;
        match Object::parse(&buffer)? {
            Object::Elf(elf) => Ok(CapabilityExtractor {
                format: Format::ELF,
                arch: extractor::elf::get_arch(&elf)?,
                endian: extractor::elf::get_endian(&elf)?,
                os: extractor::elf::get_os(&elf)?,
            }),
            Object::PE(pe) => Ok(CapabilityExtractor {
                format: Format::PE,
                arch: extractor::pe::get_arch(&pe)?,
                endian: extractor::pe::get_endian(&pe)?,
                os: extractor::pe::get_os(&pe)?,
            }),
            _ => Err(error::Error::UnsupportedFormatError),
        }
    }
}

pub fn proceed_file(
    file_name: &str,
    rule_path: &str,
    logger: &dyn Fn(&str),
    high_accuracy: bool,
) -> result::Result<String> {
    let extractor = extractor::Extractor::new(file_name, high_accuracy)?;
    logger(&format!("loading rules..."));
    let rules = rules::RuleSet::new(rule_path)?;
    logger(&format!("loaded {} rules", rules.rules.len()));
    let mut meta = Meta::new(file_name, rule_path, &extractor)?;
    let (capabilities, counts) = find_capabilities(&rules, &extractor, logger)?;

    meta.update_capabilities(&capabilities, &counts)?;
    Ok(serde_json::to_string_pretty(&meta)?)
}

pub fn find_function_capabilities<'a>(
    ruleset: &'a crate::rules::RuleSet,
    extractor: &crate::extractor::Extractor,
    f: &Function,
    logger: &dyn Fn(&str),
) -> Result<(
    std::collections::HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    std::collections::HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut function_features: std::collections::HashMap<
        crate::rules::features::Feature,
        Vec<u64>,
    > = std::collections::HashMap::new();
    let mut bb_matches: std::collections::HashMap<
        &crate::rules::Rule,
        Vec<(u64, (bool, Vec<u64>))>,
    > = std::collections::HashMap::new();

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
        let mut bb_features: std::collections::HashMap<crate::rules::features::Feature, Vec<u64>> =
            std::collections::HashMap::new();
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
            //            logger(&format!("\t\tinstruction {} from {}", insn_index, _n_insns));
            for (feature, va) in extractor.extract_insn_features(f, &bb, insn)? {
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
                index_rule_matches(&mut function_features, &rule, vec![va.clone()])?;
            }
        }
    }
    let (_, function_matches) = match_fn(
        &ruleset.function_rules,
        &function_features,
        &f.offset,
        logger,
    )?;
    Ok((function_matches, bb_matches, function_features.len()))
}

pub fn find_capabilities(
    ruleset: &crate::rules::RuleSet,
    extractor: &crate::extractor::Extractor,
    logger: &dyn Fn(&str),
) -> Result<(
    std::collections::HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    std::collections::HashMap<u64, usize>,
)> {
    let mut all_function_matches: std::collections::HashMap<
        &crate::rules::Rule,
        Vec<(u64, (bool, Vec<u64>))>,
    > = std::collections::HashMap::new();
    let mut all_bb_matches: std::collections::HashMap<
        &crate::rules::Rule,
        Vec<(u64, (bool, Vec<u64>))>,
    > = std::collections::HashMap::new();

    let mut meta = std::collections::HashMap::new();
    let functions = extractor.get_functions()?;
    let _n_funcs = functions.len();
    logger(&format!("functions capabilities started"));
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
        meta.insert(function_address.clone(), feature_count);
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
    logger(&format!("functions capabilities finish"));
    //# collection of features that captures the rule matches within function and BB scopes.
    //# mapping from feature (matched rule) to set of addresses at which it matched.
    let mut function_and_lower_features = std::collections::HashMap::new();
    for (rule, results) in itertools::chain!(&all_function_matches, &all_bb_matches) {
        let locations: Vec<u64> = results.iter().map(|a| a.0).collect();
        index_rule_matches(&mut function_and_lower_features, rule, locations)?;
    }

    let (all_file_matches, feature_count) =
        find_file_capabilities(ruleset, extractor, &function_and_lower_features, logger)?;

    let mut matches = std::collections::HashMap::new();
    for (rule, res) in itertools::chain!(&all_bb_matches, &all_function_matches, &all_file_matches)
    {
        matches.insert((*rule).clone(), res.clone());
    }

    meta.insert(0, feature_count);
    Ok((matches, meta))
}

pub fn find_file_capabilities<'a>(
    ruleset: &'a crate::rules::RuleSet,
    extractor: &crate::extractor::Extractor,
    function_features: &std::collections::HashMap<crate::rules::features::Feature, Vec<u64>>,
    logger: &dyn Fn(&str),
) -> Result<(
    std::collections::HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut file_features: std::collections::HashMap<crate::rules::features::Feature, Vec<u64>> =
        std::collections::HashMap::new();
    for (feature, va) in itertools::chain!(
        extractor.extract_file_features()?,
        extractor.extract_global_features()?
    ) {
        //not all file features may have virtual addresses.
        //if not, then at least ensure the feature shows up in the index.
        //the set of addresses will still be empty.
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
            if !file_features.contains_key(&feature) {
                file_features.insert(feature, vec![]);
            }
        }
    }
    // println!("{:?}", file_features);
    //logger.debug("analyzed file and extracted %d features",
    // len(file_features))
    for (f1, f2) in function_features {
        file_features.insert(f1.clone(), f2.clone());
    }

    let (_, matches) = match_fn(&ruleset.file_rules, &file_features, &0x0, logger)?;
    Ok((matches, file_features.len()))
}

#[derive(Debug, serde::Serialize)]
pub struct FunctionCapabilities {
    address: u64,
    features: usize,
    capabilities: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct BasicProperties {
    md5: String,
    sha1: String,
    sha256: String,
    path: String,
    format: Format,
    arch: Arch,
    os: Os,
    base_address: u64,
    compilation_time: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct Section {
    name: String,
    address: u64,
    size: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct Import {
    lib: String,
    symbol: String,
    #[serde(serialize_with = "to_hex")]
    offset: usize,
}

fn to_hex<S>(x: &usize, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&format!("0x{:08x}", x))
}

#[derive(Debug, serde::Serialize)]
pub struct Meta {
    basic_properties: BasicProperties,
    #[serde(skip_serializing)]
    sections: Vec<Section>,
    #[serde(skip_serializing)]
    imports: Vec<Import>,
    attacks: std::collections::HashMap<String, std::collections::HashSet<String>>,
    mbc: std::collections::HashMap<String, std::collections::HashSet<String>>,
    capability_namespaces: std::collections::HashMap<String, String>,
    #[cfg(feature = "verbose")]
    rules_path: String,
    #[cfg(feature = "verbose")]
    features: usize,
    #[cfg(feature = "verbose")]
    functions_capabilities: std::collections::HashMap<u64, FunctionCapabilities>,
}

impl Meta {
    pub fn new(
        sample_path: &str,
        rules_path: &str,
        extractor: &extractor::Extractor,
    ) -> Result<Meta> {
        let mut md5_hasher = md5::Md5::new();
        let mut sha1_hasher = sha1::Sha1::new();
        let mut sha256_hasher = sha2::Sha256::new();

        md5_hasher.update(extractor.get_buf()?);
        sha1_hasher.update(extractor.get_buf()?);
        sha256_hasher.update(extractor.get_buf()?);

        return Ok(Meta {
            basic_properties: BasicProperties {
                md5: hex::encode(md5_hasher.finalize()),
                sha1: hex::encode(sha1_hasher.finalize()),
                sha256: hex::encode(sha256_hasher.finalize()),
                path: sample_path.to_string(),
                format: Meta::get_format(extractor)?,
                arch: Meta::get_arch(extractor)?,
                os: Meta::get_os(extractor)?,
                base_address: extractor.get_base_address()?,
                compilation_time: 0,
            },
            sections: extractor
                .report
                .sections
                .iter()
                .map(|s| Section {
                    name: s.0.trim_matches(char::from(0)).to_string(),
                    address: s.1,
                    size: s.2,
                })
                .collect(),
            imports: extractor
                .report
                .imports
                .iter()
                .map(|s| Import {
                    lib: s.0.clone(),
                    symbol: s.1.clone(),
                    offset: s.2,
                })
                .collect(),
            attacks: std::collections::HashMap::new(),
            mbc: std::collections::HashMap::new(),
            capability_namespaces: std::collections::HashMap::new(),
            #[cfg(feature = "verbose")]
            rules_path: rules_path.to_string(),
            #[cfg(feature = "verbose")]
            features: 0,
            #[cfg(feature = "verbose")]
            functions_capabilities: std::collections::HashMap::new(),
        });
    }

    pub fn update_capabilities(
        &mut self,
        capabilities: &std::collections::HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
        counts: &std::collections::HashMap<u64, usize>,
    ) -> Result<()> {
        for (rule, _) in capabilities {
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
                            .ok_or(Error::InvalidRule(line!(), file!().to_string()))?
                            .split("::")
                            .collect();
                        if parts.len() > 1 {
                            match self.attacks.get_mut(parts[0]) {
                                Some(s) => {
                                    s.insert(parts[1..].join("::"));
                                }
                                _ => {
                                    self.attacks.insert(
                                        parts[0].to_string(),
                                        vec![parts[1..].join("::").to_string()]
                                            .iter()
                                            .map(|s| s.clone())
                                            .collect(),
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
                            .ok_or(Error::InvalidRule(line!(), file!().to_string()))?
                            .split("::")
                            .collect();
                        if parts.len() > 1 {
                            match self.mbc.get_mut(parts[0]) {
                                Some(s) => {
                                    s.insert(parts[1..].join("::"));
                                }
                                _ => {
                                    self.mbc.insert(
                                        parts[0].to_string(),
                                        vec![parts[1..].join("::").to_string()]
                                            .iter()
                                            .map(|s| s.clone())
                                            .collect(),
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
                address: addr.clone(),
                features: count.clone(),
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

    pub fn get_format(extractor: &extractor::Extractor) -> Result<Format> {
        Ok(extractor.report.format.clone())
    }

    pub fn get_arch(extractor: &extractor::Extractor) -> Result<Arch> {
        if extractor.report.bitness == 32 {
            return Ok(Arch::I386);
        } else if extractor.report.bitness == 64 {
            return Ok(Arch::AMD64);
        }
        Err(Error::UnsupportedArchError)
    }

    pub fn get_os(extractor: &extractor::Extractor) -> Result<Os> {
        if let Format::PE = extractor.report.format {
            return Ok(Os::WINDOWS);
        } else {
            return Ok(Os::LINUX);
        }
    }
}

pub fn match_fn<'a>(
    rules: &'a Vec<crate::rules::Rule>,
    features: &std::collections::HashMap<crate::rules::features::Feature, Vec<u64>>,
    va: &u64,
    logger: &dyn Fn(&str),
) -> Result<(
    std::collections::HashMap<crate::rules::features::Feature, Vec<u64>>,
    std::collections::HashMap<&'a crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
)> {
    let mut results: std::collections::HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> =
        std::collections::HashMap::new();
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
                        s.push((va.clone(), res));
                    }
                    _ => {
                        results.insert(rule, vec![(va.clone(), res)]);
                    }
                }
                index_rule_matches(&mut features, rule, vec![va.clone()])?;
            }
        }
    }
    Ok((features, results))
}

pub fn index_rule_matches(
    features: &mut std::collections::HashMap<crate::rules::features::Feature, Vec<u64>>,
    rule: &crate::rules::Rule,
    locations: Vec<u64>,
) -> Result<()> {
    for location in &locations {
        match features.get_mut(&crate::rules::features::Feature::MatchedRule(
            crate::rules::features::MatchedRuleFeature::new(&rule.name, "")?,
        )) {
            Some(s) => {
                s.push(location.clone());
            }
            None => {
                features.insert(
                    crate::rules::features::Feature::MatchedRule(
                        crate::rules::features::MatchedRuleFeature::new(&rule.name, "")?,
                    ),
                    vec![location.clone()],
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
                            s.push(location.clone());
                        }
                        None => {
                            features.insert(
                                crate::rules::features::Feature::MatchedRule(
                                    crate::rules::features::MatchedRuleFeature::new(
                                        &namespace, "",
                                    )?,
                                ),
                                vec![location.clone()],
                            );
                        }
                    }
                }
                let parts: Vec<&str> = namespace.split("/").collect();
                if parts.len() == 1 {
                    ns = None;
                } else {
                    let mut nss = "".to_string();
                    for i in 0..parts.len() - 1 {
                        nss += "/";
                        nss += parts[i];
                    }
                    ns = Some(nss[1..].to_string());
                }
            }
        }
    }
    Ok(())
}
