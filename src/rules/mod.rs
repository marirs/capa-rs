mod com_db;
pub mod features;
mod statement;

use crate::{Error, Result};
use features::{Feature, RuleFeatureType};
use statement::{
    AndStatement, Description, NotStatement, OrStatement, RangeStatement, SomeStatement, Statement,
    StatementElement, SubscopeStatement,
};
use std::collections::{HashMap, HashSet};
use yaml_rust::{Yaml, YamlLoader, yaml::Hash};

use self::features::{BytesFeature, ComType};

const MAX_BYTES_FEATURE_SIZE: usize = 0x100;

/// 0.5.0: resolve a `com/class:` or `com/interface:` feature into a list
/// of `Feature::Bytes` patterns — one per known CLSID/IID for the named
/// class or interface. Some COM types had multiple GUIDs over Windows
/// versions; all variants are emitted.
///
/// Wrapped in an `OrStatement` by the caller (`mod.rs:1113`), so a rule
/// `com/class: WbemLocator` becomes `or: [bytes: <guid1>, bytes: <guid2>]`
/// at rule-load time and downstream evaluation is just normal Bytes
/// matching against extractor-emitted byte features. No runtime
/// ComFeature evaluator needed.
///
/// Returns an empty Vec if the name is unknown. Caller's `OrStatement`
/// of an empty list evaluates to "never matches", which is the right
/// semantic for an unrecognised COM name (matches Python capa's
/// behaviour — Python raises a `parse error` at rule load, we
/// gracefully no-match).
///
/// The GUID database lives in `src/rules/com_db.rs`, generated from
/// Python capa's `capa/features/com/{classes,interfaces}.py` via
/// `scripts/gen_com_tables.py`. ~29k entries; ~4 MB of source, ~470 KB
/// of `.rodata` in the final binary.
fn translate_com_features(name: &str, com_type: &ComType) -> Vec<StatementElement> {
    let table: &[(&str, &[[u8; 16]])] = match com_type {
        ComType::Class => com_db::COM_CLASSES,
        ComType::Interface => com_db::COM_INTERFACES,
    };
    // Binary search by name (the static table is sorted). Returns
    // empty Vec on miss — Python capa raises at load; we no-match.
    let guids: &[[u8; 16]] = match table.binary_search_by(|(n, _)| n.cmp(&name)) {
        Ok(idx) => table[idx].1,
        Err(_) => return Vec::new(),
    };

    guids
        .iter()
        .filter_map(|guid| {
            // Each GUID becomes a `bytes: <16 raw bytes>` feature.
            // Empty description — the COM rule already names the
            // class in its own description.
            BytesFeature::new(guid.as_slice(), "")
                .ok()
                .map(|bf| StatementElement::Feature(Box::new(Feature::Bytes(bf))))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandType {
    And,
    Or,
    Not,
    Optional,
    Process,
    Thread,
    Call,
    Function,
    BasicBlock,
    Instruction,
    Description,
    CountOrMore,
    Count,
    Feature,
    ComType,
}

impl CommandType {
    // 0.3.21: intentionally not implementing `std::str::FromStr` — that
    // trait's `from_str` returns `Result<Self, Self::Err>` with a strict
    // error-type signature, while this method returns capa-rs's `Result`
    // for consistency with the rest of the parser. Allow the clippy lint.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "and" => Ok(CommandType::And),
            "or" => Ok(CommandType::Or),
            "not" => Ok(CommandType::Not),
            "optional" => Ok(CommandType::Optional),
            "process" => Ok(CommandType::Process),
            "thread" => Ok(CommandType::Thread),
            "call" => Ok(CommandType::Call),
            "function" => Ok(CommandType::Function),
            "basic block" => Ok(CommandType::BasicBlock),
            "instruction" => Ok(CommandType::Instruction),
            "description" => Ok(CommandType::Description),
            s if s.ends_with(" or more") => Ok(CommandType::CountOrMore),
            s if s.starts_with("count(") && s.ends_with(')') => Ok(CommandType::Count),
            s if s.starts_with("com/") => Ok(CommandType::ComType),
            _ => Ok(CommandType::Feature),
        }
    }
}
#[derive(Debug)]
pub enum Value {
    Str(String),
    Bytes(Vec<u8>),
    Int(i128),
    Null,
}

impl Value {
    pub fn get_str(&self) -> Result<String> {
        match self {
            Value::Str(s) => Ok(s.clone()),
            _ => Err(Error::InvalidRule(
                line!(),
                format!("{:?} need to be string", self),
            )),
        }
    }

    pub fn get_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Value::Bytes(s) => Ok(s.clone()),
            _ => Err(Error::InvalidRule(
                line!(),
                format!("{:?} need to be bytes array", self),
            )),
        }
    }

    pub fn get_int(&self) -> Result<i128> {
        match self {
            Value::Int(s) => Ok(*s),
            _ => Err(Error::InvalidRule(
                line!(),
                format!("{:?} need to be int", self),
            )),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Scope {
    None,
    Global,
    Function,
    File,
    BasicBlock,
    Instruction,
    Process,
    Thread,
    Call,
    SpanOfCalls,
}

// 0.4.1: ordered scope tables for Python-compatible
// `is_subscope_compatible`. Reference: capa/rules/__init__.py:596–610.
// A subscope is compatible with the current scope iff it appears at or
// below the current scope in the table the subscope belongs to.
const STATIC_SCOPE_ORDER: &[Scope] = &[
    Scope::File,
    Scope::Function,
    Scope::BasicBlock,
    Scope::Instruction,
];

const DYNAMIC_SCOPE_ORDER: &[Scope] = &[
    Scope::File,
    Scope::Process,
    Scope::Thread,
    Scope::SpanOfCalls,
    Scope::Call,
];

/// 0.4.1: Python-style subscope compatibility check. Returns `true`
/// when a `subscope:` block is allowed inside the current `scope`.
///
/// Static and dynamic scopes form parallel orderings; a subscope is
/// dispatched against whichever ordering contains it. A subscope at
/// or below the current scope's position in that ordering is allowed
/// — e.g. `instruction:` (position 3) inside `static: file`
/// (position 0) is fine: 3 ≥ 0.
///
/// Replaces 0.4.0's hardcoded `if [Scope::X, Scope::Y].contains(...)`
/// checks per subscope arm, which rejected legitimate cross-scope
/// rules like `host-interaction/service/run-as-service.yml`.
///
/// Reference: `capa/rules/__init__.py:613`.
fn is_subscope_compatible(scope: &Scope, subscope: &Scope) -> bool {
    let pos = |order: &[Scope], s: &Scope| order.iter().position(|x| x == s);

    if STATIC_SCOPE_ORDER.contains(subscope) {
        match (
            pos(STATIC_SCOPE_ORDER, scope),
            pos(STATIC_SCOPE_ORDER, subscope),
        ) {
            (Some(scope_idx), Some(sub_idx)) => sub_idx >= scope_idx,
            _ => false,
        }
    } else if DYNAMIC_SCOPE_ORDER.contains(subscope) {
        match (
            pos(DYNAMIC_SCOPE_ORDER, scope),
            pos(DYNAMIC_SCOPE_ORDER, subscope),
        ) {
            (Some(scope_idx), Some(sub_idx)) => sub_idx >= scope_idx,
            _ => false,
        }
    } else {
        false
    }
}

impl TryFrom<&Yaml> for Scope {
    type Error = Error;
    fn try_from(value: &Yaml) -> std::result::Result<Self, Self::Error> {
        Ok(match value.as_str() {
            Some("global") => Scope::Global,
            Some("function") => Scope::Function,
            Some("span of calls") => Scope::SpanOfCalls,
            Some("file") => Scope::File,
            Some("basic block") => Scope::BasicBlock,
            Some("instruction") => Scope::Instruction,
            Some("process") => Scope::Process,
            Some("thread") => Scope::Thread,
            Some("call") => Scope::Call,
            Some("unsupported") => Scope::None,
            Some(_) => {
                return Err(Error::InvalidScope(
                    line!(),
                    value.as_str().unwrap().to_string(),
                ));
            }
            None => Scope::None,
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StaticScope {
    scope: Scope,
}

impl TryFrom<&Yaml> for StaticScope {
    type Error = Error;
    fn try_from(value: &Yaml) -> std::result::Result<Self, Self::Error> {
        let scope = Scope::try_from(value)?;
        match scope {
            Scope::None
            | Scope::File
            | Scope::Global
            | Scope::Function
            | Scope::BasicBlock
            | Scope::Instruction => Ok(Self { scope }),
            _ => Err(Error::InvalidStaticScope(line!())),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DynamicScope {
    scope: Scope,
}

impl TryFrom<&Yaml> for DynamicScope {
    type Error = Error;
    fn try_from(value: &Yaml) -> std::result::Result<Self, Self::Error> {
        let scope = Scope::try_from(value)?;
        match scope {
            Scope::None
            | Scope::File
            | Scope::Global
            | Scope::Process
            | Scope::Thread
            | Scope::Call
            | Scope::SpanOfCalls => Ok(Self { scope }),
            _ => Err(Error::InvalidDynamicScope(line!())),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Scopes {
    r#static: StaticScope,
    dynamic: DynamicScope,
}

impl Scopes {
    pub fn try_from_dict(dict: &Yaml) -> Result<Self> {
        Ok(Scopes {
            r#static: StaticScope::try_from(&dict["static"])?,
            dynamic: DynamicScope::try_from(&dict["dynamic"])?,
        })
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Rule {
    pub name: String,
    scopes: Scopes,
    statement: StatementElement,
    pub meta: Hash,
    definition: String,
}

impl Rule {
    pub fn set_path(&mut self, path: String) -> Result<()> {
        self.meta
            .insert(Yaml::String("rule-path".to_string()), Yaml::String(path));
        Ok(())
    }

    /// 0.4.1: subscope extraction pass. Walks `self.statement`,
    /// replaces every inline `Subscope` with a `MatchedRule` feature,
    /// and returns the synthetic rules that own the extracted
    /// subscope bodies. Each synthetic rule carries
    /// `capa/subscope-rule: true` in its meta and runs at the
    /// subscope's target scope.
    ///
    /// Mirrors Python capa's behaviour in `capa/rules/__init__.py`
    /// (~line 1124). The reason for the rewrite: subscope contents
    /// need to evaluate at their inner scope (e.g. instruction-by-
    /// instruction) so feature addresses are meaningful; the outer
    /// rule then sees only a `MatchedRule` feature carrying those
    /// addresses, which is what makes evidence trees work later.
    ///
    /// Pre-0.4.1 capa-rs wrapped subscopes inline (`Subscope::evaluate`
    /// just delegated to `child.evaluate`), which gave the right
    /// boolean answer but lost the address-of-match in the outer
    /// rule. This extraction makes the addresses available — they
    /// flow through the existing `index_rule_matches` pipeline.
    pub fn extract_subscopes(&mut self) -> Result<Vec<Rule>> {
        let mut counter = 0usize;
        let mut extracted = Vec::new();
        extract_subscopes_walk(
            &mut self.statement,
            &self.name,
            &self.definition,
            &mut counter,
            &mut extracted,
        )?;
        Ok(extracted)
    }

    pub fn get_dependencies(
        &self,
        namespaces: &HashMap<String, Vec<&Rule>>,
    ) -> Result<Vec<String>> {
        let mut deps = vec![];

        fn rec(
            statement: &StatementElement,
            deps: &mut Vec<String>,
            namespaces: &HashMap<String, Vec<&Rule>>,
        ) -> Result<()> {
            if let StatementElement::Feature(f) = statement {
                if let features::Feature::MatchedRule(s) = &**f {
                    if namespaces.contains_key(&s.value) {
                        //# matches a namespace, so take precedence and
                        // don't even check rule names.
                        for r in &namespaces[&s.value] {
                            deps.push(r.name.clone());
                        }
                    } else {
                        //# not a namespace, assume its a rule name.
                        deps.push(s.value.clone());
                    }
                }
            } else if let StatementElement::Statement(s) = statement {
                for child in s.get_children()? {
                    rec(child, deps, namespaces)?;
                }
            }
            //# else: might be a Feature, etc.
            //# which we don't care about here.
            Ok(())
        }
        rec(&self.statement, &mut deps, namespaces)?;
        Ok(deps)
    }

    fn parse_int(s: &str) -> Result<i128> {
        if let Some(x) = s.strip_prefix("0x") {
            Ok(i128::from_str_radix(x, 0x10)?)
        } else if let Some(x) = s.strip_prefix("-0x") {
            let v = i128::from_str_radix(x, 0x10)?;
            Ok(-v)
        } else {
            Ok(s.parse::<i128>()?)
        }
    }

    /// Bitness suffix of `number/…` / `offset/…` feature keys. The
    /// documented form (capa-rules `doc/format.md`) is `x32` / `x64`;
    /// a bare number is accepted too. Pre-#20 this was
    /// `parse_int(&suffix[1..]) as u32`, which panicked on an empty
    /// suffix (`number/`) and silently truncated out-of-range values.
    fn parse_bitness_suffix(suffix: &str, key: &str) -> Result<u32> {
        let digits = suffix.trim();
        let digits = digits.strip_prefix('x').unwrap_or(digits);
        digits
            .parse::<u32>()
            .map_err(|_| Error::InvalidRule(line!(), key.to_string()))
    }

    /// 0.4.2: parse an `N or more` / `N or fewer` count operand and
    /// validate that the value fits in `u32`. Pre-0.4.2 the code did
    /// `value as u32` after parsing via `i64`, which silently
    /// truncated "5000000000 or more" to ~705 million and matched
    /// the wrong threshold. Now out-of-range values error at rule
    /// load. Reference: audit findings S7+S8.
    fn parse_count_u32(s: &str, raw: &str) -> Result<u32> {
        let n = s.parse::<i64>().map_err(|_| {
            Error::InvalidRule(line!(), format!("count value `{}` is not an integer", s))
        })?;
        if n < 0 {
            return Err(Error::InvalidRule(
                line!(),
                format!("count value must be non-negative: {}", raw),
            ));
        }
        if n > u32::MAX as i64 {
            return Err(Error::InvalidRule(
                line!(),
                format!("count value exceeds u32::MAX (~4.3B): {} in `{}`", n, raw),
            ));
        }
        Ok(n as u32)
    }

    fn parse_range(s: &str) -> Result<(i128, i128)> {
        if !s.starts_with('(') {
            return Err(Error::InvalidRule(line!(), s.to_string()));
        }
        if !s.ends_with(')') {
            return Err(Error::InvalidRule(line!(), s.to_string()));
        }
        let s = &s["(".len()..s.len() - ")".len()];
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidRule(line!(), s.to_string()));
        }
        let min_spec = parts[0].trim();
        let max_spec = parts[1].trim();
        let min = Rule::parse_int(min_spec)?;
        let max = Rule::parse_int(max_spec)?;
        if min < 0 || max < 0 || max < min {
            return Err(Error::InvalidRule(line!(), s.to_string()));
        }
        Ok((min, max))
    }

    fn parse_feature_type(key: &str) -> Result<RuleFeatureType> {
        match key {
            "api" => Ok(RuleFeatureType::Api),
            // 0.4.1: bare `property:` arm added. Python capa's
            // `parse_feature` (capa/rules/__init__.py:446) returns the
            // `Property` class for the unqualified key — used by the
            // count-context form `count(property(...))`. Unblocks
            // nursery/check-for-time-delay-in-dotnet.yml.
            "property" => Ok(RuleFeatureType::Property),
            "property/read" => Ok(RuleFeatureType::PropertyRead),
            "property/write" => Ok(RuleFeatureType::PropertyWrite),
            "namespace" => Ok(RuleFeatureType::Namespace),
            "string" => Ok(RuleFeatureType::StringFactory),
            "substring" => Ok(RuleFeatureType::Substring),
            "bytes" => Ok(RuleFeatureType::Bytes),
            "number" => Ok(RuleFeatureType::Number(0)),
            "offset" => Ok(RuleFeatureType::Offset(0)),
            "mnemonic" => Ok(RuleFeatureType::Mnemonic),
            "basic blocks" => Ok(RuleFeatureType::BasicBlock),
            "characteristic" => Ok(RuleFeatureType::Characteristic),
            "export" => Ok(RuleFeatureType::Export),
            "import" => Ok(RuleFeatureType::Import),
            "section" => Ok(RuleFeatureType::Section),
            "match" => Ok(RuleFeatureType::MatchedRule),
            "function-name" => Ok(RuleFeatureType::FunctionName),
            "os" => Ok(RuleFeatureType::Os),
            "format" => Ok(RuleFeatureType::Format),
            "class" => Ok(RuleFeatureType::Class),
            "arch" => Ok(RuleFeatureType::Arch),
            _ => {
                if let Some(suffix) = key.strip_prefix("number/") {
                    return Ok(RuleFeatureType::Number(Rule::parse_bitness_suffix(
                        suffix, key,
                    )?));
                }
                if let Some(suffix) = key.strip_prefix("offset/") {
                    return Ok(RuleFeatureType::Offset(Rule::parse_bitness_suffix(
                        suffix, key,
                    )?));
                }
                if let Some(rest) = key
                    .strip_prefix("operand[")
                    .and_then(|s| s.strip_suffix("].number"))
                {
                    let idx = rest
                        .parse::<usize>()
                        .map_err(|_| Error::InvalidRule(line!(), key.to_string()))?;
                    return Ok(RuleFeatureType::OperandNumber(idx));
                }
                if let Some(rest) = key
                    .strip_prefix("operand[")
                    .and_then(|s| s.strip_suffix("].offset"))
                {
                    let idx = rest
                        .parse::<usize>()
                        .map_err(|_| Error::InvalidRule(line!(), key.to_string()))?;
                    return Ok(RuleFeatureType::OperandOffset(idx));
                }
                Err(Error::InvalidRule(line!(), key.to_string()))
            }
        }
    }

    fn parse_bytes(s: &str) -> Result<Vec<u8>> {
        let b = hex::decode(s.replace(' ', ""))?;
        if b.len() > MAX_BYTES_FEATURE_SIZE {
            return Err(Error::InvalidRule(line!(), s.to_string()));
        }
        Ok(b)
    }

    fn parse_description(
        s: &str,
        value_type: &RuleFeatureType,
        description: &Option<String>,
    ) -> Result<(Value, Option<String>)> {
        let value; // = Value::Str(String::from(""));
        let mut dd = description.clone();
        match value_type {
            //string features cannot have inline descriptions,
            //so we assume the entire value is the string,
            //like: `string: foo = bar` -> "foo = bar"
            RuleFeatureType::String => {
                value = Value::Str(s.to_string());
            }
            _ => {
                let v; // = "";
                //other features can have inline descriptions, like `number: 10 = CONST_FOO`.
                //in this case, the RHS will be like `10 = CONST_FOO` or some other string
                if let Some((value_part, ddd)) = s.split_once(" = ") {
                    if description.is_some() {
                        // there is already a description passed in as a sub node, like:
                        //
                        //    - number: 10 = CONST_FOO
                        //      description: CONST_FOO
                        return Err(Error::InvalidRule(line!(), s.to_string()));
                    }
                    // split on the FIRST " = " only — the description
                    // itself may contain the separator (#20).
                    v = value_part.trim();
                    if ddd.is_empty() {
                        //# sanity check:
                        //# there is an empty description, like `number: 10 =`
                        return Err(Error::InvalidRule(line!(), s.to_string()));
                    }
                    dd = Some(ddd.to_string());
                } else {
                    //# this is a string, but there is no description,
                    //# like: `api: CreateFileA`
                    v = s;
                }
                //cast from the received string value to the appropriate type.
                //without a description, this type would already be correct,
                //but since we parsed the description from a string,
                //we need to convert the value to the expected type.
                //for example, from `number: 10 = CONST_FOO` we have
                //the string "10" that needs to become the number 10.
                value = match value_type {
                    RuleFeatureType::Bytes => Value::Bytes(Rule::parse_bytes(v)?),
                    RuleFeatureType::Number(_) | RuleFeatureType::OperandNumber(_) => {
                        Value::Int(Rule::parse_int(v)?)
                    }
                    RuleFeatureType::Offset(_) | RuleFeatureType::OperandOffset(_) => {
                        Value::Int(Rule::parse_int(v)?)
                    }
                    _ => Value::Str(v.to_string()),
                };
            }
        }
        Ok((value, dd))
    }

    pub fn from_yaml_file(path: &str) -> Result<Rule> {
        let content = std::fs::read_to_string(path)?;
        Rule::from_yaml(&content)
    }

    pub fn from_yaml(s: &str) -> Result<Rule> {
        let doc = YamlLoader::load_from_str(s)?;
        if doc.is_empty() {
            return Err(Error::InvalidRule(line!(), s.to_string()));
        }
        Rule::from_dict(&doc[0], s)
    }

    pub fn from_dict(d: &Yaml, definition: &str) -> Result<Rule> {
        let meta = &d["rule"]["meta"];
        let name = meta["name"]
            .as_str()
            .ok_or_else(|| Error::InvalidRule(line!(), definition.to_string()))?;
        //if scope is not specified, default to function scope.
        //this is probably the mode that rule authors will start with.
        let scopes = Scopes::try_from_dict(&meta["scopes"])?;
        let statements = d["rule"]["features"]
            .as_vec()
            .ok_or_else(|| Error::InvalidRule(line!(), definition.to_string()))?;
        // the rule must start with a single logic node.
        // doing anything else is too implicit and difficult to remove (AND vs OR ???).
        if statements.len() != 1 {
            return Err(Error::InvalidRule(line!(), definition.to_string()));
        }
        //TODO
        //if isinstance(statements[0], ceng.Subscope):
        //     raise InvalidRule(line!(), "top level statement may not be a subscope")

        match meta["att&ck"] {
            Yaml::Array(_) => {}
            Yaml::BadValue => {}
            _ => return Err(Error::InvalidRule(line!(), definition.to_string())),
        }
        match meta["mbc"] {
            Yaml::Array(_) => {}
            Yaml::BadValue => {}
            _ => return Err(Error::InvalidRule(line!(), definition.to_string())),
        }
        Rule::new(
            name,
            &scopes,
            Rule::build_statements(&statements[0], &scopes)?,
            &meta
                .as_hash()
                .ok_or_else(|| Error::InvalidRule(line!(), definition.to_string()))?
                .clone(),
            definition,
        )
    }

    pub fn new(
        name: &str,
        scopes: &Scopes,
        statement: StatementElement,
        meta: &Hash,
        definition: &str,
    ) -> Result<Rule> {
        Ok(Rule {
            name: name.to_string(),
            scopes: scopes.clone(),
            statement,
            meta: meta.clone(),
            definition: definition.to_string(),
        })
    }

    pub fn extract_elements_and_description(
        vals: &[Yaml],
        scopes: &Scopes,
    ) -> Result<(Vec<StatementElement>, String)> {
        let mut description = String::new();

        let params = vals
            .iter()
            .map(|vv| Rule::build_statements(vv, scopes))
            .filter_map(|result| match result {
                Ok(StatementElement::Description(s)) => {
                    description = s.value.clone();
                    None
                }
                Ok(elem) => Some(Ok(elem)),
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>>>()?;

        Ok((params, description))
    }

    fn wrap_and_subscope(
        scope: Scope,
        params: Vec<StatementElement>,
        description: &str,
    ) -> Result<StatementElement> {
        Ok(StatementElement::Statement(Box::new(Statement::Subscope(
            SubscopeStatement::new(
                scope,
                StatementElement::Statement(Box::new(Statement::And(AndStatement::new(
                    params,
                    description,
                )?))),
                description,
            )?,
        ))))
    }

    pub fn build_statements(dd: &Yaml, scopes: &Scopes) -> Result<StatementElement> {
        let d = dd
            .as_hash()
            .ok_or_else(|| Error::InvalidRule(line!(), "statement need to be hash".to_string()))?;

        if let Some((key, vval)) = d.into_iter().next() {
            let key_str = key
                .as_str()
                .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", key)))?;

            let command_type = CommandType::from_str(key_str)?;

            match command_type {
                CommandType::Description => {
                    let val = vval
                        .as_str()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    return Ok(StatementElement::Description(Box::new(Description::new(
                        val,
                    )?)));
                }
                CommandType::And => {
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    let (params, description) =
                        Rule::extract_elements_and_description(val, scopes)?;
                    return Ok(StatementElement::Statement(Box::new(Statement::And(
                        AndStatement::new(params, &description)?,
                    ))));
                }
                CommandType::Or => {
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    let (params, description) =
                        Rule::extract_elements_and_description(val, scopes)?;
                    return Ok(StatementElement::Statement(Box::new(Statement::Or(
                        OrStatement::new(params, &description)?,
                    ))));
                }
                CommandType::Not => {
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    let (params, description) =
                        Rule::extract_elements_and_description(val, scopes)?;
                    // 0.4.2: enforce arity. Pre-0.4.2 the code took
                    // `params[0]` and silently dropped any additional
                    // children — so `not: [a, b]` evaluated as `not a`
                    // with `b` discarded. Python upstream rejects this
                    // at rule load. Now we do too. Reference:
                    // capa/rules/__init__.py:864.
                    if params.len() != 1 {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`not` requires exactly one child statement, got {}: {:?}",
                                params.len(),
                                vval
                            ),
                        ));
                    }
                    return Ok(StatementElement::Statement(Box::new(Statement::Not(
                        NotStatement::new(params[0].clone(), &description)?,
                    ))));
                }
                CommandType::Optional => {
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    let (params, description) =
                        Rule::extract_elements_and_description(val, scopes)?;
                    return Ok(StatementElement::Statement(Box::new(Statement::Some(
                        SomeStatement::new(0, params, &description)?,
                    ))));
                }
                CommandType::Process => {
                    // 0.4.1: replaced hardcoded `[File].contains(...)` with
                    // is_subscope_compatible. `process` is in DYNAMIC_SCOPE_ORDER,
                    // so it's checked against the dynamic scope. Result is the
                    // same for the previously-permitted file→process transition;
                    // also accepts process→process as Python does.
                    if !is_subscope_compatible(&scopes.dynamic.scope, &Scope::Process) {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`process` subscope not allowed in scope {:?}: {:?}",
                                scopes.dynamic.scope, vval
                            ),
                        ));
                    }
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;

                    let process_scope = Scopes {
                        r#static: StaticScope {
                            scope: Scope::Process,
                        },
                        dynamic: DynamicScope { scope: Scope::None },
                    };

                    let (params, description) =
                        Rule::extract_elements_and_description(val, &process_scope)?;

                    if params.len() != 1 {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!("process must have exactly one condition: {:?}", vval),
                        ));
                    }

                    return Rule::wrap_and_subscope(Scope::Process, params, &description);
                }
                CommandType::Thread => {
                    // 0.4.1: `thread` is in DYNAMIC_SCOPE_ORDER. Checking
                    // against the dynamic scope allows process→thread (as
                    // before) plus thread→thread.
                    if !is_subscope_compatible(&scopes.dynamic.scope, &Scope::Thread) {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`thread` subscope not allowed in scope {:?}: {:?}",
                                scopes.dynamic.scope, vval
                            ),
                        ));
                    }
                    let thread_scope = Scopes {
                        r#static: StaticScope {
                            scope: Scope::Thread,
                        },
                        dynamic: DynamicScope { scope: Scope::None },
                    };

                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;

                    let (params, description) =
                        Rule::extract_elements_and_description(val, &thread_scope)?;

                    if params.len() != 1 {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!("thread must have exactly one condition: {:?}", vval),
                        ));
                    }
                    return Rule::wrap_and_subscope(Scope::Thread, params, &description);
                }
                CommandType::Call => {
                    // 0.4.1: `call` is in DYNAMIC_SCOPE_ORDER. Compatible with
                    // process / thread / span-of-calls / call. Was previously
                    // unchecked.
                    if !is_subscope_compatible(&scopes.dynamic.scope, &Scope::Call) {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`call` subscope not allowed in scope {:?}: {:?}",
                                scopes.dynamic.scope, vval
                            ),
                        ));
                    }
                    let call_scope = Scopes {
                        r#static: StaticScope { scope: Scope::Call },
                        dynamic: DynamicScope {
                            scope: Scope::SpanOfCalls,
                        },
                    };

                    let val_list = match vval {
                        Yaml::Array(arr) => arr.as_slice(),
                        Yaml::Hash(_) => std::slice::from_ref(vval),
                        _ => {
                            return Err(Error::InvalidRule(
                                line!(),
                                format!("call expects array or hash: {:?}", vval),
                            ));
                        }
                    };

                    let (params, description) =
                        Rule::extract_elements_and_description(val_list, &call_scope)?;

                    if params.len() != 1 {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!("process must have exactly one condition: {:?}", vval),
                        ));
                    }

                    return Rule::wrap_and_subscope(Scope::Call, params, &description);
                }
                CommandType::Function => {
                    // 0.4.1: `function` is in STATIC_SCOPE_ORDER. Allowed
                    // in file scope (position 0 → function position 1).
                    if !is_subscope_compatible(&scopes.r#static.scope, &Scope::Function) {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`function` subscope not allowed in scope {:?}: {:?}",
                                scopes.r#static.scope, vval
                            ),
                        ));
                    }
                    let function_scope = Scopes {
                        r#static: StaticScope {
                            scope: Scope::Function,
                        },
                        dynamic: DynamicScope { scope: Scope::None },
                    };

                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;

                    let (params, description) =
                        Rule::extract_elements_and_description(val, &function_scope)?;

                    if params.len() != 1 {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!("{:?}: {:?}", key, vval),
                        ));
                    }

                    return Ok(StatementElement::Statement(Box::new(Statement::Subscope(
                        SubscopeStatement::new(Scope::Function, params[0].clone(), &description)?,
                    ))));
                }
                CommandType::BasicBlock => {
                    // 0.4.1: `basic block` is in STATIC_SCOPE_ORDER.
                    // Allowed in file / function / basic-block scope.
                    if !is_subscope_compatible(&scopes.r#static.scope, &Scope::BasicBlock) {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`basic block` subscope not allowed in scope {:?}: {:?}",
                                scopes.r#static.scope, vval
                            ),
                        ));
                    }
                    let bb_scope = Scopes {
                        r#static: StaticScope {
                            scope: Scope::BasicBlock,
                        },
                        dynamic: DynamicScope { scope: Scope::None },
                    };

                    let val_list = match vval {
                        Yaml::Array(arr) => arr.as_slice(),
                        Yaml::Hash(_) => std::slice::from_ref(vval),
                        _ => {
                            return Err(Error::InvalidRule(
                                line!(),
                                format!("basic block expects array or hash: {:?}", vval),
                            ));
                        }
                    };

                    let (params, description) =
                        Rule::extract_elements_and_description(val_list, &bb_scope)?;

                    if params.is_empty() {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!("basic block must have at least one condition: {:?}", vval),
                        ));
                    }

                    return Rule::wrap_and_subscope(Scope::BasicBlock, params, &description);
                }
                CommandType::Instruction => {
                    // 0.4.1: `instruction` is in STATIC_SCOPE_ORDER (position
                    // 3). Now allowed in any static scope: file (0),
                    // function (1), basic-block (2), instruction (3). This is
                    // the load-bearing fix — pre-0.4.1 it was rejected at
                    // file scope, breaking host-interaction/service/run-as-
                    // service.yml and similar.
                    if !is_subscope_compatible(&scopes.r#static.scope, &Scope::Instruction) {
                        return Err(Error::InvalidRule(
                            line!(),
                            format!(
                                "`instruction` subscope not allowed in scope {:?}: {:?}",
                                scopes.r#static.scope, vval
                            ),
                        ));
                    }
                    let instruction_scope = Scopes {
                        r#static: StaticScope {
                            scope: Scope::Instruction,
                        },
                        dynamic: DynamicScope { scope: Scope::None },
                    };

                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;

                    let (params, description) =
                        Rule::extract_elements_and_description(val, &instruction_scope)?;

                    return Rule::wrap_and_subscope(Scope::Instruction, params, &description);
                }
                _ => {
                    let kkey = key.as_str().ok_or_else(|| {
                        Error::InvalidRule(line!(), format!("{:?} must be string", key))
                    })?;
                    // if kkey.ends_with(" or more") {
                    // let count =
                    //     u32::from_str_radix(&kkey[..kkey.len() - " or more".len()], 10)?;
                    // let count = (&kkey[..kkey.len() - " or more".len()]).parse::<u32>()?;
                    if let Some(x) = kkey.strip_suffix(" or more") {
                        // 0.4.2: route through parse_count_u32 for the
                        // helpful out-of-range error message.
                        let count = Rule::parse_count_u32(x, kkey)?;
                        let mut params = vec![];
                        let mut description = "".to_string();
                        let val = vval
                            .as_vec()
                            .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                        for vv in val {
                            let p = Rule::build_statements(vv, scopes)?;
                            match p {
                                StatementElement::Description(s) => description = s.value,
                                _ => params.push(p),
                            }
                        }
                        return Ok(StatementElement::Statement(Box::new(Statement::Some(
                            SomeStatement::new(count, params, &description)?,
                        ))));
                    } else if kkey.starts_with("count(") && kkey.ends_with(')') {
                        // e.g.:
                        //count(basic block)
                        //count(mnemonic(mov))
                        //count(characteristic(nzxor))
                        let term = &kkey["count(".len()..kkey.len() - ")".len()];
                        //when looking for the existence of such a feature, our rule might look like:
                        //- mnemonic: mov
                        //but here we deal with the form: `mnemonic(mov)`.
                        let parts: Vec<&str> = term.split('(').collect();
                        let term = parts[0];
                        let arg = if parts.len() > 1 { parts[1] } else { "" };
                        let feature_type = Rule::parse_feature_type(term)?;
                        let arg = if !arg.is_empty() {
                            // `count(mnemonic(mov)` — the whole key still
                            // ends with ')' so we get here, but the arg
                            // itself doesn't; blindly stripping the last
                            // byte would mangle "mov" to "mo" (#20).
                            arg.strip_suffix(')')
                                .ok_or_else(|| Error::InvalidRule(line!(), kkey.to_string()))?
                        } else {
                            ""
                        };
                        // can't rely on yaml parsing ints embedded within strings
                        //like:
                        //count(offset(0xC))
                        //count(number(0x11223344))
                        //count(number(0x100 = description))
                        let feature = if term != "string" {
                            let (value, _) = Rule::parse_description(arg, &feature_type, &None)?;
                            Feature::new(feature_type, &value, "")?
                        } else {
                            //arg is string (which doesn't support inline descriptions), like:
                            //count(string(error))
                            //TODO: what about embedded newlines?
                            Feature::new(feature_type, &Value::Str(arg.to_string()), "")?
                        };
                        Rule::ensure_feature_valid_for_scope(scopes, &feature)?;
                        //let val =
                        // vval.as_str().ok_or(Error::InvalidRule(line!(),
                        // format!("{:?} must be string", vval)))?;
                        match vval {
                            Yaml::Integer(i) => {
                                // The string count forms are validated by
                                // `parse_count_u32` (0.4.2); the integer
                                // arm still did `*i as u32`, silently
                                // wrapping e.g. -1 to u32::MAX (#20).
                                let count = u32::try_from(*i).map_err(|_| {
                                    Error::InvalidRule(
                                        line!(),
                                        format!("count value {i} out of range for u32"),
                                    )
                                })?;
                                return Ok(StatementElement::Statement(Box::new(
                                    Statement::Range(RangeStatement::new(
                                        StatementElement::Feature(Box::new(feature)),
                                        count,
                                        count,
                                        "",
                                    )?),
                                )));
                            }
                            Yaml::String(val) => {
                                // 0.4.2: route count-operand parsing through
                                // `parse_count_u32` so out-of-range thresholds
                                // (e.g. "5000000000 or more") error at rule
                                // load instead of silently truncating via
                                // `as u32`. Same for "or fewer" and "(min,
                                // max)" forms.
                                if let Some(num) = val.strip_suffix(" or more") {
                                    let min = Rule::parse_count_u32(num, val)?;
                                    return Ok(StatementElement::Statement(Box::new(
                                        Statement::Range(RangeStatement::new(
                                            StatementElement::Feature(Box::new(feature)),
                                            min,
                                            u32::MAX,
                                            "",
                                        )?),
                                    )));
                                } else if let Some(num) = val.strip_suffix(" or fewer") {
                                    let max = Rule::parse_count_u32(num, val)?;
                                    return Ok(StatementElement::Statement(Box::new(
                                        Statement::Range(RangeStatement::new(
                                            StatementElement::Feature(Box::new(feature)),
                                            0,
                                            max,
                                            "",
                                        )?),
                                    )));
                                } else if val.starts_with('(') {
                                    let (min, max) = Rule::parse_range(val)?;
                                    let min_u32 = u32::try_from(min).map_err(|_| {
                                        Error::InvalidRule(
                                            line!(),
                                            format!(
                                                "range min exceeds u32::MAX: {} in `{}`",
                                                min, val
                                            ),
                                        )
                                    })?;
                                    let max_u32 = u32::try_from(max).map_err(|_| {
                                        Error::InvalidRule(
                                            line!(),
                                            format!(
                                                "range max exceeds u32::MAX: {} in `{}`",
                                                max, val
                                            ),
                                        )
                                    })?;
                                    return Ok(StatementElement::Statement(Box::new(
                                        Statement::Range(RangeStatement::new(
                                            StatementElement::Feature(Box::new(feature)),
                                            min_u32,
                                            max_u32,
                                            "",
                                        )?),
                                    )));
                                }
                                return Err(Error::InvalidRule(
                                    line!(),
                                    format!("{:?} {:?}", key, val),
                                ));
                            }
                            _ => {
                                return Err(Error::InvalidRule(
                                    line!(),
                                    format!("{:?} {:?}", key, vval),
                                ));
                            }
                        }
                    } else if let Some(stripped_key) = kkey.strip_prefix("com/") {
                        let com_type_name = stripped_key;
                        let com_type: ComType = com_type_name.try_into()?;
                        let val = match &d[key] {
                            Yaml::String(s) => s.clone(),
                            Yaml::Integer(i) => i.to_string(),
                            _ => return Err(Error::InvalidRule(line!(), format!("{:?}", d[key]))),
                        };
                        let description = match &d.get(&Yaml::String("description".to_string())) {
                            Some(Yaml::String(s)) => Some(s.clone()),
                            _ => None,
                        };
                        let (value, description) = Rule::parse_description(
                            &val,
                            &RuleFeatureType::ComType(com_type.clone()),
                            &description,
                        )?;
                        let d = match description {
                            Some(s) => s,
                            _ => "".to_string(),
                        };
                        let ff = translate_com_features(&value.get_str()?, &com_type);
                        return Ok(StatementElement::Statement(Box::new(Statement::Or(
                            OrStatement::new(ff, &d)?,
                        ))));
                    } else {
                        let feature_type = Rule::parse_feature_type(kkey)?;
                        let val = match &d[key] {
                            Yaml::String(s) => s.clone(),
                            Yaml::Integer(i) => i.to_string(),
                            _ => return Err(Error::InvalidRule(line!(), format!("{:?}", d[key]))),
                        };
                        let description = match &d.get(&Yaml::String("description".to_string())) {
                            Some(Yaml::String(s)) => Some(s.clone()),
                            _ => None,
                        };
                        let (value, description) =
                            Rule::parse_description(&val, &feature_type, &description)?;
                        let d = match description {
                            Some(s) => s,
                            _ => "".to_string(),
                        };
                        let feature = Feature::new(feature_type, &value, &d)?;
                        Rule::ensure_feature_valid_for_scope(scopes, &feature)?;
                        return Ok(StatementElement::Feature(Box::new(feature)));
                    }
                }
            }
        }
        Err(Error::InvalidRule(line!(), "finish".to_string()))
    }

    pub fn ensure_feature_valid_for_scope(scopes: &Scopes, feature: &Feature) -> Result<()> {
        if feature.is_supported_in_scope(scopes)? {
            return Ok(());
        }
        Err(Error::InvalidRule(
            line!(),
            format!("{:?} not suported in scope {:?}", feature, scopes),
        ))
    }

    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        match self.statement.evaluate(features) {
            Ok(s) => Ok(s),
            Err(e) => {
                // println!("rule {:?}", self);
                // println!("rule error {:?}", e);
                Err(e)
            }
        }
    }
}

fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or_default()
}

pub fn get_rules(rule_path: &str) -> Result<Vec<Rule>> {
    use rayon::prelude::*;

    // 0.4.2: collect the WalkDir entries up front so the YAML parse
    // step can rayon-parallelise. WalkDir is itself sequential
    // (filesystem traversal); the per-file YAML parse is the
    // expensive bit (~50–200 µs per file × 1,000 rules = the bulk
    // of rule-load time). Also: `follow_links(false)` defends against
    // malicious symlink chains in a user-controlled rules directory.
    //
    // 0.4.2: replaced `to_str().unwrap()` with a defensive skip on
    // non-UTF-8 paths so unusual filenames don't panic the loader
    // (S2 from the audit).
    let entries: Vec<String> = walkdir::WalkDir::new(rule_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_hidden(e))
        .filter_map(|e| e.ok())
        .filter_map(|e| e.path().to_str().map(str::to_string))
        .filter(|fname| fname.ends_with(".yml") || fname.ends_with(".yaml"))
        .collect();

    // Each YAML file is independent — parse, set_path, extract
    // subscopes per file. Workers return `Vec<Rule>` (parent +
    // synthetic subscope rules); the final `flatten()` merges them.
    // Parse errors print a warning and yield an empty Vec rather
    // than propagating, matching pre-0.4.2 best-effort behaviour.
    let rules: Vec<Rule> = entries
        .par_iter()
        .map(|fname| -> Vec<Rule> {
            let mut rule = match Rule::from_yaml_file(fname) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warn: rule {} error: {:?}", fname, e);
                    return Vec::new();
                }
            };
            if let Err(e) = rule.set_path(fname.clone()) {
                eprintln!("warn: rule {} set_path error: {:?}", fname, e);
                return Vec::new();
            }
            // 0.4.1: extract inline subscopes into synthetic rules.
            // Each `Subscope` statement in `rule.statement` is replaced
            // with a `MatchedRule` feature referencing a freshly-minted
            // synthetic rule, which carries the subscope body at the
            // target scope and `capa/subscope-rule: true` in its meta.
            // Lets the rules engine evaluate the inner block at its
            // proper scope (where its matches have meaningful
            // addresses), then surface only the boolean result to the
            // outer rule via the match-rule feature index. Mirrors
            // Python capa's pattern from rules/__init__.py.
            let synthetics = match rule.extract_subscopes() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("warn: rule {} subscope extraction error: {:?}", fname, e);
                    return Vec::new();
                }
            };
            let mut out = Vec::with_capacity(1 + synthetics.len());
            out.push(rule);
            out.extend(synthetics);
            out
        })
        .flatten()
        .collect();
    Ok(rules)
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub basic_block_rules: Vec<Rule>,
    pub function_rules: Vec<Rule>,
    pub file_rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(path: &str) -> Result<RuleSet> {
        let rules = get_rules(path)?;
        let basic_block_rules = get_basic_block_rules(&rules)?;
        let function_rules = get_function_rules(&rules)?;
        let file_rules = get_file_rules(&rules)?;
        Ok(RuleSet {
            rules: rules.clone(),
            basic_block_rules: basic_block_rules.iter().map(|r| (*r).clone()).collect(),
            function_rules: function_rules.iter().map(|r| (*r).clone()).collect(),
            file_rules: file_rules.iter().map(|r| (*r).clone()).collect(),
        })
    }

    /// 0.5.2 (upstream parity mandiant/capa#2929): return a new
    /// `RuleSet` with rules removed whose global-feature requirements
    /// (`os:`, `arch:`, `format:`) cannot be satisfied by the binary
    /// under analysis.
    ///
    /// Global features are determined once at the start of analysis
    /// from the binary's headers. Any rule that requires, for example,
    /// `os: windows` while we're analysing a Linux ELF can never match
    /// and is safe to discard *before* the per-function matching loop
    /// — eliminating those rules from every per-function /
    /// per-basic-block / per-instruction evaluation downstream.
    ///
    /// Conservative: a rule is only removed when its global-feature
    /// constraints are *provably* unsatisfiable. Rules with no global
    /// constraints, with `os: any`-style wildcards, or with negated
    /// constraints (`not:`) are always kept. Transitive dependencies
    /// of kept rules are also retained so internal RuleSet
    /// dependency invariants hold.
    ///
    /// Returns a clone of `self` (cheap — the per-scope vecs already
    /// re-clone) if no rules can be pruned.
    pub fn filter_rules_by_meta_features(
        &self,
        features: &HashMap<Feature, Vec<u64>>,
    ) -> Result<RuleSet> {
        // Restrict the input features to *actual* globals (OS / Arch / Format).
        let global_features: HashMap<Feature, Vec<u64>> = features
            .iter()
            .filter(|(f, _)| f.is_global_feature())
            .map(|(f, l)| (f.clone(), l.clone()))
            .collect();
        if global_features.is_empty() {
            return Ok(self.clone());
        }

        // Build the namespace index from the *full* ruleset so dependency
        // closure later picks up rules referenced by namespace.
        let namespaces = index_rules_by_namespace(&self.rules)?;

        // 1. Determine which rules' global constraints are satisfiable.
        let mut keep: HashSet<String> = HashSet::with_capacity(self.rules.len());
        for rule in &self.rules {
            if can_match_globals(&rule.statement, &global_features) {
                keep.insert(rule.name.clone());
            }
        }

        // Fast exit when nothing would be pruned.
        if keep.len() == self.rules.len() {
            return Ok(self.clone());
        }

        // 2. Expand to include transitive dependencies of every surviving
        // rule, so `match: foo` references still resolve.
        let mut stack: Vec<String> = keep.iter().cloned().collect();
        while let Some(name) = stack.pop() {
            let rule = match self.rules.iter().find(|r| r.name == name) {
                Some(r) => r,
                None => continue,
            };
            for dep in rule.get_dependencies(&namespaces)? {
                if keep.insert(dep.clone()) {
                    stack.push(dep);
                }
            }
        }
        if keep.len() == self.rules.len() {
            return Ok(self.clone());
        }

        // 3. Rebuild the per-scope vectors from the filtered list, the same
        // way `RuleSet::new` does.
        let filtered: Vec<Rule> = self
            .rules
            .iter()
            .filter(|r| keep.contains(&r.name))
            .cloned()
            .collect();
        let basic_block_rules = get_basic_block_rules(&filtered)?
            .iter()
            .map(|r| (*r).clone())
            .collect();
        let function_rules = get_function_rules(&filtered)?
            .iter()
            .map(|r| (*r).clone())
            .collect();
        let file_rules = get_file_rules(&filtered)?
            .iter()
            .map(|r| (*r).clone())
            .collect();

        Ok(RuleSet {
            rules: filtered,
            basic_block_rules,
            function_rules,
            file_rules,
        })
    }
}

/// 0.5.2 (upstream parity mandiant/capa#2929): recursive walker over a
/// rule's `StatementElement` AST that returns `true` if the rule
/// *might* still match given the binary's global feature set, and
/// `false` only when the rule's global constraints are provably
/// unsatisfiable. Non-global features always return `true` —
/// pre-pruning only reasons about Os/Arch/Format.
///
/// Mirrors the `can_match` helper in upstream's Python implementation
/// (capa/rules/__init__.py, filter_rules_by_meta_features).
fn can_match_globals(node: &StatementElement, globals: &HashMap<Feature, Vec<u64>>) -> bool {
    match node {
        StatementElement::Feature(f) => {
            if f.is_global_feature() {
                // `os: any` / `arch: any` / `format: any` are the
                // explicit "don't care" wildcard form and are always
                // satisfiable — short-circuit before the strict
                // value-equality lookup in `OsFeature::evaluate`
                // (etc.) would otherwise wrongly return false because
                // the binary's globals carry a concrete value.
                let wildcard = match f.as_ref() {
                    Feature::Os(o) => o.value() == "any",
                    Feature::Arch(a) => a.value() == "any",
                    Feature::Format(fmt) => fmt.value() == "any",
                    _ => false,
                };
                if wildcard {
                    return true;
                }
                // `evaluate` returns (bool, locations); we only need
                // the bool. On any error fall back to "might match"
                // — pruning errs on the side of keeping the rule.
                f.evaluate(globals).map(|(b, _)| b).unwrap_or(true)
            } else {
                // Non-global features can't be ruled out from globals alone.
                true
            }
        }
        // Description nodes carry no constraints — transparent.
        StatementElement::Description(_) => true,
        StatementElement::Statement(boxed) => match boxed.as_ref() {
            Statement::And(s) => match s.get_children() {
                Ok(children) => children.iter().all(|c| can_match_globals(c, globals)),
                Err(_) => true,
            },
            Statement::Or(s) => match s.get_children() {
                Ok(children) => children.iter().any(|c| can_match_globals(c, globals)),
                Err(_) => true,
            },
            // Negation: we can't prove unsatisfiability from globals alone,
            // since the global constraint might appear inside the `not:` and
            // be exactly what makes the rule satisfiable. Keep the rule.
            Statement::Not(_) => true,
            Statement::Some(s) => {
                if s.count() == 0 {
                    return true;
                }
                let children = match s.get_children() {
                    Ok(c) => c,
                    Err(_) => return true,
                };
                let satisfiable: u32 = children
                    .iter()
                    .map(|c| if can_match_globals(c, globals) { 1 } else { 0 })
                    .sum();
                satisfiable >= s.count()
            }
            Statement::Range(s) => {
                // `min == 0` means the feature can be absent — always satisfiable.
                if s.min() == 0 {
                    return true;
                }
                match s.get_children() {
                    Ok(children) => children.iter().all(|c| can_match_globals(c, globals)),
                    Err(_) => true,
                }
            }
            // Subscope is normally rewritten before matching (task #155);
            // if we still see one, treat it transparently — recurse into
            // its single child.
            Statement::Subscope(_) => match boxed.get_children() {
                Ok(children) => children.iter().all(|c| can_match_globals(c, globals)),
                Err(_) => true,
            },
        },
    }
}

pub fn get_instruction_rules(rules: &[Rule]) -> Result<Vec<&Rule>> {
    get_rules_for_scope(rules, &Scope::Instruction)
}

pub fn get_basic_block_rules(rules: &[Rule]) -> Result<Vec<&Rule>> {
    get_rules_for_scope(rules, &Scope::BasicBlock)
}

pub fn get_function_rules(rules: &[Rule]) -> Result<Vec<&Rule>> {
    get_rules_for_scope(rules, &Scope::Function)
}

pub fn get_file_rules(rules: &[Rule]) -> Result<Vec<&Rule>> {
    get_rules_for_scope(rules, &Scope::File)
}

/// 0.4.1: returns `true` for the given meta key bool if present and
/// `true`. Generalises the existing `capa/subscope-rule` and new
/// `lib: true` filters in [`get_rules_for_scope`] and
/// `update_capabilities`. Mirrors Python's
/// `rule.meta.get("lib", False)` lookup pattern.
pub(crate) fn rule_meta_bool(rule: &Rule, key: &str) -> bool {
    matches!(
        rule.meta.get(&Yaml::String(key.to_string())),
        Some(Yaml::Boolean(true))
    )
}

/// 0.4.1: `lib: true` marks a rule as a building block consumed by
/// other rules via `match:` rather than a user-facing capability.
/// 21 rules in `capa-rules` are lib-marked today. Python capa skips
/// them from rendered output; capa-rs now matches that behaviour
/// (also filtered from `update_capabilities` in src/lib.rs).
pub(crate) fn is_lib_rule(rule: &Rule) -> bool {
    rule_meta_bool(rule, "lib")
}

/// 0.4.1: build a `Scopes` for a synthetic subscope rule. Routes the
/// target scope into the right slot (static or dynamic) and sets the
/// other to `Scope::None`. Used by [`Rule::extract_subscopes`].
fn scopes_for_subscope(target: &Scope) -> Scopes {
    let is_static = matches!(
        target,
        Scope::File | Scope::Function | Scope::BasicBlock | Scope::Instruction
    );
    if is_static {
        Scopes {
            r#static: StaticScope {
                scope: target.clone(),
            },
            dynamic: DynamicScope { scope: Scope::None },
        }
    } else {
        Scopes {
            r#static: StaticScope { scope: Scope::None },
            dynamic: DynamicScope {
                scope: target.clone(),
            },
        }
    }
}

/// 0.4.1: recursive walker for [`Rule::extract_subscopes`]. Depth-
/// first traversal: rewrites the deepest subscopes first so nested
/// subscopes (e.g. `function:` containing `basic block:`) generate
/// rules in the correct order — the inner synthetic rule exists by
/// the time the outer synthetic rule's body is sealed.
fn extract_subscopes_walk(
    elem: &mut StatementElement,
    parent_name: &str,
    parent_definition: &str,
    counter: &mut usize,
    extracted: &mut Vec<Rule>,
) -> Result<()> {
    // Depth-first: recurse into any children first.
    if let StatementElement::Statement(s) = elem {
        for c in s.children_mut() {
            extract_subscopes_walk(c, parent_name, parent_definition, counter, extracted)?;
        }
    }

    // After children are clean, check if this node is itself a
    // Subscope to extract.
    let target_scope = match elem {
        StatementElement::Statement(s) => match s.as_ref() {
            Statement::Subscope(sub) => Some(sub.scope().clone()),
            _ => None,
        },
        _ => None,
    };
    let Some(target_scope) = target_scope else {
        return Ok(());
    };

    // 0.4.1 limitation: only extract subscopes whose target has an
    // evaluation bucket in `RuleSet` (`basic_block_rules`,
    // `function_rules`, `file_rules`). Today that means Function and
    // BasicBlock. Instruction subscopes stay inline so they continue
    // to use `SubscopeInstructionEvaluator`'s per-address matching;
    // dynamic-scope subscopes (Process / Thread / Call / SpanOfCalls)
    // stay inline because dynamic-analysis isn't yet wired through.
    // Extracting those would silently break working rules — the
    // synthetic rule would never evaluate.
    //
    // Once an instruction_rules bucket + dynamic-analysis pipeline
    // land (0.5.0 target), this guard can be lifted.
    if !matches!(target_scope, Scope::Function | Scope::BasicBlock) {
        return Ok(());
    }

    let idx = *counter;
    *counter += 1;
    let synth_name = format!("{}/subscope/{}", parent_name, idx);

    // Move the Subscope out via a placeholder Description swap.
    // Description is the cheapest StatementElement to construct (no
    // regex compile, no scope check) — it's a one-shot dummy that
    // gets overwritten before this function returns.
    let placeholder = StatementElement::Description(Box::new(Description::new("").unwrap()));
    let owned = std::mem::replace(elem, placeholder);

    let StatementElement::Statement(boxed) = owned else {
        unreachable!("checked Statement above")
    };
    let Statement::Subscope(sub) = *boxed else {
        unreachable!("checked Subscope above")
    };
    // `target_scope` from the pre-check shadowed here on purpose —
    // `into_inner` consumes the only owned copy.
    let (target_scope, child, description) = sub.into_inner();

    // Build the synthetic rule that owns the subscope body.
    let scopes = scopes_for_subscope(&target_scope);
    let mut meta = Hash::new();
    meta.insert(
        Yaml::String("name".to_string()),
        Yaml::String(synth_name.clone()),
    );
    meta.insert(
        Yaml::String("capa/subscope-rule".to_string()),
        Yaml::Boolean(true),
    );
    if !description.is_empty() {
        meta.insert(
            Yaml::String("description".to_string()),
            Yaml::String(description.clone()),
        );
    }
    let synth = Rule::new(&synth_name, &scopes, child, &meta, parent_definition)?;
    extracted.push(synth);

    // Replace the placeholder with a `match: <synth_name>` reference
    // so the outer rule's evaluation now consults the synthetic
    // rule's match status via the MatchedRule feature index.
    let matched = features::MatchedRuleFeature::new(&synth_name, "")?;
    *elem = StatementElement::Feature(Box::new(Feature::MatchedRule(matched)));
    Ok(())
}

pub fn get_rules_for_scope<'a>(rules: &'a [Rule], scope: &Scope) -> Result<Vec<&'a Rule>> {
    // 0.4.2: build the namespace + name indexes ONCE per call instead
    // of once per rule. Previously `get_rules_and_dependencies` (called
    // per rule from the loop below) rebuilt both indexes internally —
    // with ~1,000 rules in capa-rules and four scope passes that was
    // ~16M HashMap inserts per `RuleSet::new`. Hoist them; the body
    // becomes a flat O(N + deps) per rule, O(N²) total at worst.
    let namespaces = index_rules_by_namespace(rules)?;
    let rules_by_name = build_rules_by_name(rules);

    let mut scope_rules = vec![];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for rule in rules {
        // 0.4.1: skip synthetic subscope rules and library rules from
        // the top-level iteration. Both remain available via
        // `get_rules_and_dependencies` when another rule depends on
        // them — this only prevents them from being treated as their
        // own evaluation target. Matches Python's RuleSet partitioning.
        if rule_meta_bool(rule, "capa/subscope-rule") || is_lib_rule(rule) {
            continue;
        }
        let deps =
            get_rules_and_dependencies_indexed(rules, &rules_by_name, &namespaces, &rule.name)?;
        for r in deps {
            if seen.insert(r.name.clone()) {
                scope_rules.push(r);
            }
        }
    }
    let trules = topologically_order_rules(scope_rules)?;

    get_rules_with_scope(trules, scope)
}

/// 0.4.2: build the name→rule index once. Used to be inlined per
/// `get_rules_and_dependencies` call (now `get_rules_and_dependencies_indexed`).
fn build_rules_by_name(rules: &[Rule]) -> HashMap<String, &Rule> {
    let mut rules_by_name = HashMap::with_capacity(rules.len());
    for rule in rules {
        rules_by_name.insert(rule.name.clone(), rule);
    }
    rules_by_name
}

/// 0.4.2: public entry that builds indexes ad-hoc — kept for external
/// callers that don't already have indexes on hand. Internal hot path
/// uses `get_rules_and_dependencies_indexed` directly to share the
/// indexes across calls.
pub fn get_rules_and_dependencies<'a>(rules: &'a [Rule], rule_name: &str) -> Result<Vec<&'a Rule>> {
    let namespaces = index_rules_by_namespace(rules)?;
    let rules_by_name = build_rules_by_name(rules);
    get_rules_and_dependencies_indexed(rules, &rules_by_name, &namespaces, rule_name)
}

/// 0.4.2: indexed variant of [`get_rules_and_dependencies`]. Caller
/// owns the namespace index and `rules_by_name` map, so they can be
/// built once and reused across N rules — turns the original O(N²)
/// scope-rule construction into O(N + total deps).
fn get_rules_and_dependencies_indexed<'a>(
    _rules: &'a [Rule],
    rules_by_name: &HashMap<String, &'a Rule>,
    namespaces: &HashMap<String, Vec<&'a Rule>>,
    rule_name: &str,
) -> Result<Vec<&'a Rule>> {
    // `wanted` is a HashSet (was a Vec with O(N) `.contains`) so the
    // final filter is O(N) total instead of O(N²).
    let mut wanted: std::collections::HashSet<String> = std::collections::HashSet::new();

    fn rec<'a>(
        want: &mut std::collections::HashSet<String>,
        rule: &'a Rule,
        rules_by_name: &HashMap<String, &'a Rule>,
        namespaces: &HashMap<String, Vec<&'a Rule>>,
    ) -> Result<()> {
        // 0.4.2: cycle break — a rule referenced through nested
        // `match:` namespaces could otherwise loop. If already wanted,
        // its dependencies have already been walked.
        if !want.insert(rule.name.clone()) {
            return Ok(());
        }
        for dep in rule.get_dependencies(namespaces)? {
            match rules_by_name.get(&dep) {
                Some(dep_rule) => {
                    rec(want, dep_rule, rules_by_name, namespaces)?;
                }
                None => {
                    eprintln!("Rule not found: {}", dep);
                    return Err(Error::MatchRuleNotFound(format!(
                        "Rule '{}' not found in the rules set",
                        dep
                    )));
                }
            }
        }
        Ok(())
    }

    let seed = rules_by_name
        .get(rule_name)
        .ok_or_else(|| Error::MatchRuleNotFound(rule_name.to_string()))?;
    rec(&mut wanted, seed, rules_by_name, namespaces)?;

    // Materialise the HashSet into a Vec preserving insertion via
    // rules_by_name's iteration (deterministic ordering depends on
    // HashMap's hasher seed — downstream topo-sort renders that
    // irrelevant).
    let mut res = Vec::with_capacity(wanted.len());
    for name in &wanted {
        if let Some(rule) = rules_by_name.get(name) {
            res.push(*rule);
        }
    }
    Ok(res)
}

pub fn get_rules_with_scope<'a>(rules: Vec<&'a Rule>, scope: &Scope) -> Result<Vec<&'a Rule>> {
    let mut res = vec![];
    for rule in rules {
        if &rule.scopes.r#static.scope == scope || &rule.scopes.dynamic.scope == scope {
            res.push(rule);
        }
    }
    Ok(res)
}

fn generate_namespace_paths(namespace: &str) -> Vec<String> {
    namespace
        .split('/')
        .scan(String::new(), |state, part| {
            if !state.is_empty() {
                state.push('/');
            }
            state.push_str(part);
            Some(state.clone())
        })
        .collect()
}

pub fn index_rules_by_namespace(rules: &[Rule]) -> Result<HashMap<String, Vec<&Rule>>> {
    let mut namespaces: HashMap<String, Vec<&Rule>> = HashMap::new();

    for rule in rules {
        if let Some(Yaml::String(namespace)) = rule.meta.get(&Yaml::String("namespace".to_string()))
        {
            for path in generate_namespace_paths(namespace) {
                namespaces.entry(path).or_default().push(rule);
            }
        }
    }

    Ok(namespaces)
}

pub fn index_rules_by_namespace2<'a>(rules: &[&'a Rule]) -> Result<HashMap<String, Vec<&'a Rule>>> {
    let mut namespaces: HashMap<String, Vec<&'a Rule>> = HashMap::new();

    for &rule in rules {
        if let Some(Yaml::String(namespace)) = rule.meta.get(&Yaml::String("namespace".to_string()))
        {
            for path in generate_namespace_paths(namespace) {
                namespaces.entry(path).or_default().push(rule);
            }
        }
    }

    Ok(namespaces)
}
pub fn topologically_order_rules(rules: Vec<&Rule>) -> Result<Vec<&Rule>> {
    //# we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    let namespaces = index_rules_by_namespace2(&rules)?;
    let mut rules_by_name = HashMap::new();
    for rule in &rules {
        rules_by_name.insert(rule.name.clone(), *rule);
    }
    let mut seen = std::collections::HashSet::new();
    let mut ret = vec![];

    fn rec<'a>(
        rule: &'a Rule,
        seen: &mut std::collections::HashSet<String>,
        rules_by_name: &HashMap<String, &'a Rule>,
        namespaces: &HashMap<String, Vec<&'a Rule>>,
    ) -> Result<Vec<&'a Rule>> {
        if seen.contains(&rule.name) {
            return Ok(vec![]);
        }
        let mut rett = vec![];
        for dep in rule.get_dependencies(namespaces)? {
            // Public entry point: a caller can pass a rule subset whose
            // dependencies aren't all present — return an error instead
            // of panicking on the map index (#20).
            let dep_rule = rules_by_name
                .get(&dep)
                .ok_or_else(|| Error::MatchRuleNotFound(dep.clone()))?;
            rett.append(&mut rec(dep_rule, seen, rules_by_name, namespaces)?);
        }

        rett.push(rule);
        seen.insert(rule.name.clone());
        Ok(rett)
    }
    for rule in rules_by_name.values() {
        ret.append(&mut rec(rule, &mut seen, &rules_by_name, &namespaces)?);
    }
    Ok(ret)
}

// 0.5.2 (upstream parity mandiant/capa#2929): tests for
// `RuleSet::filter_rules_by_meta_features`. Mirror the upstream
// `tests/test_match.py::test_filter_rules_by_meta_features_*` cases,
// adapted to capa-rs's `Rule::from_yaml` constructor and the local
// `RuleSet` struct layout.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::features::OsFeature;

    fn make_ruleset(rules: Vec<Rule>) -> Result<RuleSet> {
        let basic_block_rules = get_basic_block_rules(&rules)?
            .iter()
            .map(|r| (*r).clone())
            .collect();
        let function_rules = get_function_rules(&rules)?
            .iter()
            .map(|r| (*r).clone())
            .collect();
        let file_rules = get_file_rules(&rules)?
            .iter()
            .map(|r| (*r).clone())
            .collect();
        Ok(RuleSet {
            rules,
            basic_block_rules,
            function_rules,
            file_rules,
        })
    }

    fn os_globals(value: &str) -> HashMap<Feature, Vec<u64>> {
        let mut m = HashMap::new();
        m.insert(
            Feature::Os(OsFeature::new(value, "").expect("OsFeature::new")),
            vec![0],
        );
        m
    }

    fn names(rs: &RuleSet) -> HashSet<String> {
        rs.rules.iter().map(|r| r.name.clone()).collect()
    }

    const WINDOWS_RULE: &str = r#"
rule:
  meta:
    name: windows only
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - os: windows
      - api: CreateFile
"#;

    const LINUX_RULE: &str = r#"
rule:
  meta:
    name: linux only
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - os: linux
      - api: open
"#;

    const ANY_OS_RULE: &str = r#"
rule:
  meta:
    name: any os
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - os: any
      - api: malloc
"#;

    const NO_OS_RULE: &str = r#"
rule:
  meta:
    name: no os
    scopes:
      static: function
      dynamic: process
  features:
    - api: calloc
"#;

    #[test]
    fn upstream_parity_2929_prunes_incompatible_os() {
        let rs = make_ruleset(vec![
            Rule::from_yaml(WINDOWS_RULE).expect("windows yaml"),
            Rule::from_yaml(LINUX_RULE).expect("linux yaml"),
        ])
        .expect("RuleSet");

        // Linux binary: windows-only rule pruned, linux-only kept.
        let filtered = rs
            .filter_rules_by_meta_features(&os_globals("linux"))
            .expect("filter");
        let ns = names(&filtered);
        assert!(ns.contains("linux only"), "kept: {:?}", ns);
        assert!(!ns.contains("windows only"), "kept: {:?}", ns);

        // Windows binary: linux-only rule pruned, windows-only kept.
        let filtered = rs
            .filter_rules_by_meta_features(&os_globals("windows"))
            .expect("filter");
        let ns = names(&filtered);
        assert!(ns.contains("windows only"), "kept: {:?}", ns);
        assert!(!ns.contains("linux only"), "kept: {:?}", ns);
    }

    #[test]
    fn upstream_parity_2929_keeps_any_os_and_no_os() {
        let rs = make_ruleset(vec![
            Rule::from_yaml(ANY_OS_RULE).expect("any-os yaml"),
            Rule::from_yaml(NO_OS_RULE).expect("no-os yaml"),
        ])
        .expect("RuleSet");

        for os in ["windows", "linux"] {
            let filtered = rs
                .filter_rules_by_meta_features(&os_globals(os))
                .expect("filter");
            let ns = names(&filtered);
            assert!(
                ns.contains("any os"),
                "any-os pruned for os={os}, kept: {ns:?}"
            );
            assert!(
                ns.contains("no os"),
                "no-os pruned for os={os}, kept: {ns:?}"
            );
        }
    }

    #[test]
    fn upstream_parity_2929_empty_globals_returns_clone() {
        let rs = make_ruleset(vec![
            Rule::from_yaml(WINDOWS_RULE).expect("yaml"),
            Rule::from_yaml(LINUX_RULE).expect("yaml"),
        ])
        .expect("RuleSet");
        let filtered = rs
            .filter_rules_by_meta_features(&HashMap::new())
            .expect("filter");
        assert_eq!(
            filtered.rules.len(),
            2,
            "empty globals should keep all rules"
        );
    }

    const PARENT_USES_LINUX_DEP: &str = r#"
rule:
  meta:
    name: windows parent
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - os: windows
      - or:
        - api: CreateFile
        - match: linux dep
"#;

    const LINUX_DEP: &str = r#"
rule:
  meta:
    name: linux dep
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - os: linux
      - api: open
"#;

    #[test]
    fn upstream_parity_2929_keeps_dependencies_of_surviving_rules() {
        let rs = make_ruleset(vec![
            Rule::from_yaml(LINUX_DEP).expect("dep yaml"),
            Rule::from_yaml(PARENT_USES_LINUX_DEP).expect("parent yaml"),
        ])
        .expect("RuleSet");

        // Windows binary: parent kept (os: windows), and its transitive
        // `match: linux dep` dependency must survive too even though the
        // dep itself has os:linux that would otherwise be pruned.
        let filtered = rs
            .filter_rules_by_meta_features(&os_globals("windows"))
            .expect("filter");
        let ns = names(&filtered);
        assert!(ns.contains("windows parent"), "parent pruned: {ns:?}");
        assert!(
            ns.contains("linux dep"),
            "transitive dep pruned (broken dependency invariant): {ns:?}"
        );
    }

    const UNREACHABLE_SOME_RULE: &str = r#"
rule:
  meta:
    name: unreachable some
    scopes:
      static: function
      dynamic: process
  features:
    - 3 or more:
      - os: windows
      - os: linux
      - os: macos
"#;

    #[test]
    fn upstream_parity_2929_prunes_unreachable_some_count() {
        let rs = make_ruleset(vec![Rule::from_yaml(UNREACHABLE_SOME_RULE).expect("yaml")])
            .expect("RuleSet");

        // The rule requires 3 satisfied global constraints out of 3
        // mutually-exclusive OSes — impossible on any single binary.
        let filtered = rs
            .filter_rules_by_meta_features(&os_globals("windows"))
            .expect("filter");
        let ns = names(&filtered);
        assert!(
            !ns.contains("unreachable some"),
            "unsatisfiable Some-count rule was not pruned: {ns:?}"
        );
    }

    // ————— #20: malformed-rule hardening —————

    /// `number/` / `offset/` bitness suffixes: the documented
    /// `x32` / `x64` forms parse, empty or out-of-range suffixes error
    /// (pre-#20 the parser panicked on `number/` — `&suffix[1..]` was
    /// out of bounds — and silently truncated over-u32 values).
    #[test]
    fn bitness_suffix_is_validated_instead_of_panicking() {
        assert!(matches!(
            Rule::parse_feature_type("number/x32"),
            Ok(RuleFeatureType::Number(32))
        ));
        assert!(matches!(
            Rule::parse_feature_type("offset/x64"),
            Ok(RuleFeatureType::Offset(64))
        ));
        assert!(Rule::parse_feature_type("number/").is_err());
        assert!(Rule::parse_feature_type("offset/").is_err());
        assert!(Rule::parse_feature_type("number/x18446744073709551616").is_err());
    }

    /// A negative integer count must error (pre-#20 `-1 as u32`
    /// silently wrapped to `u32::MAX`), and an unbalanced `count(`
    /// argument must error instead of silently dropping its last
    /// character (`count(mnemonic(mov)` parsed "mo").
    #[test]
    fn malformed_counts_error_instead_of_wrapping_or_mangling() {
        let negative = r#"
rule:
  meta:
    name: bad count
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - count(mnemonic(mov)): -1
"#;
        assert!(
            Rule::from_yaml(negative).is_err(),
            "negative count must be rejected"
        );

        let unbalanced = r#"
rule:
  meta:
    name: bad count paren
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - count(mnemonic(mov): 2
"#;
        assert!(
            Rule::from_yaml(unbalanced).is_err(),
            "unbalanced count( argument must be rejected"
        );
    }

    /// Inline descriptions split on the FIRST " = " only — the
    /// description itself may contain the separator (pre-#20
    /// `split(" = ")` silently dropped the tail).
    #[test]
    fn inline_description_keeps_tail_after_first_separator() {
        let (_value, description) =
            Rule::parse_description("CreateFile = opens = files", &RuleFeatureType::Api, &None)
                .expect("parse_description");
        assert_eq!(description.as_deref(), Some("opens = files"));
    }

    /// A rule whose `match:` dependency is absent from the input must
    /// produce an error, not a HashMap-index panic (#20).
    #[test]
    fn topological_order_missing_dependency_errors_instead_of_panicking() {
        let rule = Rule::from_yaml(
            r#"
rule:
  meta:
    name: depends on missing
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - match: no such rule
"#,
        )
        .expect("from_yaml");
        assert!(topologically_order_rules(vec![&rule]).is_err());
    }
}
