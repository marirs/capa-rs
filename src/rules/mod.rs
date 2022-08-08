pub mod features;
mod statement;

use crate::{Error, Result};
use features::{Feature, RuleFeatureType};
use statement::{
    AndStatement, Description, NotStatement, OrStatement, RangeStatement, SomeStatement, Statement,
    StatementElement, SubscopeStatement,
};
use std::collections::HashMap;
use yaml_rust::{yaml::Hash, Yaml, YamlLoader};

const MAX_BYTES_FEATURE_SIZE: usize = 0x100;

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
    Function,
    File,
    BasicBlock,
    Instruction,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Rule {
    pub name: String,
    scope: Scope,
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
                if key.starts_with("number/") {
                    let parts: Vec<&str> = key.split('/').collect();
                    let bitness = Rule::parse_int(&parts[1].trim()[1..])? as u32;
                    return Ok(RuleFeatureType::Number(bitness));
                }
                if key.starts_with("offset/") {
                    let parts: Vec<&str> = key.split('/').collect();
                    let bitness = Rule::parse_int(&parts[1].trim()[1..])? as u32;
                    return Ok(RuleFeatureType::Offset(bitness));
                }
                if key.starts_with("operand[") && key.ends_with("].number") {
                    let index =
                        (&key["operand[".len()..key.len() - "].number".len()]).parse::<usize>()?;
                    return Ok(RuleFeatureType::OperandNumber(index));
                }
                if key.starts_with("operand[") && key.ends_with("].offset") {
                    let index =
                        (&key["operand[".len()..key.len() - "].offset".len()]).parse::<usize>()?;
                    return Ok(RuleFeatureType::OperandOffset(index));
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
                if s.contains(" = ") {
                    if description.is_some() {
                        // there is already a description passed in as a sub node, like:
                        //
                        //    - number: 10 = CONST_FOO
                        //      description: CONST_FOO
                        return Err(Error::InvalidRule(line!(), s.to_string()));
                    }
                    let parts: Vec<&str> = s.split(" = ").collect();
                    v = parts[0].trim();
                    let ddd = parts[1];
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
        let scope = match &meta["scope"] {
            Yaml::String(s) => match s.as_str() {
                "function" => Scope::Function,
                "file" => Scope::File,
                "basic block" => Scope::BasicBlock,
                "instruction" => Scope::Instruction,
                _ => return Err(Error::InvalidRule(line!(), definition.to_string())),
            },
            Yaml::Null => Scope::Function,
            _ => return Err(Error::InvalidRule(line!(), definition.to_string())),
        };
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
            &scope,
            Rule::build_statements(&statements[0], &scope)?,
            &meta
                .as_hash()
                .ok_or_else(|| Error::InvalidRule(line!(), definition.to_string()))?
                .clone(),
            definition,
        )
    }

    pub fn new(
        name: &str,
        scope: &Scope,
        statement: StatementElement,
        meta: &Hash,
        definition: &str,
    ) -> Result<Rule> {
        Ok(Rule {
            name: name.to_string(),
            scope: scope.clone(),
            statement,
            meta: meta.clone(),
            definition: definition.to_string(),
        })
    }

    pub fn build_statements(dd: &Yaml, scope: &Scope) -> Result<StatementElement> {
        let d = dd
            .as_hash()
            .ok_or_else(|| Error::InvalidRule(line!(), "statement need to be hash".to_string()))?;

        if let Some((key, vval)) = d.into_iter().next() {
            match key
                .as_str()
                .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", key)))?
            {
                "description" => {
                    let val = vval
                        .as_str()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    return Ok(StatementElement::Description(Box::new(Description::new(
                        val,
                    )?)));
                }
                "and" => {
                    let mut params = vec![];
                    let mut description = "".to_string();
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    for vv in val {
                        let p = Rule::build_statements(vv, scope)?;
                        match p {
                            StatementElement::Description(s) => description = s.value,
                            _ => params.push(p),
                        }
                    }
                    return Ok(StatementElement::Statement(Box::new(Statement::And(
                        AndStatement::new(params, &description)?,
                    ))));
                }
                "or" => {
                    let mut params = vec![];
                    let mut description = "".to_string();
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    for vv in val {
                        let p = Rule::build_statements(vv, scope)?;
                        match p {
                            StatementElement::Description(s) => description = s.value,
                            _ => params.push(p),
                        }
                    }
                    return Ok(StatementElement::Statement(Box::new(Statement::Or(
                        OrStatement::new(params, &description)?,
                    ))));
                }
                "not" => {
                    let mut params = vec![];
                    let mut description = "".to_string();
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    for vv in val {
                        let p = Rule::build_statements(vv, scope)?;
                        match p {
                            StatementElement::Description(s) => description = s.value,
                            _ => params.push(p),
                        }
                    }
                    return Ok(StatementElement::Statement(Box::new(Statement::Not(
                        NotStatement::new(params[0].clone(), &description)?,
                    ))));
                }
                "optional" => {
                    let mut params = vec![];
                    let mut description = "".to_string();
                    let val = vval
                        .as_vec()
                        .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                    for vv in val {
                        let p = Rule::build_statements(vv, scope)?;
                        match p {
                            StatementElement::Description(s) => description = s.value,
                            _ => params.push(p),
                        }
                    }
                    return Ok(StatementElement::Statement(Box::new(Statement::Some(
                        SomeStatement::new(0, params, &description)?,
                    ))));
                }
                "function" => {
                    if let Scope::File = scope {
                        let mut params = vec![];
                        let mut description = "".to_string();
                        let val = vval
                            .as_vec()
                            .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                        for vv in val {
                            let p = Rule::build_statements(vv, &Scope::Function)?;
                            match p {
                                StatementElement::Description(s) => description = s.value,
                                _ => params.push(p),
                            }
                        }
                        if params.len() != 1 {
                            return Err(Error::InvalidRule(
                                line!(),
                                format!("{:?}: {:?}", key, vval),
                            ));
                        }
                        return Ok(StatementElement::Statement(Box::new(Statement::Subscope(
                            SubscopeStatement::new(
                                Scope::Function,
                                params[0].clone(),
                                &description,
                            )?,
                        ))));
                    }
                    return Err(Error::InvalidRule(
                        line!(),
                        format!("{:?}: {:?}", key, vval),
                    ));
                }
                "basic block" => {
                    if let Scope::Function = scope {
                        let mut params = vec![];
                        let mut description = "".to_string();
                        let val = vval
                            .as_vec()
                            .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                        for vv in val {
                            let p = Rule::build_statements(vv, scope)?;
                            match p {
                                StatementElement::Description(s) => description = s.value,
                                _ => params.push(p),
                            }
                        }
                        if params.len() != 1 {
                            return Err(Error::InvalidRule(
                                line!(),
                                format!("{:?}: {:?}", key, vval),
                            ));
                        }
                        return Ok(StatementElement::Statement(Box::new(Statement::Subscope(
                            SubscopeStatement::new(
                                Scope::BasicBlock,
                                params[0].clone(),
                                &description,
                            )?,
                        ))));
                    }
                    return Err(Error::InvalidRule(
                        line!(),
                        format!("{:?}: {:?}", key, vval),
                    ));
                }
                "instruction" => {
                    if let Scope::BasicBlock | Scope::Function = scope {
                        let mut params = vec![];
                        let mut description = "".to_string();
                        let val = vval
                            .as_vec()
                            .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                        for vv in val {
                            let p = Rule::build_statements(vv, scope)?;
                            match p {
                                StatementElement::Description(s) => description = s.value,
                                _ => params.push(p),
                            }
                        }
                        //                        if params.len() != 1 {
                        //                            return Err(Error::InvalidRule(
                        //                                line!(),
                        //                                format!("{:?}: {:?}", key, vval),
                        //                            ));
                        //                        }
                        return Ok(StatementElement::Statement(Box::new(Statement::Subscope(
                            SubscopeStatement::new(
                                Scope::Instruction,
                                params[0].clone(),
                                &description,
                            )?,
                        ))));
                    }
                    return Err(Error::InvalidRule(
                        line!(),
                        format!("{:?},  {:?}: {:?}", scope, key, vval),
                    ));
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
                        let count = x.parse::<u32>()?;
                        let mut params = vec![];
                        let mut description = "".to_string();
                        let val = vval
                            .as_vec()
                            .ok_or_else(|| Error::InvalidRule(line!(), format!("{:?}", vval)))?;
                        for vv in val {
                            let p = Rule::build_statements(vv, scope)?;
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
                            &arg[..arg.len() - ")".len()]
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
                        Rule::ensure_feature_valid_for_scope(scope, &feature)?;
                        //let val =
                        // vval.as_str().ok_or(Error::InvalidRule(line!(),
                        // format!("{:?} must be string", vval)))?;
                        match vval {
                            Yaml::Integer(i) => {
                                return Ok(StatementElement::Statement(Box::new(
                                    Statement::Range(RangeStatement::new(
                                        StatementElement::Feature(Box::new(feature)),
                                        *i as u32,
                                        *i as u32,
                                        "",
                                    )?),
                                )));
                            }
                            Yaml::String(val) => {
                                if val.ends_with(" or more") {
                                    // let min = i64::from_str_radix(
                                    //     &val[..val.len() - " or more".len()],
                                    //     10,
                                    // )?;
                                    let min =
                                        (&val[..val.len() - " or more".len()]).parse::<i64>()?;
                                    let max = 0xFFFFFFFF_u32;
                                    return Ok(StatementElement::Statement(Box::new(
                                        Statement::Range(RangeStatement::new(
                                            StatementElement::Feature(Box::new(feature)),
                                            min as u32,
                                            max,
                                            "",
                                        )?),
                                    )));
                                } else if val.ends_with(" or fewer") {
                                    let min = 0_u32;
                                    let max =
                                        (&val[..val.len() - " or fewer".len()]).parse::<i64>()?;
                                    // let max = i64::from_str_radix(
                                    //     &val[..val.len() - " or fewer".len()],
                                    //     10,
                                    // )?;
                                    return Ok(StatementElement::Statement(Box::new(
                                        Statement::Range(RangeStatement::new(
                                            StatementElement::Feature(Box::new(feature)),
                                            min as u32,
                                            max as u32,
                                            "",
                                        )?),
                                    )));
                                } else if val.starts_with('(') {
                                    let (min, max) = Rule::parse_range(val)?;
                                    return Ok(StatementElement::Statement(Box::new(
                                        Statement::Range(RangeStatement::new(
                                            StatementElement::Feature(Box::new(feature)),
                                            min as u32,
                                            max as u32,
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
                                ))
                            }
                        }
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
                        Rule::ensure_feature_valid_for_scope(scope, &feature)?;
                        return Ok(StatementElement::Feature(Box::new(feature)));
                    }
                }
            }
        }
        Err(Error::InvalidRule(line!(), "finish".to_string()))
    }

    pub fn ensure_feature_valid_for_scope(scope: &Scope, feature: &Feature) -> Result<()> {
        if feature.is_supported_in_scope(scope)? {
            return Ok(());
        }
        Err(Error::InvalidRule(
            line!(),
            format!("{:?} not suported in scope {:?}", feature, scope),
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
    let mut rules = vec![];
    for entry in walkdir::WalkDir::new(rule_path)
        .into_iter()
        .filter_entry(|e| !is_hidden(e))
        .filter_map(|e| e.ok())
    {
        let fname = entry.path().to_str().unwrap().to_string();
        if fname.ends_with(".yml") || fname.ends_with(".yaml") {
            let mut rule = match Rule::from_yaml_file(&fname){
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warn: rule {} error: {:?}", fname, e);
                    continue;
                }
            };
            rule.set_path(fname.clone())?;
            rules.push(rule)
        }
    }
    Ok(rules)
}

#[derive(Debug)]
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

pub fn get_rules_for_scope<'a>(rules: &'a [Rule], scope: &Scope) -> Result<Vec<&'a Rule>> {
    let mut scope_rules = vec![];
    for rule in rules {
        if rule
            .meta
            .contains_key(&Yaml::String("capa/subscope-rule".to_string()))
        {
            if let Yaml::Boolean(b) = rule.meta[&Yaml::String("capa/subscope-rule".to_string())] {
                if b {
                    continue;
                }
            }
        }
        scope_rules.append(&mut get_rules_and_dependencies(rules, &rule.name)?);
    }
    let trules = topologically_order_rules(scope_rules)?;

    get_rules_with_scope(trules, scope)
}

pub fn get_rules_and_dependencies<'a>(rules: &'a [Rule], rule_name: &str) -> Result<Vec<&'a Rule>> {
    let mut res = vec![];
    //# we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    let namespaces = index_rules_by_namespace(rules)?;
    let mut rules_by_name = HashMap::new();
    for rule in rules {
        rules_by_name.insert(rule.name.clone(), rule);
    }
    let mut wanted = vec![rule_name.to_string()];

    fn rec<'a>(
        want: &mut Vec<String>,
        rule: &'a Rule,
        rules_by_name: &HashMap<String, &Rule>,
        namespaces: &HashMap<String, Vec<&Rule>>,
    ) -> Result<()> {
        want.push(rule.name.clone());
        for dep in rule.get_dependencies(namespaces)? {
            rec(want, rules_by_name[&dep], rules_by_name, namespaces)?;
        }
        Ok(())
    }

    rec(
        &mut wanted,
        rules_by_name[rule_name],
        &rules_by_name,
        &namespaces,
    )?;
    for (_, rule) in rules_by_name {
        if wanted.contains(&rule.name) {
            res.push(rule)
        }
    }
    Ok(res)
}

pub fn get_rules_with_scope<'a>(rules: Vec<&'a Rule>, scope: &Scope) -> Result<Vec<&'a Rule>> {
    let mut res = vec![];
    for rule in rules {
        if &rule.scope == scope {
            res.push(rule);
        }
    }
    Ok(res)
}

pub fn index_rules_by_namespace(rules: &[Rule]) -> Result<HashMap<String, Vec<&Rule>>> {
    let mut namespaces: HashMap<String, Vec<&Rule>> = HashMap::new();
    for rule in rules {
        if rule
            .meta
            .contains_key(&yaml_rust::Yaml::String("namespace".to_string()))
        {
            match &rule.meta[&yaml_rust::Yaml::String("namespace".to_string())] {
                yaml_rust::Yaml::String(namespace) => {
                    let mut ns = Some(namespace.clone());
                    while let Some(nss) = ns {
                        match namespaces.get_mut(&nss) {
                            Some(n) => {
                                n.push(rule);
                            }
                            _ => {
                                namespaces.insert(nss.clone(), vec![rule]);
                            }
                        }
                        let parts: Vec<&str> = nss.split('/').collect();
                        if parts.len() == 1 {
                            ns = None;
                        } else {
                            let mut nsss = "".to_string();
                            for item in parts.iter().take(parts.len() - 1) {
                                nsss += "/";
                                nsss += item;
                            }
                            ns = Some(nsss[1..].to_string());
                        }
                    }
                }
                _ => {
                    continue;
                }
            }
        }
    }
    Ok(namespaces)
}

pub fn index_rules_by_namespace2<'a>(rules: &[&'a Rule]) -> Result<HashMap<String, Vec<&'a Rule>>> {
    let mut namespaces: HashMap<String, Vec<&Rule>> = HashMap::new();
    for rule in rules {
        if rule
            .meta
            .contains_key(&yaml_rust::Yaml::String("namespace".to_string()))
        {
            match &rule.meta[&yaml_rust::Yaml::String("namespace".to_string())] {
                yaml_rust::Yaml::String(namespace) => {
                    let mut ns = Some(namespace.clone());
                    while let Some(nss) = ns {
                        match namespaces.get_mut(&nss) {
                            Some(n) => {
                                n.push(rule);
                            }
                            _ => {
                                namespaces.insert(nss.clone(), vec![rule]);
                            }
                        }
                        let parts: Vec<&str> = nss.split('/').collect();
                        if parts.len() == 1 {
                            ns = None;
                        } else {
                            let mut nsss = "".to_string();
                            for item in parts.iter().take(parts.len() - 1) {
                                nsss += "/";
                                nsss += item;
                            }
                            ns = Some(nsss[1..].to_string());
                        }
                    }
                }
                _ => {
                    continue;
                }
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
            rett.append(&mut rec(
                rules_by_name[&dep],
                seen,
                rules_by_name,
                namespaces,
            )?);
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
