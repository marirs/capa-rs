use crate::rules::Scope;
use crate::{Error, Result, rules::features::Feature};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum StatementElement {
    Statement(Box<Statement>),
    Feature(Box<Feature>),
    Description(Box<Description>),
}

impl StatementElement {
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        match self {
            StatementElement::Statement(s) => s.evaluate(features),
            StatementElement::Feature(s) => s.evaluate(features),
            StatementElement::Description(s) => s.evaluate(features),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Statement {
    And(AndStatement),
    Or(OrStatement),
    Not(NotStatement),
    Some(SomeStatement),
    Range(RangeStatement),
    Subscope(SubscopeStatement),
}

impl Statement {
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        match self {
            Statement::And(s) => s.get_children(),
            Statement::Or(s) => s.get_children(),
            Statement::Not(s) => s.get_children(),
            Statement::Some(s) => s.get_children(),
            Statement::Range(s) => s.get_children(),
            Statement::Subscope(s) => s.get_children(),
        }
    }

    /// 0.4.1: mutable children — used by the subscope-extraction pass
    /// in `rules::mod` to walk the tree and rewrite each `Subscope`
    /// inline into a `MatchedRule` reference + companion synthetic
    /// rule. Mirrors `get_children` but yields `&mut`.
    pub fn children_mut(&mut self) -> Vec<&mut StatementElement> {
        match self {
            Statement::And(s) => s.children.iter_mut().collect(),
            Statement::Or(s) => s.children.iter_mut().collect(),
            Statement::Not(s) => vec![&mut s.child],
            Statement::Some(s) => s.children.iter_mut().collect(),
            Statement::Range(s) => vec![&mut s.child],
            Statement::Subscope(s) => vec![&mut s.child],
        }
    }

    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        match self {
            Statement::And(s) => s.evaluate(features),
            Statement::Or(s) => s.evaluate(features),
            Statement::Not(s) => s.evaluate(features),
            Statement::Some(s) => s.evaluate(features),
            Statement::Range(s) => s.evaluate(features),
            Statement::Subscope(s) => s.evaluate(features),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AndStatement {
    children: Vec<StatementElement>,
    description: String,
}

impl AndStatement {
    pub fn new(params: Vec<StatementElement>, description: &str) -> Result<AndStatement> {
        Ok(AndStatement {
            children: params,
            description: description.to_string(),
        })
    }
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        let mut res = vec![];
        for c in &self.children {
            res.push(c);
        }
        Ok(res)
    }
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        let mut res = true;
        for child in &self.children {
            res &= child.evaluate(features)?.0;
        }
        Ok((res, vec![]))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct OrStatement {
    children: Vec<StatementElement>,
    description: String,
}

impl OrStatement {
    pub fn new(params: Vec<StatementElement>, description: &str) -> Result<OrStatement> {
        Ok(OrStatement {
            children: params,
            description: description.to_string(),
        })
    }
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        let mut res = vec![];
        for c in &self.children {
            res.push(c);
        }
        Ok(res)
    }
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        let mut res = false;
        for child in &self.children {
            res |= child.evaluate(features)?.0;
        }
        Ok((res, vec![]))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NotStatement {
    child: StatementElement,
    description: String,
}

impl NotStatement {
    pub fn new(params: StatementElement, description: &str) -> Result<NotStatement> {
        Ok(NotStatement {
            child: params,
            description: description.to_string(),
        })
    }
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        Ok(vec![&self.child])
    }
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        Ok((!self.child.evaluate(features)?.0, vec![]))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SomeStatement {
    children: Vec<StatementElement>,
    count: u32,
    description: String,
}

impl SomeStatement {
    pub fn new(
        count: u32,
        params: Vec<StatementElement>,
        description: &str,
    ) -> Result<SomeStatement> {
        Ok(SomeStatement {
            children: params,
            description: description.to_string(),
            count,
        })
    }
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        let mut res = vec![];
        for c in &self.children {
            res.push(c);
        }
        Ok(res)
    }
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        let mut res = 0;
        for child in &self.children {
            if child.evaluate(features)?.0 {
                res += 1;
            }
        }
        Ok((res >= self.count, vec![]))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RangeStatement {
    child: StatementElement,
    min: u32,
    max: u32,
    description: String,
}

impl RangeStatement {
    pub fn new(
        params: StatementElement,
        min: u32,
        max: u32,
        description: &str,
    ) -> Result<RangeStatement> {
        Ok(RangeStatement {
            child: params,
            min,
            max,
            description: description.to_string(),
        })
    }
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        Ok(vec![&self.child])
    }
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        if let StatementElement::Feature(f) = &self.child {
            let count = match features.get(f) {
                Some(ss) => ss.len(),
                _ => 0,
            };
            return Ok((
                count >= self.min as usize && count <= self.max as usize,
                vec![],
            ));
        }
        Err(Error::RangeStatementError)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SubscopeInstructionEvaluator;

impl SubscopeInstructionEvaluator {
    pub fn evaluate(
        statement: &StatementElement,
        features: &HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        let mut addr_to_features: HashMap<u64, HashSet<&Feature>> = HashMap::new();

        for (feature, addrs) in features.iter() {
            for addr in addrs {
                addr_to_features.entry(*addr).or_default().insert(feature);
            }
        }

        if let StatementElement::Statement(stmt) = statement {
            if let Statement::And(and_stmt) = stmt.as_ref() {
                for (_addr, feature_set) in addr_to_features.iter() {
                    let mut matched = true;
                    for elem in &and_stmt.children {
                        if let StatementElement::Feature(f) = elem {
                            if !feature_set.iter().any(|feat| *feat == f.as_ref()) {
                                matched = false;
                                break;
                            }
                        } else {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        return Ok((true, vec![]));
                    }
                }
            }
        }

        Ok((false, vec![]))
    }
}
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SubscopeStatement {
    child: StatementElement,
    scope: Scope,
    description: String,
}

impl SubscopeStatement {
    pub fn new(
        scope: Scope,
        params: StatementElement,
        description: &str,
    ) -> Result<SubscopeStatement> {
        Ok(SubscopeStatement {
            child: params,
            description: description.to_string(),
            scope,
        })
    }
    pub fn get_children(&self) -> Result<Vec<&StatementElement>> {
        Ok(vec![&self.child])
    }
    /// 0.4.1: borrow the target scope of this subscope. Used by the
    /// extraction pass to determine the synthetic rule's scope.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    /// 0.4.1: borrow the description string. Used by the extraction
    /// pass to copy it onto the synthetic rule.
    pub fn description(&self) -> &str {
        &self.description
    }
    /// 0.4.1: consume the subscope and return its `(scope, child,
    /// description)` parts. Used by the extraction pass in
    /// `rules::mod` to move the inner statement onto the synthetic
    /// rule without cloning.
    pub fn into_inner(self) -> (Scope, StatementElement, String) {
        (self.scope, self.child, self.description)
    }
    pub fn evaluate(&self, features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        match self.scope {
            Scope::Instruction => SubscopeInstructionEvaluator::evaluate(&self.child, features),
            _ => self.child.evaluate(features),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Description {
    pub value: String,
}

impl Description {
    pub fn new(description: &str) -> Result<Description> {
        Ok(Description {
            value: description.to_string(),
        })
    }
    pub fn evaluate(&self, _features: &HashMap<Feature, Vec<u64>>) -> Result<(bool, Vec<u64>)> {
        Err(Error::DescriptionEvaluationError)
    }
}
