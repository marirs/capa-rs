use crate::error::Error;
use crate::result::Result;
use crate::rules::features::Feature;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum StatementElement {
    Statement(Box<Statement>),
    Feature(Box<Feature>),
    Description(Box<Description>),
}

impl StatementElement {
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        if let StatementElement::Feature(f) = &self.child {
            let count = match features.get(&f) {
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
pub struct SubscopeStatement {
    child: StatementElement,
    scope: crate::rules::Scope,
    description: String,
}

impl SubscopeStatement {
    pub fn new(
        scope: crate::rules::Scope,
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
    pub fn evaluate(
        &self,
        features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        self.child.evaluate(features)
        //        Err(Error::SubscopeEvaluationError)
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
    pub fn evaluate(
        &self,
        _features: &std::collections::HashMap<Feature, Vec<u64>>,
    ) -> Result<(bool, Vec<u64>)> {
        Err(Error::DescriptionEvaluationError)
    }
}
