#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    SMDAError(#[from] smda::Error),
    #[error("{0}")]
    RegexError(#[from] regex::Error),
    #[error("{0}")]
    FancyRegexError(#[from] fancy_regex::Error),
    #[error("{0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("{0}")]
    YamlError(#[from] yaml_rust::ScanError),
    #[error("{0}")]
    PdbError(#[from] pdb::Error),
    #[error("{0}")]
    DnFileError(#[from] dnfile::error::Error),

    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    FromSliceError(#[from] std::array::TryFromSliceError),
    #[error("parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("{0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("utf16 error: {0}")]
    FromUtf16Error(#[from] std::string::FromUtf16Error),

    #[error("goblin error")]
    ParseError(#[from] goblin::error::Error),

    #[error("unsupported format")]
    UnsupportedFormatError,
    #[error("unsupported arch")]
    UnsupportedArchError,
    #[error("unsupported os")]
    UnsupportedOsError,
    #[error("not enough bytes in buffer: {0} - {1}")]
    NotEnoughBytesError(u64, u64),
    #[error("json format error: {0} - {1}")]
    JsonFormatError(&'static str, u32),
    #[error("invalid rule: {0} - {1}")]
    InvalidRule(u32, String),
    #[error("invalid scope: {0} - {1}")]
    InvalidScope(u32, String),
    #[error("invalid static scope: {0}")]
    InvalidStaticScope(u32),
    #[error("{0}")]
    UndefinedComType(String),
    #[error("invalid dynamic scope: {0}")]
    InvalidDynamicScope(u32),
    #[error("{0}")]
    InvalidRuleFile(String),
    #[error("operand error")]
    OperandError,
    #[error("subscope evaluation error")]
    SubscopeEvaluationError,
    #[error("description evaluation error")]
    DescriptionEvaluationError,
    #[error("range statement error")]
    RangeStatementError,
    #[error("invalid token {0}")]
    InvalidToken(String),
    #[error("not implemented")]
    NoiImplementedError,
}
