use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    SMDAError(#[from] smda::Error),
    #[error("{0}")]
    RegexError(#[from] regex::Error),
    #[error("{0}")]
    FancyRegexError(#[from] Box<fancy_regex::Error>),
    #[error("{0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("{0}")]
    YamlError(#[from] yaml_rust::ScanError),
    #[error("{0}")]
    PdbError(#[from] pdb::Error),
    #[error("{0}")]
    DnFileError(#[from] dnfile::error::Error),

    #[error("binary format of file '{0}' is not recognized")]
    UnknownBinaryFormat(PathBuf),

    #[error("binary format of '{name}' is not {expected}")]
    UnexpectedBinaryFormat {
        expected: &'static str,
        name: PathBuf,
    },

    #[error("architecture of '{0}' is unexpected")]
    UnexpectedBinaryArchitecture(PathBuf),

    #[error("binary format '{format}' of file '{path}' is recognized but unsupported")]
    UnsupportedBinaryFormat { format: String, path: PathBuf },

    #[error("dependent C runtime library is not recognized. Consider specifying --sysroot, --libc, --libc-spec or --no-libc")]
    UnrecognizedNeededLibC,

    #[error("dependent C runtime library '{0}' was not found")]
    NotFoundNeededLibC(PathBuf),

    #[error(transparent)]
    FromBytesWithNul(#[from] core::ffi::FromBytesWithNulError),

    #[error(transparent)]
    FromBytesUntilNul(#[from] core::ffi::FromBytesUntilNulError),

    #[error(transparent)]
    Scroll(#[from] scroll::Error),

    #[error(transparent)]
    DynamicLoaderCache(#[from] dynamic_loader_cache::Error),

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
    #[error("Buffer overflow error")]
    BufferOverflowError,
}
