#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("logic error: {0} - {1}")]
    LogicError(&'static str, u32),
    #[error("not enough bytes in buffer: {0} - {1}")]
    NotEnoughBytesError(u64, u64),
    #[error("pe base address error")]
    PEBaseAddressError,
    #[error("unsuported pe bitness id: {0}")]
    UnsupportedPEBitnessIDError(u16),
    #[error("invalid rule: {0} - {1}")]
    InvalidRule(u32, String),
    #[error("json format error: {0} - {1}")]
    JsonFormatError(&'static str, u32),
    #[error("operand error")]
    OperandError,
    #[error("collision error: {0}")]
    CollisionError(u64),
    #[error("dereference error: {0}")]
    DereferenceError(u64),

    #[error("{0}")]
    FromSliceError(#[from] std::array::TryFromSliceError),
    #[error("utf convert error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("{0}")]
    FromHexError(#[from] hex::FromHexError),
    #[error("json parse error: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("{0}")]
    CapstoneError(capstone::Error),
    #[error("{0}")]
    RegexError(#[from] regex::Error),
    #[error("{0}")]
    ParseError(#[from] goblin::error::Error),
    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("unsupported format")]
    UnsupportedFormatError,
    #[error("Not implemented")]
    NotImplementedError,
}
