#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("logic error")]
    LogicError(&'static str, u32),
    #[error("not enough bytes in buffer")]
    NotEnoughBytesError(u64, u64),
    #[error("pe base address error")]
    PEBaseAdressError,
    #[error("unsuported pe bitness id: {0}")]
    UnsupportedPEBitnessIDError(u16),
    #[error("invalid rule: {0} - {1}")]
    InvalidRule(u32, String),
    #[error("json parse error: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("json format error: {0} - {1}")]
    JsonFormatError(&'static str, u32),
    #[error("parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("operand error")]
    OperandError,
    #[error("collision error: {0}")]
    CollisionError(u64),
    #[error("utf convert error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("dereference error: {0}")]
    DereferenceError(u64),
    #[error("{0}")]
    FromHexError(#[from] hex::FromHexError),

    #[error("{0}")]
    FromSloceError(#[from] std::array::TryFromSliceError),
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
