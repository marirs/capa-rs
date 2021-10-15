#[derive(thiserror::Error, Debug)]
pub enum Error {
    // #[error("parsing error")]
    // ParseError,
    #[error("{0}")]
    SMDAError(#[from] smda::Error),
    #[error("unsupported format")]
    UnsupportedFormatError,
    #[error("unsupported arch")]
    UnsupportedArchError,
    #[error("unsupported os")]
    UnsupportedOsError,
    #[error("goblin error")]
    ParseError(#[from] goblin::error::Error),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("try convert error")]
    FromSloceError(#[from] std::array::TryFromSliceError),
    #[error("logic error")]
    LogicError(&'static str, u32),
    // #[error("capstone error")]
    // CapstoneError(capstone::Error),
    #[error("regex error")]
    RegexError(#[from] regex::Error),
    #[error("utf convert error")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("collision error")]
    CollisionError(u64),
    #[error("dereference error")]
    DereferenceError(u64),
    #[error("unsuported pe bitness id")]
    UnsupportedPEBitnessIDError(u16),
    #[error("pe base address error")]
    PEBaseAdressError,
    #[error("parse int error")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("not implemented error")]
    NoiImplementedError,
    #[error("not enough bytes in buffer")]
    NotEnoughBytesError(u64, u64),
    #[error("json parse error")]
    JsonParseError(#[from] serde_json::Error),
    #[error("json format error")]
    JsonFormatError(&'static str, u32),
    #[error("invalid rule")]
    InvalidRule(u32, String),
    #[error("fromHexError")]
    FromHexError(#[from] hex::FromHexError),
    #[error("YamlError")]
    YamlError(#[from] yaml_rust::ScanError),
    #[error("operand error")]
    OperandError,
    #[error("subscope evaluation error")]
    SubscopeEvaluationError,
    #[error("description evaluation error")]
    DescriptionEvaluationError,
    #[error("description evaluation error")]
    RangeStatementError,
    #[error("utf16 error")]
    FromUtf16Error(#[from] std::string::FromUtf16Error),
    #[error("pdb error")]
    PdbError(#[from] pdb::Error),
    // #[error("utf8 error")]
    // UtfError(#[from] std::str::Utf8Error),
    // #[error("parse int error")]
    // ParseIntError(#[from] std::num::ParseIntError),
    // #[error("bad header")]
    // BadHeaderError,
    // #[error("bad close delimiter")]
    // BadCloseDelimiterError,
    // #[error("close delimiter")]
    // CloseDelimiterNOtFoundError(String),
    // #[error("stream length element not found")]
    // StreamLengthElementNotFound,
    // #[error("dictionary get error")]
    // DictionaryGetError(String),
    // #[error("new line error")]
    // NewLineError,
    // #[error("zero parts error")]
    // ZeroPartsError,
    // #[error("undefined pdf object error")]
    // UndefinedPDFObjectError,
    // #[error("object stream first element not found")]
    // ObjectStreamFirstElementNotFound,
    // #[error("object stream n elements not found")]
    // ObjectStreamNElementsNotFound,
    // #[error("incorrect filter params type")]
    // IncorrectFilterParamsTypeError,
    // #[error("incorrect filter type")]
    // IncorrectFilterTypeError,
    // #[error("decode error")]
    // DecodeError,
    // #[error("unsupported decode filter")]
    // UnsupportedDecodeFilterError(String),
    // #[error("ascii hex decode")]
    // AsciiHexDecodeError,
    // #[error("ascii 85 decode")]
    // Ascii85DecodeError,
    // #[error("incorrect predictor type")]
    // IncorrectPredictorTypeError,
    // #[error("flate decode")]
    // FlateDecodeError,
    // #[error("parse cross ref section")]
    // ParseCrossRefSectionError,
    // #[error("parse cross ref entry")]
    // ParseCrossRefEntryError,
    // #[error("parse obbject stream")]
    // ParseObjectStreamError,
    // #[error("array get")]
    // ArrayGetError,
    // #[error("parse trailer")]
    // ParseTrailerError,
    // #[error("have no xref stream in body")]
    // HaveNoXrefStreamInBodyError,
    // #[error("have no object stream in body")]
    // HaveNoObjectStreamInBodyError,
    // #[error("get object by id")]
    // GetObjError(u32, usize),
    // #[error("decryption")]
    // DecryptionError,
    // #[error("decryption unsupported filter")]
    // DecryptionUnsupportedFilterError,
    // #[error("unsupported crypt method")]
    // UnsupportedCryptMethodError,
    // #[error("unsupported crypt revision")]
    // UnsupportedRevisionError,
    // #[error("invalid password")]
    // InvalidPasswordError,
    // #[error("user pass length must be 48")]
    // UnsupportedUserPassLengthError(usize),
    // #[error("owner pass length must be 48")]
    // UnsupportedOwnerPassLengthError(usize),
    // #[error("UE Trailer field not fount")]
    // UETrailerFieldAbsenceError,
    // #[error("OE Trailer field not fount")]
    // OETrailerFieldAbsenceError,
    // #[error("unsupported crypt version")]
    // UnsupportedVersionError,
    // #[error("string prep")]
    // StringPrepError(#[from] stringprep::Error),
    // #[error("hex decimal format")]
    // HexDecimalFormatError(String),
    // #[error("utf16 decode")]
    // Utf16DecodeError(#[from] std::string::FromUtf16Error),
    // #[error("undefined reference")]
    // UndefinedReferenceError(u32)
}
