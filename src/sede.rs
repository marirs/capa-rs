use serde::{Serializer, Deserializer, Deserialize};

pub fn to_hex<S>(x: &usize, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    s.serialize_str(&format!("0x{:08x}", x))
}

pub fn from_hex<'de, D>(d: D) -> std::result::Result<usize, D::Error>
    where
        D: Deserializer<'de>,
{
    let buf = String::deserialize(d)?;
    if !buf.starts_with("0x") {
        return Err(serde::de::Error::custom(buf));
    }
    usize::from_str_radix(&buf[2..], 16).map_err(serde::de::Error::custom)
}
