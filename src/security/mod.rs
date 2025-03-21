use crate::{
    error::Error,
    security::{options::status::SecurityCheckStatus, parser::BinaryParser},
    Result,
};
use std::path::Path;

pub(crate) mod elf;
pub(crate) mod options;
mod parser;
mod pe;

pub fn get_security_checks(
    path: &impl AsRef<Path>,
    options: &crate::BinarySecurityCheckOptions,
) -> Result<Vec<SecurityCheckStatus>> {
    use goblin::Object;

    let parser = BinaryParser::open(path.as_ref())?;

    let results = match parser.object() {
        Object::Elf(_elf) => {
            // "Binary file format is 'ELF'."
            elf::analyze_binary(&parser, options)
        }

        Object::PE(_pe) => {
            // "Binary file format is 'PE'."
            pe::analyze_binary(&parser, options)
        }

        Object::Mach(_mach) => {
            // "Binary file format is 'MACH'."
            Err(Error::UnsupportedBinaryFormat {
                format: "MACH".into(),
                path: path.as_ref().into(),
            })
        }

        Object::Unknown(_magic) => Err(Error::UnknownBinaryFormat(path.as_ref().into())),

        _ => Err(Error::UnknownBinaryFormat(path.as_ref().into())),
    }?;
    let statuses = results
        .into_iter()
        .map(|r| r.get_security_check_status().unwrap())
        .collect::<Vec<_>>();

    Ok(statuses)
}
