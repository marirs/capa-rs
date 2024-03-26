mod pe;
mod parser;
pub(crate) mod options;
mod elf;
pub(crate) mod cmdline;

use std::path::{Path};

use log::{debug};


use crate::Result;
use crate::error::{Error};
use crate::security::options::status::{SecurityCheckStatus};
use crate::security::parser::BinaryParser;

pub fn get_security_checks(
    path: &impl AsRef<Path>,
    options: &cmdline::Options,
) -> Result<Vec<SecurityCheckStatus>> {
    use goblin::Object;

    let parser = BinaryParser::open(path.as_ref())?;

    let results = match parser.object() {
        Object::Elf(_elf) => {
            debug!("Binary file format is 'ELF'.");
            elf::analyze_binary(&parser, options)
        }

        Object::PE(_pe) => {
            debug!("Binary file format is 'PE'.");
            pe::analyze_binary(&parser, options)
        }

        Object::Mach(_mach) => {
            debug!("Binary file format is 'MACH'.");
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
        .map(|r| r.get_status().unwrap())
        .collect::<Vec<_>>();
    
    Ok(statuses)
}
