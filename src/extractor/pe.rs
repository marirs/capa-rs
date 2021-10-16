use crate::{Endian, Error, FileArchitecture, Os, Result};
use goblin::pe::PE;

pub fn get_arch(pe: &PE) -> Result<FileArchitecture> {
    match pe.header.coff_header.machine {
        goblin::pe::header::COFF_MACHINE_X86 => Ok(FileArchitecture::I386),
        goblin::pe::header::COFF_MACHINE_X86_64 => Ok(FileArchitecture::AMD64),
        _ => Err(Error::UnsupportedArchError),
    }
}

pub fn get_endian(_pe: &PE) -> Result<Endian> {
    Ok(Endian::Big)
}

pub fn get_os(_pe: &PE) -> Result<Os> {
    Ok(Os::WINDOWS)
}
