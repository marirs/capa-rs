use crate::error::Error;
use crate::result::Result;
use crate::{FileArchitecture, Endian, Os};
use goblin::elf::Elf;

pub fn get_arch(elf: &Elf) -> Result<FileArchitecture> {
    match elf.header.e_machine {
        0x03 => Ok(FileArchitecture::I386),
        0x3e => Ok(FileArchitecture::AMD64),
        _ => Err(Error::UnsupportedArchError),
    }
}

pub fn get_endian(_elf: &Elf) -> Result<Endian> {
    Ok(Endian::Big)
}

pub fn get_os(elf: &Elf) -> Result<Os> {
    match elf.header.e_ident[7] {
        0x00 => Ok(Os::UNDEFINED),
        0x01 => Ok(Os::HPUX),
        0x02 => Ok(Os::NETBSD),
        0x03 => Ok(Os::LINUX),
        0x04 => Ok(Os::HURD),
        0x06 => Ok(Os::SOLARIS),
        0x07 => Ok(Os::AIX),
        0x08 => Ok(Os::IRIX),
        0x09 => Ok(Os::FREEBSD),
        0x0A => Ok(Os::TRU64),
        0x0B => Ok(Os::MODESTO),
        0x0C => Ok(Os::OPENBSD),
        0x0D => Ok(Os::OPENVMS),
        0x0E => Ok(Os::NSK),
        0x0F => Ok(Os::AROS),
        0x10 => Ok(Os::FENIXOS),
        0x11 => Ok(Os::CLOUD),
        _ => Err(Error::UnsupportedOsError),
    }
}
