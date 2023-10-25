use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum FileFormat {
    PE,
    ELF,
    DOTNET,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileFormat::PE => write!(f, "PE file"),
            FileFormat::ELF => write!(f, "Elf file"),
            FileFormat::DOTNET => write!(f, "DotNet file"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum Os {
    WINDOWS,
    HPUX,
    NETBSD,
    LINUX,
    HURD,
    _86OPEN,
    SOLARIS,
    AIX,
    IRIX,
    FREEBSD,
    TRU64,
    MODESTO,
    OPENBSD,
    OPENVMS,
    NSK,
    AROS,
    FENIXOS,
    CLOUD,
    UNDEFINED,
}

impl Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Os::WINDOWS => write!(f, "Windows"),
            Os::HPUX => write!(f, "HP Unix"),
            Os::NETBSD => write!(f, "NetBSD"),
            Os::LINUX => write!(f, "Linux"),
            Os::HURD => write!(f, "Hurd"),
            Os::_86OPEN => write!(f, "86Open"),
            Os::SOLARIS => write!(f, "Solaris"),
            Os::AIX => write!(f, "Aix"),
            Os::IRIX => write!(f, "Irix"),
            Os::FREEBSD => write!(f, "FreeBSD"),
            Os::TRU64 => write!(f, "Tru64"),
            Os::MODESTO => write!(f, "Modesto"),
            Os::OPENBSD => write!(f, "OpenBSD"),
            Os::OPENVMS => write!(f, "OpenVMS"),
            Os::NSK => write!(f, "NSK"),
            Os::AROS => write!(f, "Aros"),
            Os::FENIXOS => write!(f, "FenixOS"),
            Os::CLOUD => write!(f, "Cloud"),
            Os::UNDEFINED => write!(f, "undefined"),
        }
    }
}

#[derive(Debug)]
pub enum Endian {
    _Big,
    _Little,
}
