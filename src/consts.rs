use serde::{Deserialize, Serialize};
use std::fmt::Display;

// 0.4.0: `#[non_exhaustive]` so future additions (e.g. `Shellcode`,
// `WASM`) don't break downstream `match` statements. Added `Macho`
// variant for the Mach-O loader that landed in smda 0.5.0 — capa
// rules that match on `format: macho` now fire on real samples.
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
pub enum FileFormat {
    PE,
    ELF,
    DOTNET,
    Macho,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FileFormat::PE => write!(f, "PE file"),
            FileFormat::ELF => write!(f, "Elf file"),
            FileFormat::DOTNET => write!(f, "DotNet file"),
            FileFormat::Macho => write!(f, "Mach-O file"),
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
    ANDROID,
    // 0.5.0 (audit HIGH): Mach-O is a fully analysable input format
    // since 0.4.0, but `extract_os` was hard-coded to return
    // `Os::LINUX` for Mach-O because this enum had no Darwin
    // variant. Result: capa rules `os: macos` / `os: ios` never
    // fired on Mach-O input, and `os: linux` rules fired
    // incorrectly. Adding both variants here + plumbing them from
    // the Mach-O cputype in `extract_os` fixes both directions.
    MACOS,
    IOS,
    #[allow(non_camel_case_types)]
    ARCH_SPECIFIC,
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
            Os::ANDROID => write!(f, "Android"),
            Os::MACOS => write!(f, "macOS"),
            Os::IOS => write!(f, "iOS"),
            Os::ARCH_SPECIFIC => write!(f, "Architecture-specific"),
        }
    }
}
#[allow(dead_code)]
#[derive(Debug)]
pub enum Endian {
    _Big,
    _Little,
}
