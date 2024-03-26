use core::fmt;
use std::path::PathBuf;

use crate::security::elf;

pub(crate) struct Options {
    /// Verbose logging.
    pub(crate) verbose: bool,

    /// Path of the C runtime library file.
    pub(crate) libc: Option<PathBuf>,

    /// Path of the system root for finding the corresponding C runtime library.
    pub(crate) sysroot: Option<PathBuf>,

    /// Use an internal list of checked functions as specified by a specification.
    pub(crate) libc_spec: Option<LibCSpec>,

    /// Assume that input files do not use any C runtime libraries.
    pub(crate) no_libc: bool,

    /// Binary files to analyze.
    pub(crate) input_files: Vec<PathBuf>,
}

// If this changes, then update the command line reference.
#[derive(Debug, Copy, Clone)]
pub(crate) enum LibCSpec {
    LSB1,
    LSB1dot1,
    LSB1dot2,
    LSB1dot3,
    LSB2,
    LSB2dot0dot1,
    LSB2dot1,
    LSB3,
    LSB3dot1,
    LSB3dot2,
    LSB4,
    LSB4dot1,
    LSB5,
}

impl fmt::Display for LibCSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let spec_name = match *self {
            LibCSpec::LSB1
            | LibCSpec::LSB1dot1
            | LibCSpec::LSB1dot2
            | LibCSpec::LSB1dot3
            | LibCSpec::LSB2
            | LibCSpec::LSB2dot0dot1
            | LibCSpec::LSB2dot1
            | LibCSpec::LSB3
            | LibCSpec::LSB3dot1
            | LibCSpec::LSB3dot2
            | LibCSpec::LSB4
            | LibCSpec::LSB4dot1
            | LibCSpec::LSB5 => "Linux Standard Base",
        };

        let spec_version = match *self {
            LibCSpec::LSB1 => "1.0.0",
            LibCSpec::LSB1dot1 => "1.1.0",
            LibCSpec::LSB1dot2 => "1.2.0",
            LibCSpec::LSB1dot3 => "1.3.0",
            LibCSpec::LSB2 => "2.0.0",
            LibCSpec::LSB2dot0dot1 => "2.0.1",
            LibCSpec::LSB2dot1 => "2.1.0",
            LibCSpec::LSB3 => "3.0.0",
            LibCSpec::LSB3dot1 => "3.1.0",
            LibCSpec::LSB3dot2 => "3.2.0",
            LibCSpec::LSB4 => "4.0.0",
            LibCSpec::LSB4dot1 => "4.1.0",
            LibCSpec::LSB5 => "5.0.0",
        };

        write!(f, "{spec_name} {spec_version}")
    }
}

impl LibCSpec {
    pub(crate) fn get_functions_with_checked_versions(self) -> &'static [&'static str] {
        match self {
            LibCSpec::LSB1
            | LibCSpec::LSB1dot1
            | LibCSpec::LSB1dot2
            | LibCSpec::LSB1dot3
            | LibCSpec::LSB2
            | LibCSpec::LSB2dot0dot1
            | LibCSpec::LSB2dot1
            | LibCSpec::LSB3
            | LibCSpec::LSB3dot1
            | LibCSpec::LSB3dot2 => &[],

            LibCSpec::LSB4 | LibCSpec::LSB4dot1 | LibCSpec::LSB5 => {
                elf::checked_functions::LSB_4_0_0_FUNCTIONS_WITH_CHECKED_VERSIONS
            }
        }
    }
}
