// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use self::checked_functions::function_is_checked_version;
use self::needed_libc::NeededLibC;
use crate::security::{
    options::{
        status::{ASLRCompatibilityLevel, HasSecurityStatus},
        AddressSpaceLayoutRandomizationOption, BinarySecurityOption, ELFFortifySourceOption,
        ELFImmediateBindingOption, ELFReadOnlyAfterRelocationsOption, ELFStackProtectionOption,
    },
    parser::BinaryParser,
    Result,
};
use std::collections::HashSet;

pub(crate) mod checked_functions;
pub(crate) mod needed_libc;

pub(crate) fn analyze_binary(
    parser: &BinaryParser,
    options: &crate::BinarySecurityCheckOptions,
) -> Result<Vec<Box<dyn HasSecurityStatus>>> {
    let supports_address_space_layout_randomization =
        AddressSpaceLayoutRandomizationOption.check(parser, options)?;
    let has_stack_protection = ELFStackProtectionOption.check(parser, options)?;
    let read_only_after_reloc = ELFReadOnlyAfterRelocationsOption.check(parser, options)?;
    let immediate_bind = ELFImmediateBindingOption.check(parser, options)?;

    let mut result = vec![
        supports_address_space_layout_randomization,
        has_stack_protection,
        read_only_after_reloc,
        immediate_bind,
    ];

    if !options.no_libc {
        if let Ok(fortify_source) =
            ELFFortifySourceOption::new(options.libc_spec).check(parser, options)
        {
            result.push(fortify_source);
        }
    }

    Ok(result)
}

pub(crate) fn get_libc_functions_by_protection<'t>(
    elf: &goblin::elf::Elf,
    libc_ref: &'t NeededLibC,
) -> (HashSet<&'t str>, HashSet<&'t str>) {
    let imported_functions = elf
        .dynsyms
        .iter()
        .filter_map(|symbol| dynamic_symbol_is_named_imported_function(elf, &symbol));

    let mut protected_functions = HashSet::<&str>::default();
    let mut unprotected_functions = HashSet::<&str>::default();
    for imported_function in imported_functions {
        if function_is_checked_version(imported_function) {
            if let Some(unchecked_function) = libc_ref.exports_function(imported_function) {
                protected_functions.insert(unchecked_function);
            } else {
                // warn!(
                //     "Checked function '{}' is not exported by the C runtime library. This might indicate a C runtime mismatch.",
                //     imported_function
                // );
            }
        } else if let Some(unchecked_function) =
            libc_ref.exports_checked_version_of_function(imported_function)
        {
            unprotected_functions.insert(unchecked_function);
        }
    }

    (protected_functions, unprotected_functions)
}

/// [`ET_EXEC`, `ET_DYN`, `PT_PHDR`](http://refspecs.linux-foundation.org/elf/TIS1.1.pdf).
pub(crate) fn supports_aslr(elf: &goblin::elf::Elf) -> ASLRCompatibilityLevel {
    // debug!(
    //     "Header type is 'ET_{}'.",
    //     goblin::elf::header::et_to_str(elf.header.e_type)
    // );

    match elf.header.e_type {
        goblin::elf::header::ET_EXEC => {
            // Position-dependent executable.
            ASLRCompatibilityLevel::Unsupported
        }

        goblin::elf::header::ET_DYN => {
            // if log_enabled!(log::Level::Debug) {
            //     if elf
            //         .program_headers
            //         .iter()
            //         .any(|ph| ph.p_type == goblin::elf::program_header::PT_PHDR)
            //     {
            //         // Position-independent executable.
            //         debug!("Found type 'PT_PHDR' inside program headers section.");
            //     } else if let Some(dynamic_section) = elf.dynamic.as_ref() {
            //         let dynamic_section_flags_include_pie = dynamic_section.dyns.iter().any(|e| {
            //             (e.d_tag == goblin::elf::dynamic::DT_FLAGS_1) && ((e.d_val & DF_1_PIE) != 0)
            //         });
            //
            //         if dynamic_section_flags_include_pie {
            //             // Position-independent executable.
            //             debug!("Bit 'DF_1_PIE' is set in tag 'DT_FLAGS_1' inside dynamic linking information.");
            //         } else {
            //             // Shared library.
            //             debug!("Binary is a shared library with dynamic linking information.");
            //         }
            //     } else {
            //         // Shared library.
            //         debug!("Binary is a shared library without dynamic linking information.");
            //     }
            // }

            ASLRCompatibilityLevel::Supported
        }

        _ => {
            // debug!("Position-independence could not be determined.");
            ASLRCompatibilityLevel::Unknown
        }
    }
}

/// [PT_GNU_RELRO](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/progheader.html).
pub(crate) fn becomes_read_only_after_relocations(elf: &goblin::elf::Elf) -> bool {
    let r = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO);

    if r {
        // debug!("Found type 'PT_GNU_RELRO' inside program headers section.");
    }
    r
}

/// [`__stack_chk_fail`](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---stack-chk-fail-1.html).
pub(crate) fn has_stack_protection(elf: &goblin::elf::Elf) -> bool {
    let r = elf
        .dynsyms
        .iter()
        // Consider only named functions, and focus on their names.
        .filter_map(|symbol| dynamic_symbol_is_named_function(elf, &symbol))
        // Check if any function name corresponds to '__stack_chk_fail'.
        .any(|name| name == "__stack_chk_fail");

    if r {
        // debug!("Found function symbol '__stack_chk_fail' inside dynamic symbols section.");
    }
    r
}

/// Visibility is specified by binding type.
const STV_DEFAULT: u8 = 0;
/// Defined by processor supplements.
//const STV_INTERNAL: u8 = 1;
/// Not visible to other components.
//const STV_HIDDEN: u8 = 2;
/// Visible in other components but not preemptable.
//const STV_PROTECTED: u8 = 3;

pub(crate) fn dynamic_symbol_is_named_exported_function<'elf>(
    elf: &'elf goblin::elf::Elf,
    symbol: &goblin::elf::sym::Sym,
) -> Option<&'elf str> {
    // Visibility must be STV_DEFAULT.
    if symbol.st_other == STV_DEFAULT {
        // Type must be STT_FUNC or STT_GNU_IFUNC.
        let st_type = symbol.st_type();
        if st_type == goblin::elf::sym::STT_FUNC || st_type == goblin::elf::sym::STT_GNU_IFUNC {
            // Binding must be STB_GLOBAL or BSF_WEAK or STB_GNU_UNIQUE.
            // Value must not be zero.
            let st_bind = symbol.st_bind();
            if (st_bind == goblin::elf::sym::STB_GLOBAL
                || st_bind == goblin::elf::sym::STB_WEAK
                || st_bind == goblin::elf::sym::STB_GNU_UNIQUE)
                && (symbol.st_value != 0)
            {
                return elf
                    .dynstrtab
                    .get_at(symbol.st_name)
                    .filter(|name| !name.is_empty()); // Only consider non-empty names.
            }
        }
    }
    None
}

/// Position Independent Executable.
pub(crate) const _DF_1_PIE: u64 = 0x08_00_00_00;

pub(crate) fn _symbol_is_named_function_or_unspecified<'elf>(
    elf: &'elf goblin::elf::Elf,
    symbol: &goblin::elf::sym::Sym,
) -> Option<&'elf str> {
    // Type must be STT_FUNC or STT_GNU_IFUNC or STT_NOTYPE.
    let st_type = symbol.st_type();
    if st_type == goblin::elf::sym::STT_FUNC
        || st_type == goblin::elf::sym::STT_GNU_IFUNC
        || st_type == goblin::elf::sym::STT_NOTYPE
    {
        elf.strtab
            .get_at(symbol.st_name)
            .filter(|name| !name.is_empty()) // Only consider non-empty names.
    } else {
        None
    }
}

fn dynamic_symbol_is_named_function<'elf>(
    elf: &'elf goblin::elf::Elf,
    symbol: &goblin::elf::sym::Sym,
) -> Option<&'elf str> {
    // Type must be STT_FUNC or STT_GNU_IFUNC.
    let st_type = symbol.st_type();
    if st_type == goblin::elf::sym::STT_FUNC || st_type == goblin::elf::sym::STT_GNU_IFUNC {
        elf.dynstrtab
            .get_at(symbol.st_name)
            .filter(|name| !name.is_empty()) // Only consider non-empty names.
    } else {
        None
    }
}

fn dynamic_symbol_is_named_imported_function<'elf>(
    elf: &'elf goblin::elf::Elf,
    symbol: &goblin::elf::sym::Sym,
) -> Option<&'elf str> {
    // Type must be STT_FUNC or STT_GNU_IFUNC.
    let st_type = symbol.st_type();
    if st_type == goblin::elf::sym::STT_FUNC || st_type == goblin::elf::sym::STT_GNU_IFUNC {
        // Binding must be STB_GLOBAL or BSF_WEAK or STB_GNU_UNIQUE.
        // Value must be zero.
        let st_bind = symbol.st_bind();
        if (st_bind == goblin::elf::sym::STB_GLOBAL
            || st_bind == goblin::elf::sym::STB_WEAK
            || st_bind == goblin::elf::sym::STB_GNU_UNIQUE)
            && (symbol.st_value == 0)
        {
            return elf
                .dynstrtab
                .get_at(symbol.st_name)
                .filter(|name| !name.is_empty()); // Only consider non-empty names.
        }
    }
    None
}

/// - [`DT_BIND_NOW`](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dynamicsection.html).
/// - [`DF_BIND_NOW`, `DF_1_NOW`](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/libc-ddefs.html).
pub(crate) fn requires_immediate_binding(elf: &goblin::elf::Elf) -> bool {
    elf.dynamic
        // We want to reference the data in `elf.dynamic`, not move it.
        .as_ref()
        .and_then(|dli| {
            // We have dynamic linking information.
            // Find the first entry that requires immediate binding.
            dli.dyns
                .iter()
                .find(|dyn_entry| dynamic_linking_info_entry_requires_immediate_binding(dyn_entry))
        })
        .is_some()
}

fn dynamic_linking_info_entry_requires_immediate_binding(
    dyn_entry: &goblin::elf::dynamic::Dyn,
) -> bool {
    match dyn_entry.d_tag {
        goblin::elf::dynamic::DT_BIND_NOW => {
            // debug!("Found tag 'DT_BIND_NOW' inside dynamic linking information.");
            true
        }

        goblin::elf::dynamic::DT_FLAGS => {
            let r = (dyn_entry.d_val & goblin::elf::dynamic::DF_BIND_NOW) != 0;
            if r {
                // debug!("Bit 'DF_BIND_NOW' is set in tag 'DT_FLAGS' inside dynamic linking information.");
            }
            r
        }

        goblin::elf::dynamic::DT_FLAGS_1 => {
            let r = (dyn_entry.d_val & goblin::elf::dynamic::DF_1_NOW) != 0;
            if r {
                // debug!(
                //     "Bit 'DF_1_NOW' is set in tag 'DT_FLAGS_1' inside dynamic linking information."
                // );
            }
            r
        }

        _ => false,
    }
}
