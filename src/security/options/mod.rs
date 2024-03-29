use self::status::{
    ELFFortifySourceStatus, HasSecurityStatus, PEControlFlowGuardLevel, YesNoUnknownStatus,
};
use crate::{
    security::{
        pe,
        {
            elf::{
                self,
                needed_libc::{LibCResolver, NeededLibC},
            },
            parser::BinaryParser,
        },
    },
    BinarySecurityCheckOptions, LibCSpec, Result,
};

pub(crate) mod status;

pub(crate) trait BinarySecurityOption<'t> {
    fn check(
        &self,
        parser: &BinaryParser,
        options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>>;
}

struct PEDllCharacteristicsBitOption {
    name: &'static str,
    mask_name: &'static str,
    mask: u16,
    present: bool,
}

impl<'t> BinarySecurityOption<'t> for PEDllCharacteristicsBitOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        if let goblin::Object::PE(pe) = parser.object() {
            if let Some(bit_is_set) =
                pe::dll_characteristics_bit_is_set(pe, self.mask_name, self.mask)
            {
                return Ok(Box::new(YesNoUnknownStatus::new(
                    self.name,
                    bit_is_set == self.present,
                )));
            }
        }
        Ok(Box::new(YesNoUnknownStatus::unknown(self.name)))
    }
}

#[derive(Default)]
pub(crate) struct PEHasCheckSumOption;

impl<'t> BinarySecurityOption<'t> for PEHasCheckSumOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = if let goblin::Object::PE(pe) = parser.object() {
            pe::has_check_sum(pe)
        } else {
            None
        };

        Ok(Box::new(r.map_or_else(
            || YesNoUnknownStatus::unknown("CHECKSUM"),
            |r| YesNoUnknownStatus::new("CHECKSUM", r),
        )))
    }
}

#[derive(Default)]
pub(crate) struct DataExecutionPreventionOption;

impl<'t> BinarySecurityOption<'t> for DataExecutionPreventionOption {
    /// Returns information about support of Data Execution Prevention (DEP) in the executable.
    ///
    /// When DEP is supported, a virtual memory page can be marked as non-executable (NX), in which
    /// case trying to execute any code from that pages will raise an exception, and likely crash
    /// the application, instead of running arbitrary code.
    fn check(
        &self,
        parser: &BinaryParser,
        options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        if let goblin::Object::PE(_pe) = parser.object() {
            PEDllCharacteristicsBitOption {
                name: "DATA-EXEC-PREVENT",
                mask_name: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                mask: pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                present: true,
            }
            .check(parser, options)
        } else {
            Ok(Box::new(YesNoUnknownStatus::unknown("DATA-EXEC-PREVENT")))
        }
    }
}

#[derive(Default)]
pub(crate) struct PERunsOnlyInAppContainerOption;

impl<'t> BinarySecurityOption<'t> for PERunsOnlyInAppContainerOption {
    /// Returns information about the requirement to run this executable inside `AppContainer`.
    ///
    /// This option indicates whether the executable must be run in the `AppContainer`
    /// process-isolation environment, such as a Universal Windows Platform (UWP) or Windows
    /// Phone 8.x app.
    fn check(
        &self,
        parser: &BinaryParser,
        options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        PEDllCharacteristicsBitOption {
            name: "RUNS-IN-APP-CONTAINER",
            mask_name: "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
            mask: pe::IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
            present: true,
        }
        .check(parser, options)
    }
}

#[derive(Default)]
pub(crate) struct RequiresIntegrityCheckOption;

impl<'t> BinarySecurityOption<'t> for RequiresIntegrityCheckOption {
    /// Returns whether the operating system must to verify the digital signature of this executable
    /// at load time.
    fn check(
        &self,
        parser: &BinaryParser,
        options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        if let goblin::Object::PE(_pe) = parser.object() {
            PEDllCharacteristicsBitOption {
                name: "VERIFY-DIGITAL-CERT",
                mask_name: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
                mask: pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
                present: true,
            }
            .check(parser, options)
        } else {
            Ok(Box::new(YesNoUnknownStatus::unknown("VERIFY-DIGITAL-CERT")))
        }
    }
}

#[derive(Default)]
pub(crate) struct PEEnableManifestHandlingOption;

impl<'t> BinarySecurityOption<'t> for PEEnableManifestHandlingOption {
    /// Returns whether the operating system is allowed to consider manifest files when loading
    /// this executable.
    ///
    /// Enabling this causes the operating system to do manifest lookup and loads.
    /// When isolation is disabled for an executable, the Windows loader will not attempt to find an
    /// application manifest for the newly created process. The new process will not have a default
    /// activation context, even if there is a manifest inside the executable or placed in the same
    /// directory as the executable with name `executable-name.exe.manifest`.
    fn check(
        &self,
        parser: &BinaryParser,
        options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        PEDllCharacteristicsBitOption {
            name: "CONSIDER-MANIFEST",
            mask_name: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            mask: pe::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
            present: false,
        }
        .check(parser, options)
    }
}

#[derive(Default)]
pub(crate) struct PEControlFlowGuardOption;

impl<'t> BinarySecurityOption<'t> for PEControlFlowGuardOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = if let goblin::Object::PE(pe) = parser.object() {
            pe::supports_control_flow_guard(pe)
        } else {
            PEControlFlowGuardLevel::Unknown
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub(crate) struct PEHandlesAddressesLargerThan2GBOption;

impl<'t> BinarySecurityOption<'t> for PEHandlesAddressesLargerThan2GBOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = if let goblin::Object::PE(pe) = parser.object() {
            YesNoUnknownStatus::new(
                "HANDLES-ADDR-GT-2GB",
                pe::handles_addresses_larger_than_2_gigabytes(pe),
            )
        } else {
            YesNoUnknownStatus::unknown("HANDLES-ADDR-GT-2GB")
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub(crate) struct AddressSpaceLayoutRandomizationOption;

impl<'t> BinarySecurityOption<'t> for AddressSpaceLayoutRandomizationOption {
    /// Returns the level of support of Address Space Layout Randomization (ASLR).
    ///
    /// When ASLR is supported, the executable should be randomly re-based at load time, enabling
    /// virtual address allocation randomization, which affects the virtual memory location of heaps,
    /// stacks, and other operating system allocations.
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        match parser.object() {
            goblin::Object::PE(pe) => Ok(Box::new(pe::supports_aslr(pe))),
            goblin::Object::Elf(elf_obj) => Ok(Box::new(elf::supports_aslr(elf_obj))),
            _ => Ok(Box::new(YesNoUnknownStatus::unknown("ASLR"))),
        }
    }
}

#[derive(Default)]
pub(crate) struct PESafeStructuredExceptionHandlingOption;

impl<'t> BinarySecurityOption<'t> for PESafeStructuredExceptionHandlingOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = if let goblin::Object::PE(pe) = parser.object() {
            YesNoUnknownStatus::new(
                "SAFE-SEH",
                pe::has_safe_structured_exception_handlers(parser, pe),
            )
        } else {
            YesNoUnknownStatus::unknown("SAFE-SEH")
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub(crate) struct ELFReadOnlyAfterRelocationsOption;

impl<'t> BinarySecurityOption<'t> for ELFReadOnlyAfterRelocationsOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = if let goblin::Object::Elf(elf) = parser.object() {
            YesNoUnknownStatus::new(
                "READ-ONLY-RELOC",
                elf::becomes_read_only_after_relocations(elf),
            )
        } else {
            YesNoUnknownStatus::unknown("READ-ONLY-RELOC")
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub(crate) struct ELFStackProtectionOption;

impl<'t> BinarySecurityOption<'t> for ELFStackProtectionOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = match parser.object() {
            goblin::Object::Elf(elf_obj) => {
                YesNoUnknownStatus::new("STACK-PROT", elf::has_stack_protection(elf_obj))
            }

            _ => YesNoUnknownStatus::unknown("STACK-PROT"),
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub(crate) struct ELFImmediateBindingOption;

impl<'t> BinarySecurityOption<'t> for ELFImmediateBindingOption {
    fn check(
        &self,
        parser: &BinaryParser,
        _options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        let r = if let goblin::Object::Elf(elf) = parser.object() {
            YesNoUnknownStatus::new("IMMEDIATE-BIND", elf::requires_immediate_binding(elf))
        } else {
            YesNoUnknownStatus::unknown("IMMEDIATE-BIND")
        };
        Ok(Box::new(r))
    }
}

pub(crate) struct ELFFortifySourceOption {
    libc_spec: Option<LibCSpec>,
}

impl ELFFortifySourceOption {
    pub(crate) fn new(libc_spec: Option<LibCSpec>) -> Self {
        Self { libc_spec }
    }
}

impl<'t> BinarySecurityOption<'t> for ELFFortifySourceOption {
    fn check(
        &self,
        parser: &BinaryParser,
        options: &BinarySecurityCheckOptions,
    ) -> Result<Box<dyn HasSecurityStatus>> {
        if let goblin::Object::Elf(elf) = parser.object() {
            let libc = if let Some(spec) = self.libc_spec {
                NeededLibC::from_spec(spec)
            } else if let Some(path) = &options.libc {
                NeededLibC::open_elf_for_architecture(path, elf)?
            } else {
                LibCResolver::get(options)?.find_needed_by_executable(elf)?
            };

            let result = ELFFortifySourceStatus::new(libc, elf)?;
            Ok(Box::new(result))
        } else {
            Ok(Box::new(YesNoUnknownStatus::unknown("FORTIFY-SOURCE")))
        }
    }
}
