use crate::{
    security::elf::{self, needed_libc::NeededLibC},
    Result,
};
use core::{marker::PhantomPinned, pin::Pin, ptr::NonNull};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub(crate) trait HasSecurityStatus {
    fn get_security_check_status(&self) -> Result<SecurityCheckStatus>;
}

pub(crate) struct YesNoUnknownStatus {
    name: &'static str,
    status: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct SecurityCheckStatus {
    pub(crate) name: String,
    pub(crate) status: String,
}

impl YesNoUnknownStatus {
    pub(crate) fn new(name: &'static str, yes_or_no: bool) -> Self {
        Self {
            name,
            status: Some(yes_or_no),
        }
    }

    pub(crate) fn unknown(name: &'static str) -> Self {
        Self { name, status: None }
    }
}

impl HasSecurityStatus for YesNoUnknownStatus {
    fn get_security_check_status(&self) -> Result<SecurityCheckStatus> {
        let (name, status) = match self.status {
            Some(true) => (self.name, "Pass"),
            Some(false) => (self.name, "Fail"),
            None => (self.name, "Unknown"),
        };

        Ok(SecurityCheckStatus {
            name: name.to_string(),
            status: status.to_string(),
        })
    }
}

/// [Control Flow Guard](https://docs.microsoft.com/en-us/cpp/build/reference/guard-enable-guard-checks).
pub(crate) enum PEControlFlowGuardLevel {
    /// Control Flow Guard support is unknown.
    Unknown,
    /// Control Flow Guard is unsupported.
    Unsupported,
    /// Control Flow Guard is supported, but cannot take effect.
    /// This is usually because the executable cannot be relocated at runtime.
    Ineffective,
    /// Control Flow Guard is supported.
    Supported,
}

impl HasSecurityStatus for PEControlFlowGuardLevel {
    fn get_security_check_status(&self) -> Result<SecurityCheckStatus> {
        let status = match *self {
            PEControlFlowGuardLevel::Unknown => "Unknown",
            PEControlFlowGuardLevel::Unsupported => "Unsupported",
            PEControlFlowGuardLevel::Ineffective => "Ineffective",
            PEControlFlowGuardLevel::Supported => "Supported",
        };

        Ok(SecurityCheckStatus {
            name: "CONTROL-FLOW-GUARD".to_string(),
            status: status.to_string(),
        })
    }
}

pub(crate) enum ASLRCompatibilityLevel {
    /// Address Space Layout Randomization support is unknown.
    Unknown,
    /// Address Space Layout Randomization is unsupported.
    Unsupported,
    /// Address Space Layout Randomization is supported, but might be expensive.
    /// This usually happens when an executable has a preferred base address explicitly specified.
    Expensive,
    /// Address Space Layout Randomization is supported, but with a low entropy, and only in
    /// addresses below 2 Gigabytes.
    SupportedLowEntropyBelow2G,
    /// Address Space Layout Randomization is supported, but with a low entropy.
    SupportedLowEntropy,
    /// Address Space Layout Randomization is supported with high entropy, but only in addresses
    /// below 2 Gigabytes.
    SupportedBelow2G,
    /// Address Space Layout Randomization is supported (with high entropy for PE32/PE32+).
    Supported,
}

impl HasSecurityStatus for ASLRCompatibilityLevel {
    fn get_security_check_status(&self) -> Result<SecurityCheckStatus> {
        let status = match *self {
            ASLRCompatibilityLevel::Unknown => "Unknown",
            ASLRCompatibilityLevel::Unsupported => "Unsupported",
            ASLRCompatibilityLevel::Expensive => "Expensive",
            ASLRCompatibilityLevel::SupportedLowEntropyBelow2G => "Low entropy below 2GB",
            ASLRCompatibilityLevel::SupportedLowEntropy => "Low entropy",
            ASLRCompatibilityLevel::SupportedBelow2G => "Below 2GB",
            ASLRCompatibilityLevel::Supported => "Supported",
        };

        Ok(SecurityCheckStatus {
            name: "ASLR".to_string(),
            status: status.to_string(),
        })
    }
}

pub(crate) struct ELFFortifySourceStatus {
    libc: NeededLibC,
    protected_functions: HashSet<&'static str>,
    unprotected_functions: HashSet<&'static str>,
    _pin: PhantomPinned,
}

impl ELFFortifySourceStatus {
    pub(crate) fn new(libc: NeededLibC, elf_object: &goblin::elf::Elf) -> Result<Pin<Box<Self>>> {
        let mut result = Box::pin(Self {
            libc,
            protected_functions: HashSet::default(),
            unprotected_functions: HashSet::default(),
            _pin: PhantomPinned,
        });

        // SAFETY:
        // `result` is now allocated, initialized and pinned on the heap.
        // Its location is therefore stable, and we can store references to it
        // in other places.
        //
        // Construct a reference to `result.libc` that lives for the 'static
        // life time:
        //     &ref => pointer => 'static ref
        //
        // This is safe because the `Drop` implementation drops the fields
        // `Self::protected_functions` and `Self::unprotected_functions`
        // before the field `Self::libc`.
        let libc_ref: &'static NeededLibC =
            unsafe { NonNull::from(&result.libc).as_ptr().as_ref().unwrap() };

        let (prot_fn, unprot_fn) = elf::get_libc_functions_by_protection(elf_object, libc_ref);

        // SAFETY: Storing to the field `protected_functions` does not move `result`.
        unsafe { Pin::get_unchecked_mut(result.as_mut()) }.protected_functions = prot_fn;

        // SAFETY: Storing to the field `unprotected_functions` does not move `result`.
        unsafe { Pin::get_unchecked_mut(result.as_mut()) }.unprotected_functions = unprot_fn;

        Ok(result)
    }

    fn drop_pinned(mut self: Pin<&mut Self>) {
        // SAFETY: Drop fields `protected_functions` and `unprotected_functions`
        // before field `libc` is dropped.
        let this = Pin::as_mut(&mut self);

        // SAFETY: Calling `HashSet::clear()` does not move `this`.
        let this = unsafe { Pin::get_unchecked_mut(this) };

        this.protected_functions.clear();
        this.unprotected_functions.clear();
    }
}

impl Drop for ELFFortifySourceStatus {
    fn drop(&mut self) {
        // SAFETY: All instances of `Self` are pinned.
        unsafe { Pin::new_unchecked(self) }.drop_pinned();
    }
}

impl HasSecurityStatus for Pin<Box<ELFFortifySourceStatus>> {
    fn get_security_check_status(&self) -> Result<SecurityCheckStatus> {
        let mut status = SecurityCheckStatus {
            name: "Fortify Source".to_string(),
            status: "".to_string(),
        };

        let mut separator = "";
        for &name in &self.protected_functions {
            status.status.push_str(separator);
            status.status.push_str(name);
            separator = ",";
        }

        for &name in &self.unprotected_functions {
            status.status.push_str(separator);
            status.status.push_str(name);
            separator = ",";
        }

        Ok(status)
    }
}
