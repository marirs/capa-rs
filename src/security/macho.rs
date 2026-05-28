//! Mach-O security-checklist analyser (capa-rs 0.5.0).
//!
//! Mirrors the structure of [`super::pe`] and [`super::elf`]:
//! reads goblin's parsed view of the binary, returns a `Vec<Box<dyn
//! HasSecurityStatus>>` containing one entry per Darwin security
//! posture bit. Pre-0.5.0 the Mach-O arm of
//! [`super::get_security_checks`] returned `Ok(Vec::new())` as a
//! placeholder and shipped an empty security table for every
//! Apple-Silicon / Intel Mach-O input — including system utilities
//! like `/bin/ls`, which clearly have stack canaries, PIE,
//! code-signing, etc.
//!
//! What's covered:
//!   * **PIE** — `MH_PIE` flag (`0x200000`), macOS equivalent of
//!     Windows ASLR.
//!   * **DATA-EXEC-PREVENT** — composite: `MH_NO_HEAP_EXECUTION`
//!     flag (`0x01000000`) OR no `__DATA*` segment with
//!     `VM_PROT_EXECUTE` (0x4) in `initprot`.
//!   * **STACK-CANARY** — presence of `___stack_chk_guard` or
//!     `___stack_chk_fail` in the symbol table.
//!   * **RESTRICT** — presence of a `__RESTRICT` segment
//!     (anti-`DYLD_INSERT_LIBRARIES` marker).
//!   * **CODE-SIGNATURE** — `LC_CODE_SIGNATURE` load command with
//!     non-zero `datasize`.
//!   * **TWO-LEVEL-NAMESPACE** — `MH_TWOLEVEL` flag (`0x80`).
//!   * **NO-UNDEF-SYMS** — `MH_NOUNDEFS` flag (`0x01`).
//!
//! Deferred (emit `Unknown`):
//!   * **HARDENED-RUNTIME** — needs `CS_RUNTIME` (`0x10000`) bit in
//!     the `CS_CodeDirectory` blob inside `__LINKEDIT`. Big-endian
//!     `CS_SuperBlob` walk (~80 LOC) tracked for a follow-up.
//!   * **ALLOW-JIT** — needs PLIST entitlements parsing from
//!     `CS_EmbeddedEntitlements` — separate parser, deferred.
//!
//! Fat (universal) binaries: we report checks for the first
//! parseable slice; capa-rs's `format`/`arch` reporting already
//! picks a single slice and the security table mirrors that.

use crate::{
    Result,
    security::{
        options::status::{HasSecurityStatus, YesNoUnknownStatus},
        parser::BinaryParser,
    },
};
use goblin::mach::{Mach, MachO};

// Mach-O header flag bits — <mach-o/loader.h>.
const MH_NOUNDEFS: u32 = 0x0000_0001;
const MH_TWOLEVEL: u32 = 0x0000_0080;
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;
// Segment protection bit — <mach/vm_prot.h>.
const VM_PROT_EXECUTE: u32 = 0x04;

pub(crate) fn analyze_binary(
    parser: &BinaryParser,
    _options: &crate::BinarySecurityCheckOptions,
) -> Result<Vec<Box<dyn HasSecurityStatus>>> {
    let mach_obj = match parser.object() {
        goblin::Object::Mach(m) => m,
        _ => {
            // BinaryParser routed Mach-O to us; if goblin re-classified
            // it now, emit a single Unknown rather than panicking.
            return Ok(vec![
                Box::new(YesNoUnknownStatus::unknown("MACHO-PARSE")) as Box<dyn HasSecurityStatus>
            ]);
        }
    };

    match mach_obj {
        // Thin Mach-O: pattern-match auto-refs `m` as `&MachO<'_>`.
        Mach::Binary(m) => run_checks(m),
        // Fat: try slices in iteration order; first parseable wins.
        // Same slice-selection convention as smda's
        // MachoArchPreference::HostNative would yield on this host —
        // good enough for the security report's purpose.
        Mach::Fat(fat) => {
            for (i, _arch) in fat.iter_arches().enumerate() {
                if let Ok(goblin::mach::SingleArch::MachO(m)) = fat.get(i) {
                    return run_checks(&m);
                }
            }
            Ok(vec![
                Box::new(YesNoUnknownStatus::unknown("MACHO-PARSE")) as Box<dyn HasSecurityStatus>
            ])
        }
    }
}

fn run_checks(slice: &MachO) -> Result<Vec<Box<dyn HasSecurityStatus>>> {
    let flags = slice.header.flags;

    // ---- PIE ----------------------------------------------------------
    let pie = YesNoUnknownStatus::new("PIE", flags & MH_PIE != 0);

    // ---- DATA-EXEC-PREVENT --------------------------------------------
    // Composite: header flag OR no __DATA* segment with executable
    // protection. Most modern Mach-Os pass the no-executable-data
    // check even without the explicit flag, so the OR matches
    // observed behaviour rather than purely header semantics.
    let nx_flag = flags & MH_NO_HEAP_EXECUTION != 0;
    let any_data_exec = slice.segments.iter().any(|seg| {
        let name = std::str::from_utf8(&seg.segname)
            .unwrap_or("")
            .trim_end_matches('\0');
        // Matches __DATA, __DATA_CONST, __DATA_DIRTY, …
        name.starts_with("__DATA") && (seg.initprot & VM_PROT_EXECUTE) != 0
    });
    let dep = YesNoUnknownStatus::new("DATA-EXEC-PREVENT", nx_flag || !any_data_exec);

    // ---- STACK-CANARY -------------------------------------------------
    // Walk the symbol table for Apple's stack-protector symbols.
    // Either presence → Pass. goblin's `MachO::symbols()` returns the
    // iterator directly (NOT a Result — each iterator item is the
    // Result, so a malformed nlist mid-stream just skips that entry
    // rather than aborting the walk). Stripped binaries that emit
    // no symbol table at all simply iterate zero entries → Fail,
    // which is the right signal (no canary symbols visible).
    let canary = {
        let mut found = false;
        for sym in slice.symbols().flatten() {
            let (name, _nlist) = sym;
            if name == "___stack_chk_guard" || name == "___stack_chk_fail" {
                found = true;
                break;
            }
        }
        YesNoUnknownStatus::new("STACK-CANARY", found)
    };

    // ---- RESTRICT -----------------------------------------------------
    // Apple's anti-DYLD_INSERT_LIBRARIES marker. A __RESTRICT
    // segment prevents dyld from honouring DYLD_INSERT_LIBRARIES /
    // DYLD_LIBRARY_PATH overrides on this binary. Common on
    // first-party system binaries (/bin/ls, /usr/bin/file) before
    // System Integrity Protection subsumed the use case.
    let has_restrict = slice.segments.iter().any(|seg| {
        let name = std::str::from_utf8(&seg.segname)
            .unwrap_or("")
            .trim_end_matches('\0');
        name == "__RESTRICT"
    });
    let restrict = YesNoUnknownStatus::new("RESTRICT", has_restrict);

    // ---- CODE-SIGNATURE -----------------------------------------------
    // LC_CODE_SIGNATURE with non-zero datasize. We don't verify the
    // signature itself — that requires the keychain / trust store
    // — but presence is the binary signal that matters
    // (unsigned binaries are increasingly rejected by Gatekeeper /
    // Notarization on modern macOS).
    let signed = slice.load_commands.iter().any(|lc| {
        matches!(
            &lc.command,
            goblin::mach::load_command::CommandVariant::CodeSignature(cs)
                if cs.datasize > 0
        )
    });
    let code_sig = YesNoUnknownStatus::new("CODE-SIGNATURE", signed);

    // ---- TWO-LEVEL-NAMESPACE -----------------------------------------
    let two_level = YesNoUnknownStatus::new("TWO-LEVEL-NAMESPACE", flags & MH_TWOLEVEL != 0);

    // ---- NO-UNDEF-SYMS -----------------------------------------------
    let no_undef = YesNoUnknownStatus::new("NO-UNDEF-SYMS", flags & MH_NOUNDEFS != 0);

    // ---- HARDENED-RUNTIME (deferred; emit Unknown) -------------------
    // Requires walking CS_SuperBlob → CS_CodeDirectory at the
    // LC_CODE_SIGNATURE.dataoff and checking
    // codedir.flags & CS_RUNTIME (0x10000). Big-endian blob format
    // embedded in __LINKEDIT — straightforward but ~80 LOC of raw
    // parsing. Tracked for a follow-up.
    let hardened = YesNoUnknownStatus::unknown("HARDENED-RUNTIME");

    // ---- ALLOW-JIT (deferred; emit Unknown) --------------------------
    // Requires CS_EmbeddedEntitlements blob parsing
    // (XML/PLIST inside the same CS_SuperBlob) — separate parser.
    let allow_jit = YesNoUnknownStatus::unknown("ALLOW-JIT");

    Ok(vec![
        Box::new(pie) as Box<dyn HasSecurityStatus>,
        Box::new(dep) as Box<dyn HasSecurityStatus>,
        Box::new(canary) as Box<dyn HasSecurityStatus>,
        Box::new(restrict) as Box<dyn HasSecurityStatus>,
        Box::new(code_sig) as Box<dyn HasSecurityStatus>,
        Box::new(two_level) as Box<dyn HasSecurityStatus>,
        Box::new(no_undef) as Box<dyn HasSecurityStatus>,
        Box::new(hardened) as Box<dyn HasSecurityStatus>,
        Box::new(allow_jit) as Box<dyn HasSecurityStatus>,
    ])
}
