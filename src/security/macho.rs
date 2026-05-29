//! Mach-O security-checklist analyser (capa-rs 0.5.x).
//!
//! Mirrors the structure of [`super::pe`] and [`super::elf`]:
//! reads goblin's parsed view of the binary, returns a `Vec<Box<dyn
//! HasSecurityStatus>>` containing one entry per Darwin security
//! posture bit. 0.5.1 closes the two `Unknown` placeholders from
//! 0.5.0 (HARDENED-RUNTIME, ALLOW-JIT) with real
//! `CS_SuperBlob`-walking parsers.
//!
//! What's covered (all real, no `Unknown` returns):
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
//!   * **HARDENED-RUNTIME** (0.5.1) — walks the `CS_SuperBlob` at
//!     `LC_CODE_SIGNATURE.dataoff` (magic `0xfade0cc0`, big-endian),
//!     locates the `CS_CodeDirectory` blob (magic `0xfade0c02`),
//!     reads the `flags` field at offset 0x10, checks
//!     `flags & CS_RUNTIME (0x10000)`.
//!   * **ALLOW-JIT** (0.5.1) — same SuperBlob walk; finds the
//!     `CS_EmbeddedEntitlements` blob (magic `0xfade7171`), parses
//!     the PLIST payload via the `plist` crate, looks for
//!     `com.apple.security.cs.allow-jit = true`.
//!
//! Fat (universal) binaries: we walk slices in iteration order;
//! first parseable wins. Slice offset is tracked so the
//! code-signing dataoff (which is slice-relative inside fat
//! binaries) resolves to the correct absolute file position.

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

// Code-signing blob magics — Apple `<Security/CSCommon.h>`.
// All big-endian on disk.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
// CS_CodeDirectory flag — Apple `<kern/cs_blobs.h>`.
const CS_RUNTIME: u32 = 0x0001_0000;

pub(crate) fn analyze_binary(
    parser: &BinaryParser,
    _options: &crate::BinarySecurityCheckOptions,
) -> Result<Vec<Box<dyn HasSecurityStatus>>> {
    let bytes = parser.bytes();
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
        // Thin Mach-O — `dataoff` in LC_CODE_SIGNATURE is already
        // whole-file relative, so slice_offset = 0.
        Mach::Binary(m) => run_checks(m, bytes, 0),
        // Fat: walk slices in iteration order; first parseable
        // MachO (not Archive) wins. We grab the per-arch `offset`
        // so the code-signing blob (slice-relative `dataoff`) maps
        // to the correct absolute file position.
        Mach::Fat(fat) => {
            for (i, arch_res) in fat.iter_arches().enumerate() {
                let arch = match arch_res {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                if let Ok(goblin::mach::SingleArch::MachO(m)) = fat.get(i) {
                    return run_checks(&m, bytes, arch.offset as usize);
                }
            }
            Ok(vec![
                Box::new(YesNoUnknownStatus::unknown("MACHO-PARSE")) as Box<dyn HasSecurityStatus>
            ])
        }
    }
}

fn run_checks(
    slice: &MachO,
    raw: &[u8],
    slice_offset: usize,
) -> Result<Vec<Box<dyn HasSecurityStatus>>> {
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
    // Find LC_CODE_SIGNATURE in load commands; we need both the
    // "is signed?" boolean for this row AND the (dataoff, datasize)
    // pair for the HARDENED-RUNTIME / ALLOW-JIT walks below. Doing
    // both in one pass.
    let cs_loc = slice.load_commands.iter().find_map(|lc| match &lc.command {
        goblin::mach::load_command::CommandVariant::CodeSignature(cs) if cs.datasize > 0 => {
            Some((cs.dataoff as usize, cs.datasize as usize))
        }
        _ => None,
    });
    let code_sig = YesNoUnknownStatus::new("CODE-SIGNATURE", cs_loc.is_some());

    // ---- TWO-LEVEL-NAMESPACE -----------------------------------------
    let two_level = YesNoUnknownStatus::new("TWO-LEVEL-NAMESPACE", flags & MH_TWOLEVEL != 0);

    // ---- NO-UNDEF-SYMS -----------------------------------------------
    let no_undef = YesNoUnknownStatus::new("NO-UNDEF-SYMS", flags & MH_NOUNDEFS != 0);

    // ---- HARDENED-RUNTIME + ALLOW-JIT (0.5.1) ------------------------
    // Both come from the same code-signing SuperBlob walk. If the
    // binary is unsigned (no LC_CODE_SIGNATURE) the answers are
    // unambiguous: HARDENED-RUNTIME=Fail (can't be hardened without
    // a signature), ALLOW-JIT=Fail (no entitlements). If the blob
    // exists but parsing fails (malformed / unknown form), emit
    // Unknown so the user can see something went wrong.
    let (hardened, allow_jit) = match cs_loc {
        None => (
            YesNoUnknownStatus::new("HARDENED-RUNTIME", false),
            YesNoUnknownStatus::new("ALLOW-JIT", false),
        ),
        Some((dataoff, datasize)) => {
            // dataoff is slice-relative inside fat Mach-O; convert
            // to absolute file position.
            let blob_start = slice_offset.saturating_add(dataoff);
            let blob_end = blob_start.saturating_add(datasize);
            if blob_end > raw.len() {
                (
                    YesNoUnknownStatus::unknown("HARDENED-RUNTIME"),
                    YesNoUnknownStatus::unknown("ALLOW-JIT"),
                )
            } else {
                let blob = &raw[blob_start..blob_end];
                let walker = SuperBlob::parse(blob);
                let hr = walker
                    .as_ref()
                    .and_then(|sb| sb.code_directory_flags())
                    .map(|cd_flags| cd_flags & CS_RUNTIME != 0);
                let aj = walker
                    .as_ref()
                    .and_then(|sb| sb.entitlements_plist())
                    .map(plist_says_allow_jit);
                (
                    match hr {
                        Some(b) => YesNoUnknownStatus::new("HARDENED-RUNTIME", b),
                        None => YesNoUnknownStatus::unknown("HARDENED-RUNTIME"),
                    },
                    match aj {
                        Some(b) => YesNoUnknownStatus::new("ALLOW-JIT", b),
                        // No entitlements blob present means the
                        // binary has no entitlements — explicitly
                        // does NOT allow JIT. Pass=true would mean
                        // "JIT is permitted", which it isn't, so
                        // Fail.
                        None => YesNoUnknownStatus::new("ALLOW-JIT", false),
                    },
                )
            }
        }
    };

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

// ---------------------------------------------------------------------
// CS_SuperBlob parser (Apple `<Security/CSCommon.h>`).
//
// On-disk layout (all big-endian):
//
//   SuperBlob {
//       magic:  u32 = 0xfade0cc0
//       length: u32                       // total bytes in SuperBlob
//       count:  u32                       // number of index entries
//       index:  [BlobIndex; count]        // each (type, offset)
//   }
//   BlobIndex { type: u32, offset: u32 } // offset from SuperBlob start
//
//   Sub-blobs at the indexed offsets all start with the same
//   8-byte header:
//
//   GenericBlob {
//       magic:  u32  // identifies what follows
//       length: u32  // total bytes including the 8-byte header
//       body:   [u8; length - 8]
//   }
//
// We need two sub-blobs:
//
//   * CSMAGIC_CODEDIRECTORY (0xfade0c02) — flags field at body
//     offset 0x10 - 8 = 0x08 (8 = sizeof magic + length already
//     consumed). In absolute terms, flags is at blob_offset + 0x10.
//   * CSMAGIC_EMBEDDED_ENTITLEMENTS (0xfade7171) — body is a PLIST
//     (usually XML on macOS, sometimes binary).
//
// All reads are bounds-checked. Any out-of-range / malformed input
// returns None — the caller surfaces that as Unknown.
// ---------------------------------------------------------------------

struct SuperBlob<'a> {
    raw: &'a [u8],
    index: Vec<(u32, u32)>, // (blob type, offset from SuperBlob start)
}

impl<'a> SuperBlob<'a> {
    fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 12 {
            return None;
        }
        let magic = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if magic != CSMAGIC_EMBEDDED_SIGNATURE {
            return None;
        }
        let length = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        if length > raw.len() {
            return None;
        }
        let count = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
        // Each index entry is 8 bytes (type u32 + offset u32). Cap
        // count at a sensible ceiling so a malformed SuperBlob with
        // count = 0xffff_ffff doesn't allocate gigabytes.
        if count > 4096 {
            return None;
        }
        let index_start: usize = 12;
        let index_end = index_start.checked_add(count.checked_mul(8)?)?;
        if index_end > raw.len() {
            return None;
        }
        let mut index = Vec::with_capacity(count);
        for i in 0..count {
            let off = index_start + i * 8;
            let typ = u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
            let blob_off =
                u32::from_be_bytes([raw[off + 4], raw[off + 5], raw[off + 6], raw[off + 7]]);
            index.push((typ, blob_off));
        }
        Some(SuperBlob { raw, index })
    }

    /// Find the sub-blob whose generic-blob header has the given
    /// magic. Returns the FULL sub-blob (including its 8-byte
    /// header). Bounds-checked.
    fn find_blob(&self, magic: u32) -> Option<&'a [u8]> {
        for &(_typ, off) in &self.index {
            let off_usz = off as usize;
            if off_usz + 8 > self.raw.len() {
                continue;
            }
            let sub_magic = u32::from_be_bytes([
                self.raw[off_usz],
                self.raw[off_usz + 1],
                self.raw[off_usz + 2],
                self.raw[off_usz + 3],
            ]);
            if sub_magic != magic {
                continue;
            }
            let sub_len = u32::from_be_bytes([
                self.raw[off_usz + 4],
                self.raw[off_usz + 5],
                self.raw[off_usz + 6],
                self.raw[off_usz + 7],
            ]) as usize;
            let end = off_usz.checked_add(sub_len)?;
            if end > self.raw.len() {
                return None;
            }
            return Some(&self.raw[off_usz..end]);
        }
        None
    }

    /// Read the `flags` field out of `CS_CodeDirectory`. Field
    /// layout (Apple `<kern/cs_blobs.h>`):
    ///   magic    u32  (offset 0x00)
    ///   length   u32  (offset 0x04)
    ///   version  u32  (offset 0x08)
    ///   flags    u32  (offset 0x0c)
    /// Big-endian, as with the rest of the blob.
    fn code_directory_flags(&self) -> Option<u32> {
        let cd = self.find_blob(CSMAGIC_CODEDIRECTORY)?;
        if cd.len() < 0x10 {
            return None;
        }
        Some(u32::from_be_bytes([cd[0x0c], cd[0x0d], cd[0x0e], cd[0x0f]]))
    }

    /// Return the PLIST payload bytes for the entitlements blob.
    /// Skips the 8-byte generic-blob header. None if the blob is
    /// absent or has no payload.
    fn entitlements_plist(&self) -> Option<&'a [u8]> {
        let blob = self.find_blob(CSMAGIC_EMBEDDED_ENTITLEMENTS)?;
        if blob.len() <= 8 {
            return None;
        }
        Some(&blob[8..])
    }
}

/// Parse the entitlements PLIST and decide whether
/// `com.apple.security.cs.allow-jit` is set to `true`. Anything
/// missing / non-boolean / `false` → returns `false`. The `plist`
/// crate handles both XML and binary PLIST formats transparently.
fn plist_says_allow_jit(plist_bytes: &[u8]) -> bool {
    use plist::Value;
    let cursor = std::io::Cursor::new(plist_bytes);
    let Ok(value) = Value::from_reader_xml(cursor) else {
        // XML parse failed — try binary PLIST as a fallback.
        let cursor = std::io::Cursor::new(plist_bytes);
        return matches!(
            Value::from_reader(cursor)
                .ok()
                .as_ref()
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("com.apple.security.cs.allow-jit"))
                .and_then(|v| v.as_boolean()),
            Some(true)
        );
    };
    matches!(
        value
            .as_dictionary()
            .and_then(|d| d.get("com.apple.security.cs.allow-jit"))
            .and_then(|v| v.as_boolean()),
        Some(true)
    )
}
