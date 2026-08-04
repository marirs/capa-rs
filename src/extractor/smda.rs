// 0.4.2: dropped the file-level `#![allow(dead_code,
// clippy::to_string_in_format_args)]`. It was hiding real warnings
// (D7 from the audit — `xor_static` / `xor_with_key`, both removed)
// and the legitimate clippy hint. With those gone, no remaining
// items need silencing at the file level.
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};

lazy_static! {
    // Used by `parse_operand_to_number` to parse signed immediates of the
    // form `-0x10` / `+0x10` out of formatted operand strings. The
    // 0.4.2 `_SPACED` variants (handled `- 0x10` with whitespace) were
    // dropped in 0.5.0 along with E1's string-based offset extraction
    // — the typed iced operand walk doesn't need them.
    static ref RE_NUMBER_HEX: Regex =
        Regex::new(r"(?P<sign>[+\-])(?P<num>0x[a-fA-F0-9]+)").unwrap();
    static ref RE_NUMBER_INT: Regex = Regex::new(r"(?P<sign>[+\-])(?P<num>[0-9]+)").unwrap();
}

use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
use smda::{
    Disassembler,
    SmdaConfig,
    // 0.5.0: AArch64 operand decoders for the ARM64 paths in
    // `extract_insn_offset_features` and
    // `extract_insn_peb_access_characteristic_features`. smda
    // exposes these as `pub mod aarch64_ops;` under `disassembler`.
    disassembler::{
        DecodedInsn,
        aarch64_ops::{decode_adr, decode_adrp, decode_ldr_str_uimm},
    },
    function::{Function, Instruction},
    report::DisassemblyReport,
};

use crate::{
    Result,
    consts::{FileFormat, Os},
    error::Error,
};

#[derive(Debug, Clone)]
struct InstructionS {
    i: Instruction,
}
impl super::Instruction for InstructionS {
    fn is_mov_imm_to_stack(&self) -> Result<bool> {
        // 0.3.21: capa-rs used to re-implement this check by string-
        // parsing `insn.mnemonic` / `insn.operands`. smda 0.4.1+ does
        // the work internally via `get_printable_len` — a non-zero
        // return value means the instruction is a `mov [stack], IMM`
        // with a printable immediate. Same semantics, no string
        // allocation, no duplicated heuristic to drift.
        Ok(self.i.get_printable_len()? > 0)
    }
    fn get_printable_len(&self) -> Result<u64> {
        Ok(self.i.get_printable_len()?)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone)]
struct FunctionS {
    f: Function,
}

impl super::Function for FunctionS {
    fn inrefs(&self) -> &Vec<u64> {
        &self.f.inrefs
    }
    fn blockrefs(&self) -> &HashMap<u64, Vec<u64>> {
        &self.f.blockrefs
    }
    fn offset(&self) -> u64 {
        self.f.offset
    }

    fn get_blocks(&self) -> Result<BTreeMap<u64, Vec<Box<dyn super::Instruction>>>> {
        let mut res = BTreeMap::<u64, Vec<Box<dyn super::Instruction>>>::new();
        for (u, b) in self.f.get_blocks()? {
            let mut instr: Vec<Box<dyn super::Instruction>> = vec![];
            for i in b {
                // `Instruction` is `Copy` in smda 0.6 (it's a thin
                // wrapper over `DecodedInsn` + offset/length); `.clone()`
                // worked but clippy::clone_on_copy flags the redundant
                // call. Dereference to take the value directly.
                instr.push(Box::new(InstructionS { i: *i }));
            }
            res.insert(*u, instr);
        }
        Ok(res)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// 0.3.21: smda 0.4.0 made `DisassemblyReport<'a>` borrow from the
/// input buffer (zero-copy). Capa-rs's existing public API
/// (`Extractor::new(path, …, &data)`) owns the buffer at construction
/// time, so we use `ouroboros::self_referencing` to hold `buf: Vec<u8>`
/// and `report: DisassemblyReport<'this>` in the same struct without
/// exposing smda's lifetime to capa-rs callers. The full zero-copy
/// refactor (caller owns the buffer, `Extractor<'a>` takes `&'a [u8]`)
/// is deferred to capa 0.4.0.
pub struct Extractor<'a> {
    report: DisassemblyReport<'a>,
    buf: &'a [u8],
    path: String,
    /// Cache for `extract_global_features` (issue marirs/capa-rs#18):
    /// OS/arch are constant per file, but computing the OS feature
    /// costs a full `goblin::Object::parse` of the buffer — and the
    /// feature was recomputed on every instruction and basic block.
    /// `OnceCell` (not `lazy_static`) because the value is per-file;
    /// the `sync` flavour because `find_capabilities` shares the
    /// extractor across rayon worker threads.
    global_features_cache: once_cell::sync::OnceCell<Vec<(crate::rules::features::Feature, u64)>>,
}

impl std::fmt::Debug for Extractor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extractor")
            .field("path", &self.path)
            .field("functions", &self.report.functions.len())
            .finish_non_exhaustive()
    }
}

// 0.4.0: lifetime parameter named `'data` (not `'a`) so it doesn't
// collide with the trait method `fn get_instructions<'a>` which uses
// `'a` for its own borrow scope.
impl<'data> super::Extractor for Extractor<'data> {
    fn is_dot_net(&self) -> bool {
        false
    }

    /// 0.4.3: surface raw function bytes for the FLIRT matcher.
    /// `bytes_at_best_effort` truncates gracefully at section
    /// boundaries — returning at least a non-empty prefix is enough
    /// for FLIRT's leading-pattern + CRC matcher to operate on.
    fn function_bytes(&self, addr: u64, max_len: u32) -> Option<&[u8]> {
        self.report()
            .binary_info
            .bytes_at_best_effort(addr, max_len)
            .ok()
    }

    fn get_base_address(&self) -> Result<u64> {
        Ok(self.report().base_addr)
    }

    fn arch(&self) -> Result<crate::FileArchitecture> {
        // smda's `DisassemblyReport.architecture` is already
        // `FileArchitecture` (the same enum capa re-exports), so this
        // is a direct passthrough. For smda 0.6+ binaries this
        // correctly surfaces `Aarch64` instead of letting upstream
        // mislabel them as AMD64 via bitness inference.
        Ok(self.report().architecture)
    }

    fn format(&self) -> FileFormat {
        // 0.4.0: capa-rs `FileFormat` gained `Macho` to mirror smda 0.5's
        // `MachO` variant — capa rules that filter on `format: macho` now
        // fire correctly. `Buffer` (shellcode / raw memory) has no
        // PE/ELF/Mach-O equivalent in the file-format sense; report as
        // PE so the rules engine still runs and OS-tagged matches behave
        // sensibly. Shellcode-specific routing happens at the
        // `FileCapabilities::from_buffer` entry point.
        match self.report().format {
            smda::FileFormat::PE => FileFormat::PE,
            smda::FileFormat::ELF => FileFormat::ELF,
            smda::FileFormat::MachO => FileFormat::Macho,
            smda::FileFormat::Buffer => FileFormat::PE,
            _ => FileFormat::PE,
        }
    }

    fn bitness(&self) -> u32 {
        self.report().bitness
    }

    fn extract_global_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        // Issue marirs/capa-rs#18: computed once per extractor, then
        // cloned — the uncached version paid a full goblin parse for
        // the OS feature on every call (i.e. per instruction).
        Ok(self
            .global_features_cache
            .get_or_try_init(|| -> Result<Vec<(crate::rules::features::Feature, u64)>> {
                Ok(vec![
                    (
                        crate::rules::features::Feature::Os(
                            crate::rules::features::OsFeature::new(
                                &self.extract_os()?.to_string(),
                                "",
                            )?,
                        ),
                        0,
                    ),
                    (
                        crate::rules::features::Feature::Arch(
                            crate::rules::features::ArchFeature::new(
                                &self.extract_arch()?.to_string(),
                                "",
                            )?,
                        ),
                        0,
                    ),
                ])
            })?
            .clone())
    }

    fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        res.extend(self.extract_file_export_names()?);
        res.extend(self.extract_file_import_names()?);
        res.extend(self.extract_file_section_names()?);
        res.extend(self.extract_file_embedded_pe()?);
        res.extend(self.extract_file_strings()?);
        // 0.3.21: smda 0.4.2 added Function::function_name(), populated
        // by Go pclntab / MinGW DWARF / Delphi VMT / Rust demangling.
        // Wires those names into the rules engine for `function-name:`
        // rule matches — previously this line was commented out
        // ("NOTE not sure") because the smda 0.2 API exposed it via a
        // different code path. The current smda surface is the right one.
        res.extend(self.extract_file_function_names()?);
        res.extend(self.extract_file_format()?);
        Ok(res)
    }

    fn get_functions(&self) -> Result<BTreeMap<u64, Box<dyn super::Function>>> {
        let mut res = BTreeMap::<u64, Box<dyn super::Function>>::new();
        for (u, f) in self.report().get_functions()? {
            res.insert(*u, Box::new(FunctionS { f: f.clone() }));
        }
        Ok(res)
    }

    fn extract_function_features(
        &self,
        f: &Box<dyn super::Function>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![]; //extract function calls to

        // 0.5.0 note: function-scope FunctionName emission was
        // considered (E2 in the parity audit) for parity with Python
        // capa, but reverted after empirical measurement showed:
        //   1. The entire capa-rules corpus contains exactly one
        //      `function-name:` rule, and it's file-scoped, not
        //      function-scoped. So function-scope emission unlocks
        //      zero rule matches today.
        //   2. The emission added ~16% to mimikatz analysis time
        //      (~0.9s on a 5s baseline) for zero functional benefit
        //      on real workloads — every emission was a wasted
        //      String + HashSet alloc that downstream rule eval had
        //      to probe past.
        // File-scope FunctionName via `extract_file_function_names`
        // covers the one rule that exists. If a future Python-capa
        // release ships function-scope name rules and they're added
        // to the corpus, revisit this.

        for inref in f.inrefs() {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("calls to", "")?,
                ),
                *inref,
            ));
        }
        //parse if a function has a loop
        let mut vertices_names = std::collections::HashSet::new();
        let mut edges = vec![];
        for (bb_from, bb_tos) in f.blockrefs() {
            for bb_to in bb_tos {
                vertices_names.insert(*bb_from);
                vertices_names.insert(*bb_to);
                edges.push((*bb_from, *bb_to))
            }
        }
        if !edges.is_empty() && self.has_loop(&vertices_names, &edges)? {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("loop", "")?,
                ),
                f.offset(),
            ));
        }
        Ok(res)
    }

    fn get_basic_blocks(
        &self,
        f: &Box<dyn super::Function>,
    ) -> Result<BTreeMap<u64, Vec<Box<dyn super::Instruction>>>> {
        f.get_blocks()
    }

    fn get_instructions<'a>(
        &self,
        _f: &Box<dyn super::Function>,
        bb: &'a (&u64, &Vec<Box<dyn super::Instruction>>),
    ) -> Result<&'a Vec<Box<dyn super::Instruction>>> {
        Ok(bb.1)
    }

    fn extract_basic_block_features(
        &self,
        f: &Box<dyn super::Function>,
        bb: &(&u64, &Vec<Box<dyn super::Instruction>>),
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![(
            crate::rules::features::Feature::BasicBlock(
                crate::rules::features::BasicBlockFeature::new()?,
            ),
            *bb.0,
        )];
        if f.blockrefs().contains_key(bb.0) && f.blockrefs()[bb.0].contains(bb.0) {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("tight loop", "")?,
                ),
                *bb.0,
            ));
        }
        let mut count = 0;
        for instr in bb.1 {
            if instr.is_mov_imm_to_stack()? {
                count += instr.get_printable_len()?;
            }
        }
        if count > 8 {
            //MIN_STACKSTRING_LEN
            // Emitted once per basic block — previously the push sat
            // inside the loop with no `break`, so every instruction
            // past the threshold added a duplicate (#24).
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("stack string", "")?,
                ),
                *bb.0,
            ));
        }
        Ok(res)
    }

    fn extract_insn_features(
        &self,
        f: &Box<dyn super::Function>,
        insn: &Box<dyn super::Instruction>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let f: &FunctionS = f.as_any().downcast_ref::<FunctionS>().unwrap();
        let insn: &InstructionS = insn.as_any().downcast_ref::<InstructionS>().unwrap();
        let mut res = vec![];
        res.extend(self.extract_insn_api_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_number_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_string_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_bytes_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_offset_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_nzxor_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_obfs_call_plus_5_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_mnemonic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_peb_access_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_cross_section_cflow(&f.f, &insn.i)?);
        res.extend(self.extract_insn_segment_access_features(&f.f, &insn.i)?);
        res.extend(self.extract_function_calls_from(&f.f, &insn.i)?);
        res.extend(self.extract_function_indirect_call_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_file_format()?);
        res.extend(self.extract_global_features()?);
        Ok(res)
    }
}

/// 0.5.0 (task #236): ARM64 equivalent of the x86 iced operand walk
/// in `extract_insn_offset_features`. Walks the disarm64 operand
/// surface to recover memory displacements with the same semantic as
/// the x86 path emits:
///
///   `LDR Xt, [Xn, #imm12]` → Offset(imm12) + OperandOffset(1, imm12)
///   `STR Xt, [Xn, #imm12]` → same
///   `ADR Xn, label`        → Number(label_va)
///
/// Stack-frame addressing (base = SP = R31 or X29 = frame pointer) is
/// skipped — matches the x86 path's RBP/EBP filter. The ADR Number
/// emission mirrors the x86 LEA path: both materialise a constant
/// address into a register.
///
/// Free function (not a method) so the `extract_insn_offset_features`
/// dispatch above can `return` it directly without re-entering the
/// `&self` borrow.
fn extract_insn_offset_features_aarch64(
    f: &Function,
    insn: &Instruction,
    raw: u32,
) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
    let mut res = vec![];

    // LDR / STR (immediate offset) — the load/store form that carries
    // a meaningful displacement. Register-indexed (`LDR Xt, [Xn, Xm
    // LSL #N]`) is excluded because it has no immediate of its own.
    if let Some(op) = decode_ldr_str_uimm(raw) {
        // Skip stack-frame addressing: SP (R31) and X29 (Apple-clang
        // / GCC frame pointer on AArch64). x86 path filters
        // EBP/RBP for the same reason.
        if op.rn != 31 && op.rn != 29 {
            let disp = op.offset as i64 as i128;
            res.push((
                crate::rules::features::Feature::Offset(
                    crate::rules::features::OffsetFeature::new(f.bitness, &disp, "")?,
                ),
                insn.offset,
            ));
            // Operand index 1 — Xt is op0 (destination/source),
            // [Xn, #imm] is op1. Matches the x86 indexing convention
            // (memory operand is typically operand 1 for `mov reg, mem`
            // / `mov mem, reg`).
            res.push((
                crate::rules::features::Feature::OperandOffset(
                    crate::rules::features::OperandOffsetFeature::new(&1usize, &disp, "")?,
                ),
                insn.offset,
            ));
        }
    }

    // ADR Xd, label — PC-relative byte-granular load. Equivalent to
    // x86 `lea rax, [rip+const]` semantically: materialises a constant
    // address into a register. Emit Number to match the x86 LEA path.
    if let Some((_rd, target)) = decode_adr(raw, insn.offset) {
        let disp = target as i64 as i128;
        res.push((
            crate::rules::features::Feature::Number(crate::rules::features::NumberFeature::new(
                f.bitness, &disp, "",
            )?),
            insn.offset,
        ));
    }

    // ADRP Xd, page — PC-relative page load (4 KiB granularity). Same
    // semantic as ADR but at page granularity. Compilers emit ADRP
    // followed by ADD/LDR to materialise a full address; for capa's
    // `number:` rules we surface the page VA — it's not exact but
    // close enough for the typical "constant in code" pattern.
    if let Some((_rd, page_va)) = decode_adrp(raw, insn.offset) {
        let disp = page_va as i64 as i128;
        res.push((
            crate::rules::features::Feature::Number(crate::rules::features::NumberFeature::new(
                f.bitness, &disp, "",
            )?),
            insn.offset,
        ));
    }

    Ok(res)
}

impl<'data> Extractor<'data> {
    /// 0.4.0: takes `&'data [u8]` borrowed from the caller. The
    /// returned `Extractor<'data>` borrows from that slice for the
    /// lifetime `'data` — no internal clone of the file bytes, no
    /// ouroboros wrapper. Pre-0.4.0 the data was deep-copied into an
    /// owned Vec; that extra ~10–50 MB peak allocation per
    /// analyse-call is gone now.
    pub fn new(
        path: &str,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        data: &'data [u8],
    ) -> Result<Extractor<'data>> {
        let cfg = SmdaConfig::new()
            .path(path)
            .high_accuracy(high_accuracy)
            .resolve_tailcalls(resolve_tailcalls);
        let report = Disassembler::parse(data, &cfg)?;
        Ok(Extractor {
            report,
            buf: data,
            path: path.to_string(),
            global_features_cache: once_cell::sync::OnceCell::new(),
        })
    }

    /// 0.4.0: raw-buffer constructor for shellcode / unpacked modules /
    /// memory dumps — no PE/ELF/Mach-O header parsing. Routes through
    /// smda's `parse_buffer` (added in smda 0.4.2 N11, public in 0.5.0).
    /// The resulting `DisassemblyReport` has
    /// `format = smda::FileFormat::Buffer`, which the trait's
    /// `format()` impl downgrades to `FileFormat::PE` for rule-engine
    /// compatibility. `bitness` must be 32 or 64; `base_addr` is the
    /// virtual address the buffer is treated as mapped to.
    pub fn from_buffer(
        data: &'data [u8],
        base_addr: u64,
        bitness: u32,
        high_accuracy: bool,
        resolve_tailcalls: bool,
    ) -> Result<Extractor<'data>> {
        let cfg = SmdaConfig::new()
            .high_accuracy(high_accuracy)
            .resolve_tailcalls(resolve_tailcalls);
        let report = Disassembler::parse_buffer(data, base_addr, bitness, &cfg)?;
        Ok(Extractor {
            report,
            buf: data,
            // Synthetic path — no real file backs a buffer-mode
            // extractor. Kept stable so `Debug` output is uniform.
            path: "<buffer>".to_string(),
            global_features_cache: once_cell::sync::OnceCell::new(),
        })
    }

    /// Borrowed view onto the smda report.
    pub(crate) fn report(&self) -> &DisassemblyReport<'data> {
        &self.report
    }

    // 0.4.2: removed `get_buf` (pub) — never called from outside this
    // module; in-tree call sites use the private `buf()` accessor
    // below. If downstream consumers need raw bytes they can hold
    // their own reference to the slice they passed to `Extractor::new`.
    fn buf(&self) -> &[u8] {
        self.buf
    }

    pub fn get_elf_os(elf: &goblin::elf::Elf) -> Result<Os> {
        match elf.header.e_ident[7] {
            0x00 => Ok(Os::LINUX),
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
            _ => {
                // For Unknown ELF OS, also assume Linux as fallback
                Ok(Os::LINUX)
            }
        }
    }
    pub fn extract_os(&self) -> Result<Os> {
        // 0.5.0: Mach-O resolves to the real Darwin family
        // (Os::MACOS / Os::IOS) instead of the pre-0.5.0 Os::LINUX
        // placeholder.
        //
        // 0.5.1: macOS / iOS distinction now wired. cputype alone
        // can't distinguish (both share CPU_TYPE_ARM64 on
        // Apple-Silicon Macs / iOS devices), but the load commands
        // do: `LC_BUILD_VERSION.platform` is `PLATFORM_MACOS (1)` /
        // `PLATFORM_IOS (2)` / `PLATFORM_TVOS (3)` / etc. on
        // Xcode-10+ binaries; legacy binaries use the older
        // `LC_VERSION_MIN_MACOSX` / `LC_VERSION_MIN_IPHONEOS`
        // commands. We inspect both — first match wins.
        //
        // Buffer (shellcode) keeps the WINDOWS default — most
        // analysed shellcode targets Win32.
        match self.report().format {
            smda::FileFormat::MachO => return classify_macho_os(self.buf()),
            smda::FileFormat::Buffer => return Ok(Os::WINDOWS),
            _ => {}
        }
        match goblin::Object::parse(self.buf())? {
            goblin::Object::Elf(elf) => Extractor::get_elf_os(&elf),
            goblin::Object::PE(_) => Ok(Os::WINDOWS),
            // Defensive: if smda labelled the format as MachO but
            // goblin sees a fat-Mach-O wrapper (cafebabe) here,
            // route through the same classifier. The earlier
            // `report().format` match should already have caught
            // this; the fallthrough is kept for safety.
            goblin::Object::Mach(_) => classify_macho_os(self.buf()),
            _ => Err(Error::UnsupportedOsError),
        }
    }

    pub fn extract_arch(&self) -> Result<crate::FileArchitecture> {
        Ok(self.report().architecture)
    }

    pub fn has_loop(
        &self,
        vertices_names: &std::collections::HashSet<u64>,
        edges: &[(u64, u64)],
    ) -> Result<bool> {
        let mut vertices = std::collections::HashMap::new();
        let mut graph = petgraph::graph::Graph::<u64, ()>::new(); // directed and unlabeled
        for n in vertices_names {
            vertices.insert(n, graph.add_node(*n));
        }
        graph.extend_with_edges(
            edges
                .iter()
                .map(|(a, b)| (vertices[a], vertices[b]))
                .collect::<Vec<(petgraph::graph::NodeIndex, petgraph::graph::NodeIndex)>>(),
        );
        let scc = petgraph::algo::kosaraju_scc(&graph);
        let mut res = false;
        for s in &scc {
            res |= s.len() >= 2 //threshold
        }
        Ok(res)
    }

    fn extract_file_format(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        // 0.4.0: Mach-O and Buffer added. capa rules that filter on
        // `format: macho` now fire correctly. Shellcode is reported as
        // `pe` to keep PE-targeted rules matchable — most analysed
        // shellcode payloads target Win32 and Python upstream behaves
        // the same way (its `disassembleBuffer` defaults to PE rules).
        let fmt = match self.report().format {
            smda::FileFormat::PE => "pe",
            smda::FileFormat::ELF => "elf",
            smda::FileFormat::MachO => "macho",
            smda::FileFormat::Buffer => "pe",
            _ => "pe",
        };
        Ok(vec![(
            crate::rules::features::Feature::Format(crate::rules::features::FormatFeature::new(
                fmt, "",
            )?),
            0,
        )])
    }

    fn extract_file_embedded_pe(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (mz_offset, _pe_offset, _key) in
            Extractor::find_embedded_pe_headers(self.report().binary_info.raw_data)
        {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("embedded pe", "")?,
                ),
                mz_offset,
            ));
        }
        Ok(res)
    }

    pub fn extract_file_section_names(
        &self,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (n, b, _e) in &self.report().sections {
            res.push((
                crate::rules::features::Feature::Section(
                    crate::rules::features::SectionFeature::new(n.trim_matches(char::from(0)), "")?,
                ),
                *b,
            ));
        }
        Ok(res)
    }

    pub fn extract_file_export_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (e, o, ree) in &self.report().exports {
            match ree {
                None => {
                    res.push((
                        crate::rules::features::Feature::Export(
                            crate::rules::features::ExportFeature::new(e, "")?,
                        ),
                        *o as u64,
                    ));
                }
                Some(re) => {
                    res.push((
                        crate::rules::features::Feature::Export(
                            crate::rules::features::ExportFeature::new(re, "")?,
                        ),
                        *o as u64,
                    ));
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new(
                                "forwarded export",
                                "",
                            )?,
                        ),
                        *o as u64,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_file_import_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (d, f, o) in &self.report().imports {
            for n in generate_symbols(&Some(d.to_string()), &Some(f.to_string()))? {
                res.push((
                    crate::rules::features::Feature::Import(
                        crate::rules::features::ImportFeature::new(&n, "")?,
                    ),
                    *o as u64,
                ));
            }
        }
        Ok(res)
    }

    /// 0.3.21: emit `Feature::FunctionName` for every smda-discovered
    /// function that carries a symbolic name. Names come from any of
    /// smda's name-recovery pipelines: Go pclntab, MinGW DWARF (with
    /// Rust / Itanium demangling), ELF dynsym/symtab, Delphi VMT
    /// (`ClassName::vmt_<idx>`). Empty names are skipped.
    fn extract_file_function_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (addr, func) in self.report().get_functions()? {
            let name = func.function_name();
            if name.is_empty() {
                continue;
            }
            res.push((
                crate::rules::features::Feature::FunctionName(
                    crate::rules::features::FunctionNameFeature::new(name, "")?,
                ),
                *addr,
            ));
        }
        Ok(res)
    }

    fn extract_file_strings(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (s, a) in extract_file_strings(self.buf())? {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            res.push((
                crate::rules::features::Feature::String(
                    crate::rules::features::StringFeature::new(trimmed, "")?,
                ),
                a,
            ));
        }
        Ok(res)
    }

    pub fn extract_function_indirect_call_characteristic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        // 0.3.21: smda 0.4.0 dropped `Instruction::mnemonic: String` in
        // favour of typed `mnemonic_enum()` + `is_call/jmp/ret` helpers.
        // String-compare hot paths now go through the iced `Mnemonic`
        // enum — no allocation per instruction.
        if !insn.is_call() {
            return Ok(res);
        }
        if let Some(o) = insn.format_operands() {
            if o.starts_with("0x") {
                return Ok(res);
            }
            if o.contains("qword ptr") && o.contains("rip") {
                return Ok(res);
            }
            if o.starts_with("dword ptr [0x") {
                return Ok(res);
            }
            //# call edx
            //# call dword ptr [eax+50h]
            //# call qword ptr [rsp+78h]
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("indirect call", "")?,
                ),
                insn.offset,
            ));
        }
        Ok(res)
    }

    pub fn extract_function_calls_from(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if !insn.is_call() {
            return Ok(res);
        }

        if f.outrefs.contains_key(&insn.offset) {
            for outref in &f.outrefs[&insn.offset] {
                res.push((
                    crate::rules::features::Feature::Characteristic(
                        crate::rules::features::CharacteristicFeature::new("calls from", "")?,
                    ),
                    *outref,
                ));
                if outref == &f.offset {
                    //if we found a jump target and it's the function address
                    //mark as recursive
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new(
                                "recursive call",
                                "",
                            )?,
                        ),
                        *outref,
                    ));
                }
            }
        }
        if f.apirefs.contains_key(&insn.offset) {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("calls from", "")?,
                ),
                insn.offset,
            ));
        }
        Ok(res)
    }
    pub fn extract_insn_segment_access_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if let Some(o) = insn.format_operands() {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            for operand in operands {
                if operand.contains("fs:") {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("fs access", "")?,
                        ),
                        insn.offset,
                    ));
                }
                if operand.contains("gs:") {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("gs access", "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_cross_section_cflow(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if insn.is_call() || insn.is_jmp() {
            if f.apirefs.contains_key(&insn.offset) {
                return Ok(res);
            }

            if f.outrefs.contains_key(&insn.offset) {
                for target in &f.outrefs[&insn.offset] {
                    if self.report().get_section(&insn.offset)?
                        != self.report().get_section(target)?
                    {
                        res.push((
                            crate::rules::features::Feature::Characteristic(
                                crate::rules::features::CharacteristicFeature::new(
                                    "cross section flow",
                                    "",
                                )?,
                            ),
                            insn.offset,
                        ));
                    }
                }
            } else if let Some(o) = insn.format_operands() {
                // if o.starts_with("0x") {
                //     let target = u64::from_str_radix(&o[2..], 16)?;
                if let Some(x) = o.strip_prefix("0x") {
                    let target = u64::from_str_radix(x, 16)?;
                    if self.report().get_section(&insn.offset)?
                        != self.report().get_section(&target)?
                    {
                        res.push((
                            crate::rules::features::Feature::Characteristic(
                                crate::rules::features::CharacteristicFeature::new(
                                    "cross section flow",
                                    "",
                                )?,
                            ),
                            insn.offset,
                        ));
                    }
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_peb_access_characteristic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];

        // 0.5.0 (task #273): ARM64 path. Windows on ARM64 reserves x18
        // as the TEB pointer (Microsoft's "x18 = platform register" ABI
        // — see Windows ARM64 calling convention docs). PEB is at
        // [x18 + 0x60] on 64-bit Windows, mirroring `gs:[0x60]` on x64.
        //
        // We flag every load with base = x18 as a TEB access (capa's
        // "peb access" characteristic) regardless of displacement —
        // that matches how the x86 path treats `gs:`/`fs:` segment
        // reads as TEB-touching, and avoids hard-coding a single
        // displacement (rules look for the broader "touches TEB"
        // signal, then narrower offset-based features layer on top).
        // Stores are excluded: writing through x18 is exotic and
        // doesn't pattern-match "read PEB to do X".
        if let DecodedInsn::Aarch64(a) = insn.decoded {
            if let Some(op) = decode_ldr_str_uimm(a.opcode) {
                if op.rn == 18 && !op.is_store {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("peb access", "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
            return Ok(res);
        }

        if !matches!(insn.mnemonic_enum(), Mnemonic::Push | Mnemonic::Mov) {
            return Ok(res);
        }
        if let Some(o) = insn.format_operands() {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            for operand in operands {
                if (operand.contains("fs:") && operand.contains("0x30"))
                    || (operand.contains("gs:") && operand.contains("0x60"))
                {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("peb access", "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_mnemonic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        // 0.5.0 (task #236): branch on architecture.
        //
        //   x86  → `format_mnemonic()` returns the iced mnemonic name
        //          ("mov", "push", "lea", …).
        //   ARM64 → `format_mnemonic()` returns "invalid" because the
        //          underlying iced `Mnemonic` enum is `INVALID` for
        //          non-x86 decodes. The disarm64 mnemonic string is
        //          available via `mnemonic_aarch64()` instead.
        //
        // Picking the right source matches the rule-author intent:
        // `mnemonic: mov` should fire on x86 `mov`; the disarm64 ARM64
        // equivalent is also called `mov` (and `ldr`, `str`, etc. have
        // their own names) — both surfaces are lowercase, no
        // architecture qualifier in the rule.
        let name = match insn.mnemonic_aarch64() {
            Some(arm64_name) => arm64_name,
            None => insn.format_mnemonic(),
        };
        Ok(vec![(
            crate::rules::features::Feature::Mnemonic(
                crate::rules::features::MnemonicFeature::new(&name, "")?,
            ),
            insn.offset,
        )])
    }

    pub fn extract_insn_nzxor_characteristic_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];

        // 0.5.0 (audit HIGH): ARM64 path. Pre-0.5.0 this function
        // only checked the iced x86 mnemonic enum, which returns
        // `Mnemonic::INVALID` on AArch64 decodes — so the `nzxor`
        // characteristic never fired on ARM64 binaries at all.
        // EOR/EOR3 are the AArch64 XOR family (general + SHA3
        // 3-way). Self-XOR (`eor xd, xn, xn`) is the AArch64
        // zeroing idiom — skipped, mirroring the x86 `xor eax,eax`
        // dst==src filter.
        if let DecodedInsn::Aarch64(a) = insn.decoded {
            // mnemonic_aarch64() returns lowercase disarm64 mnemonic
            // ("eor", "eor3", or one of the vector forms). Match
            // by prefix to catch the NEON/SVE variants without
            // enumerating every encoding (`eor` covers `eor.16b`,
            // `eor.8b`, etc. once the formatter folds them).
            let mnem = insn.mnemonic_aarch64();
            let is_eor = matches!(mnem.as_deref(), Some("eor") | Some("eor3") | Some("eors"));
            if !is_eor {
                return Ok(res);
            }
            // Self-XOR detection: EOR (shifted register) bit layout
            //   bits [20:16] = Rm, bits  [9:5]  = Rn, bits [4:0] = Rd
            // (ARM ARM §C6.2.96). Rn == Rm means "xor a register
            // with itself" — same zeroing idiom as x86's
            // `xor eax, eax`. Don't fire the characteristic for it.
            let rn = (a.opcode >> 5) & 0x1f;
            let rm = (a.opcode >> 16) & 0x1f;
            if rn == rm {
                // 0.5.2 (upstream parity #2997): `eor xd, xn, xn` is the
                // AArch64 zeroing idiom — same shape as x86 `xor eax, eax`.
                // Emit Number(0) at the instruction so rules matching on
                // `number: 0` see the produced value, rather than dropping
                // the case silently (pre-0.5.2 behaviour).
                res.push((
                    crate::rules::features::Feature::Number(
                        crate::rules::features::NumberFeature::new(f.bitness, &0_i128, "")?,
                    ),
                    insn.offset,
                ));
                return Ok(res);
            }
            // Security-cookie filter is x86-specific (stack-canary
            // load + xor pattern uses RBP-relative addressing that
            // doesn't exist verbatim on ARM64; AArch64 uses
            // `__stack_chk_guard` reads instead). Skip the
            // `is_security_cookie` call on ARM64 — it would always
            // return false (operand-string match on `[rbp-…]`).
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("nzxor", "")?,
                ),
                insn.offset,
            ));
            return Ok(res);
        }

        if !matches!(
            insn.mnemonic_enum(),
            Mnemonic::Xor | Mnemonic::Xorpd | Mnemonic::Xorps | Mnemonic::Pxor
        ) {
            return Ok(res);
        }
        if let Some(o) = insn.format_operands() {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            if operands[0] == operands[1] {
                // 0.5.2 (upstream parity #2997): `xor eax, eax` (and the SSE
                // / packed variants Xorpd/Xorps/Pxor) zero the destination
                // register. Emit Number(0) for rules matching the produced
                // value, instead of dropping the case silently.
                res.push((
                    crate::rules::features::Feature::Number(
                        crate::rules::features::NumberFeature::new(f.bitness, &0_i128, "")?,
                    ),
                    insn.offset,
                ));
                return Ok(res);
            }
        }
        if is_security_cookie(f, insn)? {
            return Ok(res);
        }

        res.push((
            crate::rules::features::Feature::Characteristic(
                crate::rules::features::CharacteristicFeature::new("nzxor", "")?,
            ),
            insn.offset,
        ));
        Ok(res)
    }

    pub fn extract_insn_obfs_call_plus_5_characteristic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if !insn.is_call() {
            return Ok(res);
        }
        if let Some(o) = insn.format_operands() {
            if !o.starts_with("0x") {
                return Ok(res);
            }
            if u64::from_str_radix(&o[2..], 16)? == insn.offset + 5 {
                res.push((
                    crate::rules::features::Feature::Characteristic(
                        crate::rules::features::CharacteristicFeature::new("call $+5", "")?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    pub fn extract_insn_offset_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        // 0.5.0 (E1): rewritten to walk iced's typed operands instead
        // of parsing `format_operands()` strings.
        //
        // Pre-0.5.0 split the formatted operand string on commas and
        // ran regexes against each piece. That silently lost offsets
        // for:
        //   - SIB-displacement forms like `[rax + rcx*4 + 0x10]`
        //     where the displacement is buried in a multi-component
        //     operand the regex couldn't always isolate
        //   - operand strings that didn't contain the substring
        //     "ptr" (some iced formatter modes drop the size prefix)
        //   - operands whose base register was matched by string
        //     containment (`ebp`/`rbp` for stack locals) but the
        //     containment check also fired on incidental substrings
        //     in larger formatter outputs
        //
        // The typed walk consults `op_kind(i)`, `memory_base()`, and
        // `memory_displacement64()` directly — exactly what Python
        // capa's vivisect operand walker does. Same algorithm:
        //
        //   for each operand:
        //     if it's a memory operand (or the instruction is LEA):
        //       skip if base register is EBP/RBP (stack-local
        //       addressing — should be a stack-var feature, not an
        //       offset feature)
        //       emit Offset + OperandOffset[i]
        //       if LEA: also emit Number (the constant load)
        //
        //# examples:
        //#
        //#     mov eax, [esi + 4]          → emit offset:4
        //#     mov eax, [esi + ecx + 16384] → emit offset:16384
        //#     lea rax, [rip + 0x100]      → emit offset:0x100 + number:0x100
        //#     mov eax, [ebp - 8]          → skipped (stack local)
        //
        // 0.5.0 (task #236): ARM64 path uses smda 0.6's
        // `aarch64_ops` decoders for the same semantic.
        if let DecodedInsn::Aarch64(a) = insn.decoded {
            return extract_insn_offset_features_aarch64(f, insn, a.opcode);
        }

        let mut res = vec![];
        let is_lea = insn.mnemonic_enum() == Mnemonic::Lea;

        for i in 0..insn.op_count() {
            // Only memory-operand kinds carry a displacement. LEA's
            // operand is also Memory-kind (it's loading the *address*,
            // not dereferencing) — handled the same way.
            if insn.op_kind(i) != OpKind::Memory {
                continue;
            }

            // Stack-frame addressing → skip. Frame-pointer-relative
            // operands are stack locals, not data offsets, and Python
            // capa treats them the same way.
            //
            // ESP/RSP omitted intentionally — Python capa's
            // `extractor/viv` walker also doesn't filter ESP-relative
            // because non-frame-pointer compiles can address locals
            // off SP and a rule looking for `offset: 0x...` should
            // still see them. The pre-0.5.0 code had ESP commented
            // out for the same reason; preserved here.
            let base = insn.memory_base();
            if matches!(base, Register::EBP | Register::RBP) {
                continue;
            }

            // `memory_displacement64` returns the unsigned form; cast
            // through i64 sign-extends 32-bit displacements correctly
            // (iced stores them sign-extended in the u64 already).
            let disp = insn.memory_displacement64() as i64 as i128;

            res.push((
                crate::rules::features::Feature::Offset(
                    crate::rules::features::OffsetFeature::new(f.bitness, &disp, "")?,
                ),
                insn.offset,
            ));
            res.push((
                crate::rules::features::Feature::OperandOffset(
                    crate::rules::features::OperandOffsetFeature::new(&(i as usize), &disp, "")?,
                ),
                insn.offset,
            ));

            if is_lea {
                // LEA is also a constant-load: `lea rax, [rip+0x100]`
                // produces the value 0x100 (or rip+0x100 in absolute
                // form) into rax. Surface the displacement as a
                // Number feature too — matches Python capa.
                res.push((
                    crate::rules::features::Feature::Number(
                        crate::rules::features::NumberFeature::new(f.bitness, &disp, "")?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    pub fn extract_insn_string_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        //# example:
        //#
        //#     push    offset aAcr     ; "ACR  > "
        for data_ref in insn.get_data_refs(self.report())? {
            for v in derefs(self.report(), &data_ref)? {
                let string_read = read_string(self.report(), &v)?;
                let trimmed = string_read.trim();
                if trimmed.is_empty() {
                    continue;
                }
                res.push((
                    crate::rules::features::Feature::String(
                        crate::rules::features::StringFeature::new(
                            trimmed.trim_end_matches('\x00'),
                            "",
                        )?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    pub fn extract_insn_bytes_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];

        for data_ref in insn.get_data_refs(self.report())? {
            for v in derefs(self.report(), &data_ref)? {
                let bytes_read = read_bytes(self.report(), &v, 0x100)?;
                if all_zeros(bytes_read)? || is_padding(bytes_read)? {
                    continue;
                }
                res.push((
                    crate::rules::features::Feature::Bytes(
                        crate::rules::features::BytesFeature::new(bytes_read, "")?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    fn parse_operand_to_number(&self, operand: &str) -> Option<i128> {
        let operand = operand.trim();

        // case 1: if operand is like 0x1234
        if let Some(x) = operand.strip_prefix("0x") {
            return i128::from_str_radix(x, 16).ok();
        }

        // case 2: if operand is like 1234h
        if let Some(stripped_operand) = operand.strip_suffix('h') {
            // Intel convention: an h-suffixed hex literal must start
            // with a digit (0ABh). Without this check the register
            // names ah/bh/ch/dh parsed as 0xA/0xB/0xC/0xD (#24).
            if stripped_operand
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
            {
                return i128::from_str_radix(stripped_operand, 16).ok();
            }
        }

        // case 3: if operand is like +0x1234
        //if start with sign apply this logic
        if operand.starts_with('-') || operand.starts_with('+') {
            if let Some(captures) = RE_NUMBER_HEX.captures(operand) {
                let sign = &captures["sign"];
                let number = &captures["num"];
                let value = i128::from_str_radix(number, 16).ok()?;
                return Some(if sign == "-" { -value } else { value });
            }
            if let Some(captures) = RE_NUMBER_INT.captures(operand) {
                let sign = &captures["sign"];
                let number = &captures["num"];
                let value = number.parse::<i128>().ok()?;
                return Some(if sign == "-" { -value } else { value });
            }
        }

        // case 4: if operand is like 1234
        if let Ok(val) = operand.parse::<i128>() {
            return Some(val);
        }

        // case 5: bare hex without 0x/h, e.g. 0dead. Must start with a
        // digit — otherwise hex-looking labels (beef, face, add) parse
        // as numbers (#24).
        if operand.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return i128::from_str_radix(operand, 16).ok();
        }
        None
    }

    pub fn extract_insn_number_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if let Some(o) = insn.format_operands() {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();

            if insn.mnemonic_enum() == Mnemonic::Add
                && ["esp", "rsp"].contains(&operands[0].as_str())
            {
                return Ok(vec![]);
            }

            for (i, operand) in operands.iter().enumerate() {
                if let Some(s) = self.parse_operand_to_number(operand) {
                    if s >= 0 {
                        res.push((
                            crate::rules::features::Feature::Number(
                                crate::rules::features::NumberFeature::new(f.bitness, &s, "")?,
                            ),
                            insn.offset,
                        ));
                    } else {
                        // Negative immediates are emitted as their
                        // unsigned interpretation at the function's
                        // bitness — masking to u32 truncated x64 values
                        // (mov rax, -1 → 0xFFFFFFFF instead of
                        // 0xFFFFFFFFFFFFFFFF) (#24).
                        let masked_value = mask_to_bitness(s, f.bitness);
                        res.push((
                            crate::rules::features::Feature::Number(
                                crate::rules::features::NumberFeature::new(
                                    f.bitness,
                                    &masked_value,
                                    "",
                                )?,
                            ),
                            insn.offset,
                        ));
                    }
                    res.push((
                        crate::rules::features::Feature::OperandNumber(
                            crate::rules::features::OperandNumberFeature::new(&i, &s, "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_api_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        let va = self.report().base_addr + insn.offset;

        if let Some((dll, api)) = f.apirefs.get(&insn.offset) {
            if let Some(api_name) = api {
                let highest_addr = self.find_highest_address_for_symbol(api_name);
                if let Some(addr) = highest_addr {
                    self.push_api_features(&mut res, dll, api, addr)?;
                } else {
                    self.push_api_features(&mut res, dll, api, va)?;
                }
            } else {
                self.push_api_features(&mut res, dll, api, va)?;
            }
            return Ok(res);
        }

        if let Some(targets) = f.outrefs.get(&insn.offset) {
            let mut api_candidates = Vec::new();

            for target in targets.iter().rev() {
                if let Some((dll, api)) = self.report().addr_to_api.get(target) {
                    api_candidates.push((*target, dll.clone(), api.clone()));
                }
            }

            if !api_candidates.is_empty() {
                let best_candidate = api_candidates
                    .iter()
                    .max_by_key(|(addr, _, _)| *addr)
                    .unwrap();
                let (mut best_addr, dll, api) = best_candidate.clone();

                // FIX: api es Option<String>, desenvolverlo
                if let Some(api_name) = &api {
                    if let Some(highest) = self.find_highest_address_for_symbol(api_name) {
                        best_addr = highest;
                    }
                }

                self.push_api_features(&mut res, &dll, &api, best_addr)?;
                return Ok(res);
            }
        }

        // fallback: thunk chain resolution
        let mut current_function = f;
        let mut current_instruction = insn;

        for _ in 0..5 {
            if let Some(targets) = current_function.outrefs.get(&current_instruction.offset) {
                if targets.len() != 1 {
                    break;
                }

                let chain_target = targets[0];
                let referenced_function = match self.report().get_function(chain_target) {
                    Ok(func) => func,
                    Err(_) => break,
                };

                if referenced_function.is_api_thunk()? {
                    if let Some((dll, api)) = referenced_function.apirefs.get(&chain_target) {
                        if let Some(api_name) = api {
                            if let Some(highest) = self.find_highest_address_for_symbol(api_name) {
                                self.push_api_features(&mut res, dll, api, highest)?;
                                return Ok(res);
                            }
                        }

                        self.push_api_features(&mut res, dll, api, chain_target)?;
                    }
                    break;
                }

                if referenced_function.get_num_instructions()? == 1
                    && referenced_function.get_num_outrefs()? == 1
                {
                    current_function = referenced_function;
                    current_instruction = referenced_function.get_instructions()?[0];
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(res)
    }

    fn find_highest_address_for_symbol(&self, symbol_name: &str) -> Option<u64> {
        let mut addresses = Vec::new();

        for (addr, (_, api)) in &self.report().addr_to_api {
            if let Some(api_name) = api {
                if api_name == symbol_name {
                    addresses.push(*addr);
                }
            }
        }

        addresses.into_iter().max()
    }

    fn push_api_features(
        &self,
        res: &mut Vec<(crate::rules::features::Feature, u64)>,
        dll: &Option<String>,
        api: &Option<String>,
        va: u64,
    ) -> Result<()> {
        for name in generate_symbols(dll, api)? {
            res.push((
                crate::rules::features::Feature::Api(crate::rules::features::ApiFeature::new(
                    &name, "",
                )?),
                va,
            ));
        }
        Ok(())
    }

    fn find_embedded_pe_headers(pbytes: &[u8]) -> Vec<(u64, u64, u8)> {
        let mut results = Vec::new();
        let start_offset = 64usize;
        let end = pbytes.len();

        let end_safe_zone = end.saturating_sub(0x40);
        let mut current_offset = start_offset;
        while current_offset < end_safe_zone {
            if pbytes[current_offset + 0x3E] == pbytes[current_offset + 0x3F] {
                let key = pbytes[current_offset + 0x3E];

                if pbytes[current_offset] ^ key == b'M' && pbytes[current_offset + 1] ^ key == b'Z'
                {
                    let e_lfanew = u32::from_le_bytes([
                        pbytes[current_offset + 0x3C] ^ key,
                        pbytes[current_offset + 0x3D] ^ key,
                        0,
                        0,
                    ]) as usize;

                    if current_offset + e_lfanew + 0x18 <= end_safe_zone
                        && pbytes[current_offset + e_lfanew] ^ key == b'P'
                        && pbytes[current_offset + e_lfanew + 1] ^ key == b'E'
                        && pbytes[current_offset + e_lfanew + 2] == key
                        && pbytes[current_offset + e_lfanew + 3] == key
                    {
                        results.push((
                            current_offset as u64,
                            (current_offset + e_lfanew) as u64,
                            key,
                        ));
                        current_offset = current_offset + e_lfanew + 4;
                        continue;
                    }
                }
            }
            current_offset += 1;
        }

        results
    }

    // 0.3.21: removed `_carve_pe`, the free-fn `is_mov_imm_to_stack`
    // (replaced by smda's `Instruction::get_printable_len`), and
    // `get_operands` (operand-string parser, no longer needed now
    // that capa walks the typed iced operands via `format_operands()`).
    // 0.4.2: removed `xor_static` / `xor_with_key` — dead helpers for
    // embedded-PE carving; `find_embedded_pe_headers` does the XOR
    // inline.
}

fn clean_dll_name(dll_name: &str) -> String {
    let mut clean = dll_name.to_string();

    // Remove common prefixes
    if clean.ends_with(".so.6") {
        clean = clean[..clean.len() - 5].to_string();
    } else if clean.ends_with(".so") {
        clean = clean[..clean.len() - 3].to_string();
    } else if clean.ends_with(".dll") {
        clean = clean[..clean.len() - 4].to_string();
    }

    clean
}

pub fn generate_symbols(dll: &Option<String>, symbol: &Option<String>) -> Result<Vec<String>> {
    let mut res = vec![];
    let symbol_name = symbol
        .clone()
        .ok_or_else(|| Error::InvalidRule(line!(), file!().to_string()))?;

    // Add simple symbol if it does not start with #
    if !symbol_name.starts_with('#') {
        res.push(symbol_name.clone());
    }

    // DLL.symbol
    if let Some(dll_ref) = dll {
        let dll_clean = clean_dll_name(dll_ref);
        let dll_symbol = format!("{}.{}", dll_clean, symbol_name);
        if dll_symbol != symbol_name {
            res.push(dll_symbol);
        }
    }

    // A/W variants para APIs Windows
    if !symbol_name.starts_with("_Z") && (symbol_name.ends_with('A') || symbol_name.ends_with('W'))
    {
        let base_name = &symbol_name[..symbol_name.len() - 1];
        if !res.contains(&base_name.to_string()) {
            res.push(base_name.to_string());
        }
        if let Some(dll_ref) = dll {
            let dll_clean = clean_dll_name(dll_ref);
            res.push(format!("{}.{}", dll_clean, base_name));
        }
    }
    Ok(res)
}

/// Unsigned interpretation of a negative immediate at the given bitness
/// (#24): `-1` is `0xFFFFFFFF` on 32-bit and `0xFFFFFFFFFFFFFFFF` on
/// 64-bit. Previously the mask was always u32, truncating x64 values.
fn mask_to_bitness(value: i128, bitness: u32) -> i128 {
    match bitness {
        64 => (value as u64) as i128,
        _ => (value as u32) as i128,
    }
}

pub fn derefs(report: &DisassemblyReport<'_>, p: &u64) -> Result<Vec<u64>> {
    let mut res = vec![];
    let mut depth = 0;
    let mut pp = *p;
    // Pointers are bitness-sized: reading only 4 bytes on x64 truncates
    // VAs above 4 GiB (e.g. 0x140000000-based images) and kills every
    // chain after the first hop.
    let ptr_size = (report.bitness / 8).clamp(4, 8) as usize;
    loop {
        if !report.is_addr_within_memory_image(&pp)? {
            break;
        }
        res.push(pp);

        let bytes_ = read_bytes(report, &pp, ptr_size)?;
        if bytes_.len() < ptr_size {
            // Truncated read at the end of the image — stop the chain.
            break;
        }
        let val = bytes_
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc | ((*b as u64) << (8 * i)));
        // sanity: pointer points to self
        if val == pp {
            break;
        }
        //sanity: avoid chains of pointers that are unreasonably deep
        depth += 1;
        if depth > 10 {
            break;
        }
        pp = val;
    }
    Ok(res)
}

/// 0.3.21: smda 0.4.0 replaced the owned `report.buffer: Vec<u8>` with
/// the borrowed `binary_info.raw_data: &[u8]`. All readers go through
/// that now — same semantics, no clone.
pub fn read_bytes<'a>(
    report: &'a DisassemblyReport<'_>,
    offset: &u64,
    num_bytes: usize,
) -> Result<&'a [u8]> {
    let raw = report.binary_info.raw_data;
    let rva = offset - report.base_addr;
    let buffer_end = raw.len();
    let mut end_of_string = rva + num_bytes as u64;

    if end_of_string > buffer_end as u64 {
        end_of_string = buffer_end as u64;
    }
    if rva > buffer_end as u64 {
        return Err(Error::BufferOverflowError);
    }
    Ok(&raw[rva as usize..end_of_string as usize])
}

pub fn read_string(report: &DisassemblyReport<'_>, offset: &u64) -> Result<String> {
    let alen = detect_ascii_len(report, offset)?;
    if alen > 1 {
        let bytes = read_bytes(report, offset, alen)?;
        return Ok(std::str::from_utf8(bytes)?.to_string());
    }
    let ulen = detect_unicode_len(report, offset)?;
    if ulen > 2 {
        let bytes = read_bytes(report, offset, ulen)?;
        let utf16_units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|arr| u16::from_le_bytes([arr[0], arr[1]]))
            .collect();
        return Ok(std::string::String::from_utf16(&utf16_units)?);
    }
    Ok("".to_string())
}

pub fn detect_ascii_len(report: &DisassemblyReport<'_>, offset: &u64) -> Result<usize> {
    let raw = report.binary_info.raw_data;
    let buffer_len = raw.len() as u64;
    let rva = offset.checked_sub(report.base_addr).ok_or_else(|| {
        std::io::Error::other("Offset is out of bounds relative to the base address")
    })?;

    if rva as usize >= raw.len() {
        Err(std::io::Error::other("RVA is beyond buffer length"))?;
    }

    let ascii_len = raw[rva as usize..]
        .iter()
        .take_while(|&&ch| ch != 0 && ch.is_ascii())
        .take_while(|&&ch| b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ \r\n".contains(&ch))
        .count();

    if rva + ascii_len as u64 >= buffer_len {
        Err(std::io::Error::other(
            "Buffer overflow detected while detecting ASCII length",
        ))?;
    }

    Ok(ascii_len)
}

pub fn detect_unicode_len(report: &DisassemblyReport<'_>, offset: &u64) -> Result<usize> {
    let raw = report.binary_info.raw_data;
    let mut unicode_len = 0;
    let mut rva = offset - report.base_addr;
    if (rva as usize) + 1 >= raw.len() {
        return Ok(0);
    }
    let mut ch = raw[rva as usize];
    let mut second_char = raw[rva as usize + 1];
    while ch < 127 && b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ \r\n".contains(&ch) && second_char == 0 {
        unicode_len += 2;
        rva += 2;
        if (rva as usize) + 1 >= raw.len() {
            return Ok(0);
        }
        ch = raw[rva as usize];
        second_char = raw[rva as usize + 1];
    }
    if ch == 0 && second_char == 0 {
        return Ok(unicode_len);
    }
    Ok(0)
}

pub fn all_zeros(bytez: &[u8]) -> Result<bool> {
    let mut res = true;
    for b in bytez {
        res &= b == &0;
    }
    Ok(res)
}

pub fn is_padding(bytez: &[u8]) -> Result<bool> {
    Ok(bytez.iter().all(|&b| b == 0x00 || b == 0xFF))
}

pub fn is_security_cookie(f: &Function, insn: &Instruction) -> Result<bool> {
    //# security cookie check should use SP or BP
    if let Some(o) = insn.format_operands() {
        let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
        if !["esp", "ebp", "rsp", "rbp"].contains(&&operands[1][..]) {
            return Ok(false);
        }
        for (index, block) in f.get_blocks()?.iter().enumerate() {
            //# expect security cookie init in first basic block within first bytes (instructions)
            //        block_instructions = [i for i in block.get_instructions()?]
            if index == 0 && insn.offset < (block.1[0].offset + 0x40) {
                //}SECURITY_COOKIE_BYTES_DELTA
                return Ok(true);
            }
            //# ... or within last bytes (instructions) before a return
            let last = &block.1[block.1.len() - 1];
            if last.flow_control() == FlowControl::Return && insn.offset > (last.offset - 0x40) {
                //SECURITY_COOKIE_BYTES_DELTA
                return Ok(true);
            }
        }
    }
    Ok(false)
}

// 0.4.2: removed `to_u16` — pub helper that converted byte slices to
// u16 vectors, dead since the UTF-16 string scanner was rewritten to
// work directly on `&[u8]` chunks without an intermediate Vec<u16>.

fn extract_file_strings(buf: &[u8]) -> Result<Vec<(String, u64)>> {
    let mut res = vec![];
    for (s, a) in extract_ascii_strings(buf, 4)? {
        res.push((s, a));
    }
    for (s, a) in extract_unicode_strings(buf, 4)? {
        res.push((s, a));
    }
    Ok(res)
}

const ASCII_BYTE: &str = r##" !"#$%&'()*+,-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]^_\x60abcdefghijklmnopqrstuvwxyz{|}\\~\t"##;
const SLICE_SIZE: usize = 4096;

lazy_static::lazy_static! {
    static ref REPEATS: Vec<u8> = vec![b'A', 0, 0xfe, 0xff];
}

pub fn extract_ascii_strings(data: &[u8], min_length: usize) -> Result<Vec<(String, u64)>> {
    if data
        .first()
        .is_some_and(|&b| REPEATS.contains(&b) && buf_filled_with(data, &b))
    {
        return Ok(vec![]);
    }
    let re = regex::bytes::Regex::new(&format!(r##"([{}]{{{},}})"##, ASCII_BYTE, min_length))?;
    Ok(re
        .find_iter(data)
        .map(|d| {
            (
                std::string::String::from_utf8_lossy(d.as_bytes()).to_string(),
                d.start() as u64,
            )
        })
        .collect())
}
pub fn extract_unicode_strings(data: &[u8], min_length: usize) -> Result<Vec<(String, u64)>> {
    if data.len() < min_length * 2 {
        return Ok(vec![]);
    }

    let mut results = Vec::new();

    // regex pattern for UTF-16LE and UTF-16BE
    let re_le = regex::bytes::Regex::new(&format!(r"((?:[\x20-\x7E]\x00){{{},}})", min_length))?;
    let re_be = regex::bytes::Regex::new(&format!(r"((?:\x00[\x20-\x7E]){{{},}})", min_length))?;

    // UTF-16LE
    for mat in re_le.find_iter(data) {
        let matched_bytes = mat.as_bytes();
        let utf16_units = matched_bytes
            .chunks(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<u16>>();
        if let Ok(decoded_string) = String::from_utf16(&utf16_units) {
            results.push((decoded_string, mat.start() as u64));
        }
    }

    // UTF-16BE
    for mat in re_be.find_iter(data) {
        let matched_bytes = mat.as_bytes();
        let utf16_units = matched_bytes
            .chunks(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<u16>>();
        if let Ok(decoded_string) = String::from_utf16(&utf16_units) {
            results.push((decoded_string, mat.start() as u64));
        }
    }

    // NOTE (#24): there used to be a third, plain-ASCII pass here
    // (`[\x20-\x7E]{4,}`) — it duplicated `extract_ascii_strings`,
    // which `extract_file_strings` runs alongside this function, so
    // every ASCII string was emitted twice. ASCII stays with
    // `extract_ascii_strings`; this function is UTF-16 only.

    let cleaned_results = results
        .into_iter()
        .filter(|(s, _)| !s.trim().is_empty())
        .map(|(s, pos)| (clean_string(&s), pos))
        .collect::<Vec<(String, u64)>>();

    Ok(cleaned_results)
}

fn clean_string(s: &str) -> String {
    s.replace('\u{0000}', "")
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .collect()
}

fn buf_filled_with(data: &[u8], character: &u8) -> bool {
    let dupe_chunk = vec![*character; SLICE_SIZE];
    let mut offset = 0;
    while offset < data.len() {
        let new_chunk = if offset + SLICE_SIZE >= data.len() {
            data[offset..].to_vec()
        } else {
            data[offset..offset + SLICE_SIZE].to_vec()
        };
        if dupe_chunk[..new_chunk.len()] != new_chunk {
            return false;
        }
        offset += SLICE_SIZE;
    }
    true
}

/// 0.5.1: distinguish macOS / iOS / tvOS / watchOS Mach-O.
///
/// Apple-Silicon Macs and modern iOS devices both ship
/// `CPU_TYPE_ARM64` binaries — cputype alone can't tell them apart.
/// The load commands do: `LC_BUILD_VERSION` (Xcode-10+) carries a
/// `platform` field with `PLATFORM_MACOS (1)` / `PLATFORM_IOS (2)`
/// / etc. Legacy binaries use the older `LC_VERSION_MIN_*` family
/// where the load-command id (`cmd`) itself encodes the target OS.
///
/// We honour both. Order of resolution:
///   1. Walk `LC_BUILD_VERSION.platform` — modern, authoritative.
///   2. Fall back to `LC_VERSION_MIN_*` (cmd id → OS).
///   3. Default: `Os::MACOS` (matches the 0.5.0 placeholder for
///      binaries with no version commands at all — typical of
///      hand-crafted / very old Mach-O).
///
/// Platform-id taxonomy (Apple `<mach-o/loader.h>`):
///   PLATFORM_MACOS              = 1   → Os::MACOS
///   PLATFORM_IOS                = 2   → Os::IOS
///   PLATFORM_TVOS               = 3   → Os::IOS  (tvOS shares
///                                                  iOS userland)
///   PLATFORM_WATCHOS            = 4   → Os::IOS
///   PLATFORM_BRIDGEOS           = 5   → Os::IOS
///   PLATFORM_MACCATALYST        = 6   → Os::MACOS (Catalyst apps
///                                                   run on macOS)
///   PLATFORM_IOSSIMULATOR       = 7   → Os::IOS
///   PLATFORM_TVOSSIMULATOR      = 8   → Os::IOS
///   PLATFORM_WATCHOSSIMULATOR   = 9   → Os::IOS
///   PLATFORM_DRIVERKIT          = 10  → Os::MACOS
///
/// Fat binaries: first parseable Mach-O slice wins (matches the
/// rest of capa-rs's fat handling — security/macho.rs and smda's
/// `extract_macho` both iterate in fat order).
pub(crate) fn classify_macho_os(buf: &[u8]) -> Result<Os> {
    use goblin::mach::{Mach, load_command::CommandVariant};

    // PLATFORM_* constants (Apple <mach-o/loader.h>).
    const PLATFORM_MACOS: u32 = 1;
    const PLATFORM_IOS: u32 = 2;
    const PLATFORM_TVOS: u32 = 3;
    const PLATFORM_WATCHOS: u32 = 4;
    const PLATFORM_BRIDGEOS: u32 = 5;
    const PLATFORM_MACCATALYST: u32 = 6;
    const PLATFORM_IOSSIMULATOR: u32 = 7;
    const PLATFORM_TVOSSIMULATOR: u32 = 8;
    const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
    const PLATFORM_DRIVERKIT: u32 = 10;

    // LC_VERSION_MIN_* command ids (Apple <mach-o/loader.h>) —
    // listed for documentation; goblin splits these into separate
    // CommandVariant variants so we don't need the cmd id at
    // runtime.
    //   LC_VERSION_MIN_MACOSX     = 0x24
    //   LC_VERSION_MIN_IPHONEOS   = 0x25
    //   LC_VERSION_MIN_TVOS       = 0x2f
    //   LC_VERSION_MIN_WATCHOS    = 0x30

    fn classify(slice: &goblin::mach::MachO) -> Os {
        // 1. Prefer LC_BUILD_VERSION (Xcode-10+ binaries — the
        //    common case on anything built since ~2018).
        for lc in &slice.load_commands {
            if let CommandVariant::BuildVersion(bv) = &lc.command {
                return match bv.platform {
                    PLATFORM_MACOS | PLATFORM_MACCATALYST | PLATFORM_DRIVERKIT => Os::MACOS,
                    PLATFORM_IOS
                    | PLATFORM_TVOS
                    | PLATFORM_WATCHOS
                    | PLATFORM_BRIDGEOS
                    | PLATFORM_IOSSIMULATOR
                    | PLATFORM_TVOSSIMULATOR
                    | PLATFORM_WATCHOSSIMULATOR => Os::IOS,
                    // Unknown platform id from a future SDK — most
                    // future Apple platforms are iOS-family, but
                    // default to MACOS to keep the surface
                    // conservative (matches the 0.5.0 placeholder).
                    _ => Os::MACOS,
                };
            }
        }
        // 2. Fall back to LC_VERSION_MIN_* (pre-Xcode-10). Goblin
        // splits these into four separate CommandVariant variants
        // (one per Apple OS) instead of a single VersionMin variant
        // with a cmd field — so we match on the variant directly.
        for lc in &slice.load_commands {
            match &lc.command {
                CommandVariant::VersionMinMacosx(_) => return Os::MACOS,
                CommandVariant::VersionMinIphoneos(_)
                | CommandVariant::VersionMinTvos(_)
                | CommandVariant::VersionMinWatchos(_) => return Os::IOS,
                _ => {}
            }
        }
        // 3. No version commands — default to MACOS.
        Os::MACOS
    }

    match goblin::Object::parse(buf)? {
        goblin::Object::Mach(Mach::Binary(m)) => Ok(classify(&m)),
        goblin::Object::Mach(Mach::Fat(fat)) => {
            for (i, _arch) in fat.iter_arches().enumerate() {
                if let Ok(goblin::mach::SingleArch::MachO(m)) = fat.get(i) {
                    return Ok(classify(&m));
                }
            }
            // No parseable slice — fall back to MACOS.
            Ok(Os::MACOS)
        }
        _ => Ok(Os::MACOS),
    }
}

// 0.5.2 (upstream parity #2997): integration test for the
// `xor reg, reg` → `Number(0)` correctness fix. This is the first
// extractor-level test in the crate — placed inline rather than in
// `tests/` so we keep crate-internal access to the `Mnemonic` import,
// the `SmdaExtractor::report()` accessor, and the public
// `extract_insn_nzxor_characteristic_features` method without
// having to widen any visibility.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::features::{CharacteristicFeature, Feature, NumberFeature};

    /// Walks every instruction in `data/Demo64.dll`, finds any
    /// `xor reg, reg` (or `xorpd`/`xorps`/`pxor`) where both operands
    /// are the same register, and asserts that
    /// `extract_insn_nzxor_characteristic_features` emits `Number(0)`
    /// at the instruction and does NOT emit `Characteristic("nzxor")`
    /// — mirroring the upstream Python parity-test pattern from
    /// `mandiant/capa#2997`.
    ///
    /// Fails loudly if no self-XOR site is discovered, so we can't pass
    /// vacuously on a binary that happens to contain none.
    #[test]
    fn upstream_parity_2997_xor_self_emits_number_zero() {
        let path = "data/Demo64.dll";
        let bytes = std::fs::read(path).unwrap_or_else(|e| {
            panic!("test fixture missing: {path}: {e}");
        });
        let extractor = Extractor::new(path, false, false, &bytes).expect("smda parse Demo64.dll");

        let report = extractor.report();
        let functions = report.get_functions().expect("smda get_functions");

        // PartialEq on NumberFeature / CharacteristicFeature is value-only
        // (see `impl PartialEq for NumberFeature` in src/rules/features.rs),
        // so the bitness / description we construct here are irrelevant for
        // the assertion — only the value matters.
        let want_zero =
            Feature::Number(NumberFeature::new(64, &0_i128, "").expect("NumberFeature::new"));
        let want_nzxor = Feature::Characteristic(
            CharacteristicFeature::new("nzxor", "").expect("CharacteristicFeature::new"),
        );

        let mut sites_checked = 0_usize;
        for smda_func in functions.values() {
            let Ok(blocks) = smda_func.get_blocks() else {
                continue;
            };
            for instrs in blocks.values() {
                for insn in instrs {
                    // Mirror the extractor's own self-XOR detection so the
                    // test exercises the exact branch the fix added a
                    // `Number(0)` push to.
                    if !matches!(
                        insn.mnemonic_enum(),
                        Mnemonic::Xor | Mnemonic::Xorpd | Mnemonic::Xorps | Mnemonic::Pxor
                    ) {
                        continue;
                    }
                    let Some(operand_str) = insn.format_operands() else {
                        continue;
                    };
                    let parts: Vec<&str> = operand_str.split(',').map(|s| s.trim()).collect();
                    if parts.len() < 2 || parts[0] != parts[1] {
                        continue;
                    }

                    sites_checked += 1;
                    let res = extractor
                        .extract_insn_nzxor_characteristic_features(smda_func, insn)
                        .expect("extract_insn_nzxor_characteristic_features");

                    assert!(
                        res.iter().any(|(f, _)| f == &want_zero),
                        "self-XOR at {:#x} did not emit Number(0); features were {:?}",
                        insn.offset,
                        res.iter().map(|(f, _)| f).collect::<Vec<_>>(),
                    );
                    assert!(
                        res.iter().all(|(f, _)| f != &want_nzxor),
                        "self-XOR at {:#x} incorrectly tagged as nzxor",
                        insn.offset,
                    );
                }
            }
        }

        assert!(
            sites_checked > 0,
            "no `xor reg, reg` site found in {path} — \
             the test cannot verify the fix; switch the fixture to a \
             binary that contains at least one self-XOR.",
        );
        eprintln!("upstream parity #2997: verified {sites_checked} self-XOR site(s) in {path}");
    }

    /// Regression test for marirs/capa-rs#16: `derefs` must read
    /// bitness-sized pointers. On x64, reading only 4 bytes truncates VAs
    /// above 4 GiB and stops every pointer chain after the first hop.
    #[test]
    fn derefs_follows_64bit_pointers() {
        let base: u64 = 0x140000000;
        let mut data = vec![0u8; 0x100];
        data[0x20..0x28].copy_from_slice(&(base + 0x80).to_le_bytes());
        data[0x80..0x88].copy_from_slice(&(base + 0xf0).to_le_bytes());
        // null pointer at the end of the chain -> outside the image -> stop
        let extractor =
            Extractor::from_buffer(&data, base, 64, false, false).expect("parse buffer");
        let chain = derefs(extractor.report(), &(base + 0x20)).expect("derefs");
        assert_eq!(chain, vec![base + 0x20, base + 0x80, base + 0xf0]);
    }

    /// Same chain on a 32-bit image: pointers are 4 bytes wide.
    #[test]
    fn derefs_follows_32bit_pointers() {
        let base: u64 = 0x400000;
        let mut data = vec![0u8; 0x100];
        data[0x20..0x24].copy_from_slice(&((base + 0x80) as u32).to_le_bytes());
        data[0x80..0x84].copy_from_slice(&0u32.to_le_bytes());
        let extractor =
            Extractor::from_buffer(&data, base, 32, false, false).expect("parse buffer");
        let chain = derefs(extractor.report(), &(base + 0x20)).expect("derefs");
        assert_eq!(chain, vec![base + 0x20, base + 0x80]);
    }

    /// Regression test for marirs/capa-rs#16: UTF-16BE units were decoded
    /// with swapped bytes, turning every BE string into non-ASCII garbage
    /// that `clean_string` then dropped.
    #[test]
    fn utf16be_strings_decode_without_byte_swap() {
        // "WIDE" as UTF-16BE, after 8 bytes of padding. Note: the same
        // byte run also matches the UTF-16LE pattern one byte later, so
        // assert on the offset too — only the BE decode can start at 8.
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&[0x00, b'W', 0x00, b'I', 0x00, b'D', 0x00, b'E']);
        let strings = extract_unicode_strings(&data, 4).expect("extract_unicode_strings");
        assert!(
            strings.iter().any(|(s, off)| s == "WIDE" && *off == 8),
            "UTF-16BE string not decoded at offset 8: {strings:?}"
        );
    }

    /// #24: register names (ah/bh/ch/dh) and hex-looking labels must not
    /// parse as numbers; h-suffixed and bare hex literals starting with
    /// a digit still do.
    #[test]
    fn registers_and_labels_are_not_numbers() {
        let data = vec![0u8; 0x10];
        let extractor =
            Extractor::from_buffer(&data, 0x1000, 64, false, false).expect("parse buffer");
        // Pre-#24 these parsed as 0xA / 0xB / 0xC / 0xD via the 'h' strip.
        for reg in ["ah", "bh", "ch", "dh"] {
            assert_eq!(extractor.parse_operand_to_number(reg), None, "{reg}");
        }
        // Hex-looking labels parsed via the bare-hex fallback.
        for label in ["beef", "face", "add"] {
            assert_eq!(extractor.parse_operand_to_number(label), None, "{label}");
        }
        // Legitimate literals keep working.
        assert_eq!(extractor.parse_operand_to_number("0ABh"), Some(0xAB));
        assert_eq!(extractor.parse_operand_to_number("1234h"), Some(0x1234));
        assert_eq!(extractor.parse_operand_to_number("0dead"), Some(0xdead));
        assert_eq!(extractor.parse_operand_to_number("0x1234"), Some(0x1234));
        assert_eq!(extractor.parse_operand_to_number("1234"), Some(1234));
    }

    /// #24: negative immediates are emitted as their unsigned
    /// interpretation at the function's bitness (was always u32).
    #[test]
    fn negative_immediates_mask_at_bitness() {
        assert_eq!(mask_to_bitness(-1, 32), 0xFFFF_FFFF);
        assert_eq!(mask_to_bitness(-1, 64), 0xFFFF_FFFF_FFFF_FFFF);
    }

    /// #24: the UTF-16 extractor must not also emit plain ASCII strings —
    /// `extract_file_strings` runs `extract_ascii_strings` alongside it,
    /// so every ASCII string used to appear twice.
    #[test]
    fn unicode_extractor_does_not_duplicate_ascii() {
        let data = b"HELLO WORLD";
        assert!(
            extract_unicode_strings(data, 4)
                .expect("unicode")
                .is_empty(),
            "ASCII string leaked into the UTF-16 extractor"
        );
        assert_eq!(
            extract_ascii_strings(data, 4).expect("ascii")[0].0,
            "HELLO WORLD"
        );
    }
}
