# Changelog

All notable changes to **capa** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.21] — 2026-05-25 — smda 0.5 + dnfile 0.4 migration (additive)

Patch release. No public-API breaks from 0.3.20 — `FileCapabilities::from_file`
keeps its existing signature. Internal extractors are rewritten to consume
the modern smda / dnfile surfaces.

### Dependencies

- **`smda` 0.2 → 0.5.x.** Three minor families of upstream smda:
  - **Security fixes**: `.pdata` RVA conversion bug, ELF `sh_addralign=0`
    divide-by-zero, ELF unbounded mapped-allocation, ELF `p_vaddr+p_memsz`
    overflow, PE `map_binary` u32 overflow, pclntab attacker-controlled
    offset arithmetic hardening, Mach-O 32-bit-host `u64 as usize`
    truncation.
  - **Decoder swap**: capstone → iced-x86 (~2-3× faster, no C/C++ dep).
  - **Zero-copy refactor**: `DisassemblyReport<'a>` borrows the input bytes;
    capa-rs absorbs this via `ouroboros` so the public `Extractor::new`
    signature is preserved.
  - **New capabilities**: Mach-O loader, Go pclntab parser, MinGW DWARF
    resolver, Delphi VMT scanner, Rust symbol demangling, function-level
    PIC + opcode hashes, dominator tree, raw-buffer entry point.
- **`dnfile` 0.2 → 0.4.x.** Zero-copy `DnPe<'a>`, resource module,
  `AssemblyInfo` helper, accumulated security fixes.
- Added `ouroboros = "0.18"` — self-referential `Extractor` wrapper around
  the owned input buffer + borrowed smda / dnfile report.
- Added `iced-x86 = "1"` — direct dep (was transitive via smda). Lets
  capa's smda extractor compare against typed `Mnemonic` / `FlowControl`
  enums on the hot path instead of formatting mnemonic strings per
  instruction.
- Bumped `petgraph = "0.7" → "0.8"`, `scroll = "0.12" → "0.13"`.

### Fixed

- **Function-name pipeline wired up.** `Feature::FunctionName` rule matches
  now fire on Go pclntab names, MinGW DWARF function names, Rust-demangled
  ELF symbols, and Delphi VMT class methods. The `extract_file_function_names`
  call in `src/extractor/smda.rs` was commented out with a "NOTE not sure"
  marker — fixed.

### Changed

- **Edition `2021` → `2024`**, MSRV bumped to **1.95** (smda's MSRV).
- **`Extractor::new(path, …, data: &Vec<u8>)`** → **`data: &[u8]`** —
  callers passing `&Vec<u8>` continue to compile via auto-deref. Internal
  `get_file_extractors` widened identically.
- **Per-instruction string allocations eliminated.** `insn.mnemonic` /
  `insn.operands` field reads (21+ call sites) replaced with typed
  `is_call()` / `is_jmp()` / `mnemonic_enum() == Mnemonic::X` accessors.
  `format_mnemonic()` is only called where the literal string is
  actually needed (the `MnemonicFeature` constructor).
- **Duplicated stack-string detection removed.** `is_mov_imm_to_stack` +
  `get_operands` free functions deleted; the trait method now delegates
  to smda's `Instruction::get_printable_len() > 0`.
- **Dead `_carve_pe`** removed from `src/extractor/smda.rs`.

### Internal / CI

- **`#[allow(clippy::mutable_key_type, collapsible_if, collapsible_match)]`**
  at the crate root, with rationale. The first is a false positive on
  regex's internal `Pool<Cache>`; the latter two are noisy 2024-edition
  let-chain modernizations across legacy code.
- **CI rewrite.** Four legacy `actions-rs/cargo@v1` workflows
  (`linux_arm7.yml`, `linux_x86-64.yml`, `macos.yml`, `windows.yml`)
  replaced with smda-style:
  - `ci.yml`: `cargo fmt --check` + `cargo clippy --all-targets
    --all-features -- -D warnings` + matrix `cargo test` on
    stable / beta / 1.95 across Linux / macOS / Windows + `cargo doc`
    + MSRV check.
  - `release.yml`: on `v*.*.*` tag push, runs verify → packages
    `cargo package` `.crate` + git source `.tar.gz` + SHA-256 sums →
    creates GitHub release. **No auto `cargo publish`** — publishing
    stays a manual step.

### Migration notes for downstream consumers

`FileCapabilities::from_file(path, rules, ha, rt, cb, map_features, sec_opts)`
is unchanged. If you were constructing the smda or dnfile extractors
directly (`extractor::smda::Extractor::new`, `extractor::dnfile::Extractor::new`),
the signatures still accept the same arguments — `&Vec<u8>` continues to
auto-deref to `&[u8]`. No source changes required at call sites.
