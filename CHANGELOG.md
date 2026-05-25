# Changelog

All notable changes to **capa** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] — 2026-05-26 — Python-capa rule-loader parity (P0 + P1)

Patch release. No public-API breaks from 0.4.0. Closes the rule-loader
parity gaps the 0.3.21 → 0.4.0 work surfaced: two `capa-rules` files
that previously failed to load with `InvalidRule(...)` errors now load
cleanly, and `lib: true` building-block rules no longer pollute the
final capability output.

### Fixed

- **Bare `property:` feature key.** `parse_feature_type` had arms for
  `property/read` and `property/write` but rejected the unqualified
  `property` form Python capa uses in `count(property(...))` contexts.
  Unblocks `nursery/check-for-time-delay-in-dotnet.yml` and any future
  count-context property rule. Reference:
  `capa/rules/__init__.py:446`.
- **Cross-scope subscope at file level.** `build_statements` rejected
  `instruction:` blocks inside `static: file` rules with hardcoded
  per-scope checks. Replaced with Python's ordered-list compatibility
  helper (`STATIC_SCOPE_ORDER = [file, function, basic_block, instruction]`):
  any subscope at or below the current scope is now allowed. Unblocks
  `host-interaction/service/run-as-service.yml` and at least 2 other
  production rules. Reference: `capa/rules/__init__.py:613`.
- **`lib: true` rules no longer surfaced as capabilities.** Python capa
  treats library-marker rules (21 in `capa-rules`) as building blocks
  for `match:` dependency resolution and filters them from output;
  capa-rs read them but listed them in `capability_namespaces`. Now
  loaded for dependency resolution and skipped from the final output,
  mirroring the existing `capa/subscope-rule` skip pattern.
- **Subscope rule rewriting (Function / BasicBlock targets).**
  `function:` and `basic block:` subscopes are now extracted into
  synthetic rules with `capa/subscope-rule: true` at ruleset
  construction (Python's pattern from `rules/__init__.py:~1124`)
  and the parent rule references them via `MatchedRule`. Each
  synthetic rule evaluates at its own scope, so feature addresses
  are meaningful and bubble up correctly through the existing
  match-rule feature index.
  - **Behavioural fix as side effect:** rules with a `basic block:`
    subscope inside a function-scope rule (or similar
    higher-scope-with-lower-subscope patterns) now correctly
    require the inner features to occur **in the same basic
    block**, not aggregated across all basic blocks of the
    function. Pre-0.4.1 capa-rs evaluated subscopes inline against
    aggregated higher-scope features, which produced false-positive
    matches when an outer rule's `basic block:` features actually
    lived in different basic blocks. Mimikatz example: pre-0.4.1
    matched `encode data using ADD XOR SUB operations` (which
    requires tight-loop + nzxor + 1 add + 1 sub in the same BB);
    0.4.1 correctly does not match it because mimikatz spreads those
    features across BBs. Python upstream behaves the same way.
  - **Instruction subscopes left inline** (continued use of
    `SubscopeInstructionEvaluator`'s per-address matching). Same
    for dynamic-scope subscopes (`process:`, `thread:`, `call:`,
    `span of calls:`). Extracting these requires an
    `instruction_rules` evaluation bucket and the dynamic-analysis
    pipeline, both deferred to 0.5.0.

### Internal

- Typo fix: `RuleFeatureType::PropretyRead` → `PropertyRead`,
  `PropretyWrite` → `PropertyWrite`. Pure rename — no behaviour
  change, but the misspelling was visible in error output.

## [0.4.0] — 2026-05-26 — Full zero-copy + Mach-O + shellcode entry (breaking)

The 0.3.21 release got capa-rs onto modern smda/dnfile by wrapping the
borrow with `ouroboros` so the public API didn't change. 0.4.0
completes that work — the wrapper is gone, lifetimes flow through the
trait hierarchy, and three new product surfaces ride along.

### Breaking changes

- **Positional `FileCapabilities::from_file(...)` / `from_buffer(...)` removed.**
  Replaced by the chained `FileCapabilities::analyze()` builder
  (`AnalyzeBuilder`). 7- and 8-argument positional calls were hard to
  read without comments on every literal; the builder makes the bool
  flags self-documenting. `.rules(path)` is the only required setter;
  every other knob defaults sensibly. Terminal methods are
  `.from_file(path)` and `.from_buffer(raw, base_addr, bitness)`.
  See migration section below.
- **`extractor::smda::Extractor`** is now `Extractor<'a>` and
  `Extractor::new(path, ha, rt, data: &'a [u8])` borrows `data` for
  the lifetime `'a`. Pre-0.4.0 the bytes were cloned into an owned
  `Vec<u8>` inside the struct; 0.4.0 holds the borrowed slice
  directly. Saves ~10–50 MB peak per analyse-call on typical malware
  samples.
- **`extractor::dnfile::Extractor`** likewise becomes `Extractor<'a>`
  and `Extractor::new(data: &'a [u8])`. Pre-0.4.0 the signature was
  `Extractor::new(file_path: &str)` (which read internally); callers
  must now read the file themselves and pass the bytes in. Matches
  the smda extractor shape and removes the duplicated file-read.
- **`Box<dyn extractor::Extractor>`** → **`Box<dyn extractor::Extractor + 'a>`**
  — the trait-object lifetime is now explicit. Only relevant to
  downstream code that constructs extractors directly; the
  `FileCapabilities::from_file` entry point hides this.
- **`FileFormat::Macho` variant added** and `FileFormat` is now
  `#[non_exhaustive]` — downstream `match` statements need a wildcard
  arm. Future additions (e.g. `Shellcode`) won't be breaking.
- **`ouroboros` dependency dropped** — direct consumers that
  re-exported it through capa-rs's tree get a thinner dep graph.

### Added

- **`FileCapabilities::analyze()` chained builder** (`AnalyzeBuilder`)
  — single entry point that ends in `.from_file(path)` or
  `.from_buffer(raw, base_addr, bitness)`. Settable: `.rules` (required),
  `.high_accuracy`, `.resolve_tailcalls`, `.logger`, `.features_dump`,
  `.security_checks`. Defaults: `high_accuracy=false`,
  `resolve_tailcalls=false`, `logger=no-op`, `features_dump=false`,
  `security_checks=default`. Returns `Error::BuilderMissingRules` if
  `.rules()` was never called. Matches the SmdaConfig builder pattern
  used in smda 0.5.
- **`FileCapabilities::analyze().from_buffer(raw, base_addr, bitness)`**
  — shellcode / memory dump / unpacked module entry. Bypasses the
  magic-byte format check; routes directly to smda's
  `Disassembler::parse_buffer`. Skips dnfile (no PE header) and the
  security-checks pipeline (those are PE/ELF-specific). Closes the
  long-standing "capa-rs only accepts files with executable magic"
  limitation.
- **Mach-O support.** PE / ELF / Mach-O all route through smda 0.5's
  unified loader. capa rules that match on `format: macho` or
  Mach-O-specific imports now fire on real Mach-O malware samples.
- **PDB GUID in `FileCapabilities.properties`.** When the input is a
  PE with a CodeView debug record, `pdb_guid`, `pdb_age`, and
  `pdb_filename` are now exposed in the properties output for
  symbol-server (Microsoft SymSrv / Mozilla / Chromium) lookup.
  Fields are serialized only when present (`skip_serializing_if`),
  so existing JSON consumers that don't know about them don't see
  surprise `null`s on ELF / Mach-O / shellcode inputs.

### Fixed

- **`examples/capa_cli.rs` properties table.** The renderer used
  `v.as_str().unwrap()` per row, which panicked the moment Properties
  gained a numeric field (`pdb_age`). Renderer now handles `String`,
  `Number`, `Bool`, `Null`, and any future scalar via JSON
  stringification.

### Migration

**Entry points.** The 0.3.x positional `from_file` / `from_buffer`
constructors are gone. Move call sites to the builder:

```rust
// Before (0.3.x):
let fc = FileCapabilities::from_file(
    "Sample.exe",
    "./capa-rules",
    true,                                        // high_accuracy
    true,                                        // resolve_tailcalls
    &|_| {},                                     // logger
    false,                                       // features_dump
    Some(BinarySecurityCheckOptions::default()), // security checks
)?;

// After (0.4.0):
let fc = FileCapabilities::analyze()
    .rules("./capa-rules")
    .high_accuracy(true)
    .resolve_tailcalls(true)
    .security_checks(BinarySecurityCheckOptions::default())
    .from_file("Sample.exe")?;
```

Defaults match the prior implicit zeros — drop any builder method
you'd previously have passed `false` / `&|_|{}` / `None` to.

**Extractors.** If you construct the smda or dnfile extractors directly:

```rust
// Before (0.3.21):
let extractor = extractor::smda::Extractor::new(path, false, false, &data)?;

// After (0.4.0): same call, but the returned Extractor borrows from
// `data` for as long as it's used. Make sure `data` outlives it.
let extractor = extractor::smda::Extractor::new(path, false, false, &data)?;
```

```rust
// Before (0.3.21): dnfile read the file path internally.
let extractor = extractor::dnfile::Extractor::new(path)?;

// After (0.4.0): caller reads the file and passes the bytes.
let data = std::fs::read(path)?;
let extractor = extractor::dnfile::Extractor::new(&data)?;
```

If you `match` on `FileFormat`, add a wildcard arm:

```rust
match fc.format {
    FileFormat::PE => …,
    FileFormat::ELF => …,
    FileFormat::DOTNET => …,
    FileFormat::Macho => …,    // new in 0.4.0
    _ => …,                    // FileFormat is now #[non_exhaustive]
}
```

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
