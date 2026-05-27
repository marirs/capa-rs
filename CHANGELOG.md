# Changelog

All notable changes to **capa** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.3] — 2026-05-27 — FLIRT polish

### Added
  
- **FLIRT matcher.** `AnalyzeBuilder::signatures(path)` loads
  `.sig` and `.pat` files from a directory; matched functions are  
  flagged as library code and excluded from the capability output. 
  Engine: [`fast-flirt`](https://crates.io/crates/fast-flirt).  
- **`capa_cli --signatures PATH`** flag.
- **`flirt-sigs/`** — 195 `.sig` files (~70 MB) covering MSVC CRT,
  ATL/MFC, OpenSSL, zlib, boost, libcurl, lua, protobuf, DirectX, 
  and Intel libs on Windows. Sourced from Mandiant FLARE
  (`mandiant/`, Apache-2.0) and Maktm's FLIRTDB (`flirtdb/`,
  community-permissive). Credits in `flirt-sigs/README.md`.
- **`flirt-sigs-vX.Y.Z.tar.gz`** GitHub release artifact carrying
  the same content; download, extract, point `--signatures` at it.  
- **`AnalyzeBuilder::with_flirt_matcher(Arc<FlirtMatcher>)`.** Reuse
  one loaded signature corpus across many `from_file` / `from_buffer`
  calls instead of re-walking the directory and rebuilding the trie
  on every analysis. Amortises the ~360 ms / ~70 MB FLIRT load over
  the whole batch. Takes precedence over `signatures(path)` when both
  are set. Pattern: build the matcher once, wrap in `Arc`, clone the
  handle per builder.

### Changed

- **`fast-flirt` 0.2.0 → 0.2.1.** Picks up th
   — the NameIter corruption bug when a `.sig` module carries
  both references and tail bytes (CRIT), the missing arena-bounds
  validation in `FlirtSetBuilder::build()` (HIGH), the `u8` /
  `u16` overflows on `names_count` and `tail_bytes_count` from
  pathological inputs (MED). `FlirtMatcher::from_directory` now maps
  the new fallible `build()` through `Error::InvalidRuleFile`.
- **`FlirtMatcher::match_function` returns `Option<&str>`.** Borrowed
  from the underlying `FlirtSet` arena — no per-call `String`
  allocation in the hot path. Callers that need an owned name can
  `.map(str::to_owned)`.
- **Case-insensitive `.sig` / `.pat` extension matching.** Vendor
  zips frequently ship uppercase `.SIG`; the directory walker now
  lowercases before the suffix check, matching `fast-flirt`'s own
  `load_dir` behaviour.
- **`make_library_filter` borrows `&dyn Extractor` instead of
  `&Box<dyn Extractor>`.** Drops the surplus indirection clippy
  flagged as `borrowed_box`.
- **`FLIRT_LOOKAHEAD_BYTES` lives only in `flirt.rs`.** The lookahead
  read + matcher dispatch is encapsulated in
  `FlirtMatcher::match_function_at`; `make_library_filter` is a
  one-liner over that.

### Fixed

- **Symlinks in the signature directory are skipped.** `walkdir`
  with `follow_links(false)` still reads file-typed symlink entries;
  an explicit `is_symlink()` check now prevents that. Consistent with
  `fast-flirt`'s own walker policy.
- **`.pat.gz` files are counted and surfaced in the load summary.**
  capa-rs 0.4.x doesn't unpack gzipped pat — the load line now reads
  e.g. `loaded 4982 signatures from 195 files (3 .pat.gz skipped —
  gunzip to enable)` so the gap is visible. Hard-fails only when the
  directory yields zero parseable signatures.


## [0.4.2] — 2026-05-26 — Performance, threading, hardening

### Performance

- **Rule loader O(N²) → O(N).** `get_rules_and_dependencies` rebuilt
  the namespace index and rules-by-name HashMap on every call; with
  ~1,000 rules and four scope passes that's ~16M HashMap inserts per
  `RuleSet::new`. Hoisted the indexes to build once; flattened the
  `wanted.contains(...)` linear scan to a HashSet lookup. Expected
  5–20× rule-load speedup.
- **`rayon::par_iter` over the function loop in `find_capabilities`.**
  Each function's `find_function_capabilities` call is pure — reads
  the extractor, evaluates rules, returns matches. Parallelised the
  outer loop; aggregation via collect+sequential merge. Expected
  4–8× end-to-end analysis speedup on multi-core machines.
- **`rayon::par_iter` over the YAML parse loop in `get_rules`.**
  Independent per file. Expected 3–5× additional rule-load speedup
  on top of the index-hoist fix.
- **`lazy_static!` for two recompile-per-call regexes**
  (`update_capabilities` tag extraction, `parse_parts_id` att&ck/mbc
  parser).
- **`BytesFeature::evaluate` length-equality short-circuit.** capa
  rules' `bytes:` features are almost always the same length as the
  binary's extracted bytes; one-line check that avoids the
  `windows().any()` scan in the common case.
- **`Arch` / `Os` / `Format` / `Namespace` / `Class` feature
  canonicalisation moved to construction.** Previously
  `.to_lowercase()` ran inside `Hash` and `PartialEq`; now once at
  parse time.
- **`Box<dyn extractor::Extractor + Send + Sync + 'a>`.** Trait
  object now explicitly bounded so it can be shared across rayon
  threads. The underlying smda and dnfile extractors already
  satisfy both.

### Fixed

- **B5: `NumberFeature` and `OffsetFeature` ignored bitness in
  `Hash` / `PartialEq`.** `number/u32: 0x100` and `number/u64: 0x100`
  collided in the rule-engine HashMap, producing silent rule
  miss / over-match. Bitness is now part of the equality contract,
  matching Python upstream.
- **B2: `NotStatement` silently dropped extra children.**
  `not: [a, b]` evaluated as `not a`, ignoring `b`. Now rejected
  at rule load with `InvalidRule`, matching Python upstream.
- **B1: `SubscopeInstructionEvaluator` now recurses into nested
  statements.** Previously the per-address loop only handled
  flat-Feature `And` children — any nested `Or` / `And` / `Not`
  inside an `instruction:` subscope evaluated to false even when
  Python would match. Closes the parity gap flagged in the prior
  audit report. Combined with 0.4.1's cross-scope subscope fix,
  `host-interaction/service/run-as-service.yml` and similar
  file-scope-with-instruction-subscope rules now fully work.
- **S7+S8: Integer-overflow validation in count parsing.**
  "5000000000 or more" used to silently truncate `i64 → u32` and
  match against `705032704`. Out-of-range thresholds now error at
  rule load.

### Security

- **S1: ReDoS hardening on user-rule regex patterns.** Capa rules'
  regex features go through `fancy_regex` (NFA + backtracking — a
  hostile rule like `(a+)+b` can hang the analyzer for hours).
  `RegexFeature::new` now tries the linear-time `regex` crate
  first and falls back to `fancy_regex` only when the rule actually
  uses lookbehind / backrefs (~5% of capa-rules patterns). Caps the
  worst-case match time on the common path.
- **S10: `walkdir::follow_links(false)`** on rule directory traversal.
  Defence-in-depth against malicious symlink chains in a
  user-controlled `--rules` path.
- **S2: Non-UTF-8 rule paths no longer panic** the loader (`unwrap()`
  on `Path::to_str()` replaced with `if let Some`).

### Internal / cleanup

- Removed dead `get_buf`, `_read_dotnet_user_string`, `xor_static`,
  `xor_with_key`, commented-out `StringFactoryFeature`, the
  file-level `#![allow(dead_code)]` on `src/extractor/smda.rs`
  (and fixed the warnings it was hiding), three stale commented
  `let count` / `let min` / `let max` blocks in `rules/mod.rs`.

## [0.4.1] — 2026-05-26 — Python-capa rule-loader parity (P0 + P1)

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
  - **Side effect:** `basic block:` subscope features are now
    correctly required to occur in the same basic block, matching
    Python upstream. Some rules that previously matched on
    cross-BB feature combinations no longer fire.

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
