# Changelog

All notable changes to **capa** are documented here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] — Mach-O closeout: zero `Unknown` rows, stub-VA API resolution, iOS distinction

Closes every `Unknown` placeholder in the 0.5.0 Mach-O security
table, picks up smda 0.6.5's `__TEXT,__stubs` walker so direct
`bl _stub` calls resolve to API names, and distinguishes iOS
binaries from macOS via `LC_BUILD_VERSION.platform`.

### Dependency bumps

- **smda 0.6.4 → 0.6.5.** Mach-O closeout — see smda CHANGELOG
  0.6.5 entry. `__TEXT,__stubs` walker via `LC_DYSYMTAB`
  registers stub VAs (catches direct `bl _stub` calls, the most
  common ARM64 PIC call shape); `MachoArchPreference` plumbed
  through `BinaryInfo` so import extraction parses the same
  slice the analyser disassembled.
- **`plist = "1"` (pure-rust, no native deps).** New dep used
  by `security/macho.rs` to parse the Mach-O entitlements PLIST
  payload for the ALLOW-JIT check. No openssl / aws-lc /
  native-tls in the transitive tree — matches the project's
  pure-Rust stance.

### Fixed — security checklist closeout

- **HARDENED-RUNTIME** no longer emits `Unknown`. Walks the
  `CS_SuperBlob` (magic `0xfade0cc0`) at
  `LC_CODE_SIGNATURE.dataoff`, locates the `CS_CodeDirectory`
  blob (magic `0xfade0c02`), reads its big-endian `flags` field
  at offset 0x0c, checks `flags & CS_RUNTIME (0x10000)`. Fat
  binaries: slice offset folded in so `dataoff` resolves to the
  correct absolute file position. Unsigned binaries (no
  `LC_CODE_SIGNATURE`) report Fail; malformed blobs report
  Unknown.
- **ALLOW-JIT** no longer emits `Unknown`. Same SuperBlob walk
  finds the `CS_EmbeddedEntitlements` blob (magic `0xfade7171`);
  the PLIST payload is parsed via the `plist` crate (handles
  both XML and binary forms transparently) and checked for
  `com.apple.security.cs.allow-jit = true`. No entitlements →
  Fail (the absence of the key means JIT is not permitted).

### Added — iOS vs macOS distinction

- **`Os::IOS` is now actually emitted** (0.5.0 defined the
  variant but always collapsed Mach-O to `MACOS`). New
  `classify_macho_os` walker inspects load commands:
  - `LC_BUILD_VERSION.platform` (Xcode-10+ binaries) — modern,
    authoritative. Maps `PLATFORM_IOS (2)` / `PLATFORM_TVOS (3)`
    / `PLATFORM_WATCHOS (4)` / `PLATFORM_BRIDGEOS (5)` /
    iOS-family simulators → `Os::IOS`. `PLATFORM_MACOS (1)` /
    `PLATFORM_MACCATALYST (6)` / `PLATFORM_DRIVERKIT (10)` →
    `Os::MACOS`.
  - `LC_VERSION_MIN_*` (legacy / pre-Xcode-10) — fallback. cmd
    id `LC_VERSION_MIN_IPHONEOS (0x25)` / `_TVOS (0x2F)` /
    `_WATCHOS (0x30)` → `Os::IOS`; `LC_VERSION_MIN_MACOSX
    (0x24)` → `Os::MACOS`.
  - No version commands → defaults to `Os::MACOS`.
  Both the smda-extractor `extract_os()` (CLI surface) and
  `FileCapabilities::get_os()` (properties feature) route
  through the same helper for consistency.

### Maintenance

- `cargo update` — clears the `goblin v0.10.6` yanked warning
  carried over from 0.5.0's publish.

## [0.5.0] — AArch64 thread-through

Threads the AArch64 surface from smda 0.6.x into the analysis
pipeline. No API breaks at the `AnalyzeBuilder` / `FileCapabilities`
level; the `Extractor` trait gains one new method (`arch()`) so
downstream consumers implementing the trait need to add it.

### Dependency bumps

- **smda 0.5 → 0.6.** Picks up AArch64 (Apple-silicon Mach-O,
  Linux EM_AARCH64, Windows ARM64 PE), the seven AArch64 analyser
  ports (jump-table, indirect-call, tail-call, .pdata, NOP,
  exit-syscall, is_api_thunk), ELF GOT/PLT API resolution, and
  the 0.6.2 hygiene patches. Semver-compatible with all future
  0.6.x.

### Added

- typed iced operand walking in `extract_insn_offset_features`.
  Pre-0.5.0 split formatted operand strings on commas and ran
  regexes; missed offsets buried in SIB-displacement forms like
  `[rax + rcx*4 + 0x10]`. Now consults `op_kind(i)`, `memory_base()`,
  and `memory_displacement64()`
- real `translate_com_features` impl backed by a generated
  ~29 k-entry GUID database (`src/rules/com_db.rs`, ~5.8 MB) for
  every COM class and interface known to upstream Python capa.
  Rule-load-time rewrite of `com/class: WbemLocator` →
  `or: [bytes: <guid1>, bytes: <guid2>]`. Database regenerated via
  `scripts/gen_com_tables.py`.
- scope-keyed feature dump
  (`map_features_by_scope: HashMap<&'static str, …>`) so the
  `--map-features` CLI flag surfaces feature counts per scope
  (file / function / basic_block / instruction). New CLI summary
  table in `capa_cli`.

### Added — AArch64 thread-through (task #236)

- **`Extractor::arch()`** trait method. Both `Smda` and `DnFile`
  impls provided. Surfaces the real `FileArchitecture` from the
  underlying disassembler instead of the previous bitness-based
  guess.
- **`FileCapabilities::get_arch`** now calls `extractor.arch()`
  instead of mapping `bitness == 64 → AMD64` unconditionally —
  which had been silently mislabelling every AArch64 binary that
  smda 0.6 started producing.
- **`extract_insn_mnemonic_features`** branches on
  `Instruction::mnemonic_aarch64()` so ARM64 instructions emit
  their disarm64 mnemonic (`ldr`, `str`, `bl`, …) instead of the
  iced sentinel string `"invalid"`. Rules `mnemonic: ldr` etc.
  now fire on ARM64 binaries.

### Added — AArch64 instruction-scope feature parity

- **`extract_insn_offset_features` ARM64 path.** Routes through
  smda 0.6's `disassembler::aarch64_ops` decoders instead of the
  x86-only iced operand walk (which returned sentinel/zero on
  ARM64 and silently dropped every offset feature). Now emits:
  - `LDR/STR Xt, [Xn, #imm12]` → `Offset(imm12)` +
    `OperandOffset(1, imm12)` — base = SP (R31) / X29 (frame
    pointer) skipped, matching the x86 path's EBP/RBP filter.
  - `ADR  Xd, label`             → `Number(label_va)` — mirrors
    x86 LEA's "constant address into register" emission.
  - `ADRP Xd, page`              → `Number(page_va)` — same shape
    at 4 KiB granularity (compilers emit ADRP+ADD/LDR to
    materialise a full address; the page VA is close enough for
    the typical "constant in code" pattern that `number:` rules
    look for).
- **`extract_insn_peb_access_characteristic_features` ARM64
  path.** Windows on ARM64 reserves x18 as the TEB pointer
  (Microsoft "platform register" ABI; PEB lives at
  `[x18 + 0x60]`, mirroring `gs:[0x60]` on x64). Loads with
  base = x18 are flagged as `peb access` regardless of
  displacement — same "touches TEB" granularity as the x86
  `fs:`/`gs:` segment-read match. Stores are excluded; writing
  through x18 is exotic and doesn't pattern-match the rule.

### Fixed — Mach-O closeout (audit findings)

- **Fat (universal) Mach-O now routed to smda instead of
  rejected.** `is_macho_magic` previously excluded `cafebabe` /
  `cafebabf` (and their byte-swapped variants), so every
  Apple-Silicon system binary that ships as a universal binary
  (`/bin/ls`, `/usr/bin/file`, …) returned
  `UnsupportedFormatError` even though smda's
  `extract_macho_with_offset` already has fat-slice selection
  wired up. Now accepted; smda picks the matching slice via
  the `MachoArchPreference::HostNative` default. Caveat: the
  `cafebabe` magic is also Java `.class` file magic — goblin's
  `Mach::parse` rejects class files cleanly (the nfat_arch
  sanity check fails), so a misrouted `.class` surfaces as a
  parse error rather than silent misinterpretation.
- **`security::get_security_checks` no longer aborts on
  Mach-O.** Pre-0.5.0 returned `UnsupportedBinaryFormat` for
  every Mach-O input, which `from_file` propagates via `?` —
  so even with the fat-Mach-O fix above, no Mach-O could
  actually reach the capability engine. The PE/ELF security
  checklist (ASLR, DEP, SEH, CHECKSUM, RELRO, CANARY, …) has
  no 1:1 equivalent on Darwin, so the path now returns an
  empty `Vec` and lets analysis continue — mirrors how
  `from_buffer` skips security checks for shellcode.
- **`extract_insn_nzxor_characteristic_features` ARM64 path.**
  Pre-0.5.0 the function checked iced's x86 `Mnemonic` enum
  only, which is `INVALID` on AArch64 decodes — so the `nzxor`
  characteristic never fired on ARM64 binaries. Now branches
  on `insn.decoded` and detects AArch64 `EOR` / `EOR3` /
  `EORS` via `mnemonic_aarch64()`, with a self-XOR exclusion
  (`Rn == Rm`, the AArch64 zeroing idiom) mirroring the x86
  `dst == src` filter. Security-cookie filter is skipped on
  ARM64 — the RBP-relative cookie pattern doesn't exist
  verbatim (Darwin uses `__stack_chk_guard` loads instead).
- **Mach-O OS now reports `MACOS`, not the `LINUX`
  placeholder.** Added `Os::MACOS` and `Os::IOS` to the
  public `consts::Os` enum (additive — non-breaking for
  matchers using `_`). `extract_os` + `get_os` route Mach-O
  through `MACOS`. Rules `os: macos` now fire on Mach-O
  input; `os: linux` rules no longer fire incorrectly. iOS
  vs macOS isn't distinguishable from cputype alone
  (CPU_TYPE_ARM64 covers both); future work could promote to
  `IOS` based on `LC_VERSION_MIN_IPHONEOS`.

### Dependency bumps (continued)

- **smda 0.6.2 → 0.6.4.** Picks up two Mach-O fixes that
  capa-rs 0.5.0 depends on:
  - **0.6.3 tail-call resolver fix:** when
    `resolve_tailcalls(true)` is active (capa_cli default),
    `TailCallAnalyser::resolve_tailcalls` used to fatally
    propagate `CollisionError` from `analyse_function` —
    aborting the whole `Disassembler::parse` call. Now treats
    CollisionError as expected (skip candidate, continue),
    matching the main candidate loop's `.ok()` pattern. Pre-fix
    repro: `SMDAError(CollisionError(0x100003698))` in ~95 ms
    on every Apple-Silicon /bin/ls invocation.
  - **0.6.4 Mach-O imports → `disassembly.apis` bridge:**
    `analyse_buffer` had an explicit ELF→apis bridge and PE was
    handled by the WinApiResolver, but Mach-O had neither.
    Imports stopped at file-scope `binary_info.imports` and
    never reached `disassembly.apis` / `addr_to_api`, so
    `Function::apirefs` was empty for every Mach-O function and
    capa's `extract_insn_api_features` emitted zero
    `Feature::Api` for Mach-O input — making /bin/ls match zero
    capa rules. Now a Mach-O-symmetric block in `analyse_buffer`
    walks `macho::extract_macho_dynamic_apis` (new in 0.6.4) and
    populates both `apis` and `addr_to_api` directly. Coverage:
    `__DATA,__got` / `__DATA,__la_symbol_ptr` slot VAs, reached
    by the canonical ARM64 PIC patterns (`adrp+ldr+blr` inlined
    or via __TEXT,__stubs thunks).

### Added — Mach-O security checklist

- **Real `security/macho.rs` module** replacing the placeholder
  `Ok(Vec::new())` that pre-0.5.0 shipped (an empty Security
  Checks table on every Mach-O input). Nine checks emitted:
  - **PIE** — `MH_PIE` (`0x200000`), Darwin ASLR equivalent.
  - **DATA-EXEC-PREVENT** — `MH_NO_HEAP_EXECUTION` (`0x01000000`)
    OR no `__DATA*` segment with `VM_PROT_EXECUTE` in
    `initprot`.
  - **STACK-CANARY** — `___stack_chk_guard` /
    `___stack_chk_fail` in the symbol table.
  - **RESTRICT** — presence of a `__RESTRICT` segment
    (anti-`DYLD_INSERT_LIBRARIES` marker).
  - **CODE-SIGNATURE** — `LC_CODE_SIGNATURE` load command with
    non-zero `datasize`.
  - **TWO-LEVEL-NAMESPACE** — `MH_TWOLEVEL` (`0x80`).
  - **NO-UNDEF-SYMS** — `MH_NOUNDEFS` (`0x01`).
  - **HARDENED-RUNTIME** — `Unknown` (requires `CS_SuperBlob` →
    `CS_CodeDirectory.flags & CS_RUNTIME (0x10000)` walk;
    deferred to a follow-up, ~80 LOC of big-endian parsing
    inside `__LINKEDIT`).
  - **ALLOW-JIT** — `Unknown` (requires
    `CS_EmbeddedEntitlements` PLIST parsing; deferred).
  Fat binaries: first parseable slice's checks are reported,
  same convention as smda's `MachoArchPreference::HostNative`
  picks for analysis.

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
