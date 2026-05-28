// 0.3.21: crate-level allows for clippy categories that produce noise on
// this legacy codebase but don't represent real defects:
// - `mutable_key_type`: false positive — `Feature` contains regex internals
//   (`Pool<Cache>`) whose interior mutability is for caching, not stateful
//   semantics. Using them as `HashMap` keys is safe.
// - `collapsible_if` / `collapsible_match`: 2024-edition let-chain
//   modernizations applied across hundreds of legacy sites. Stylistic.
// - `type_complexity` / `borrowed_box`: pre-existing.
#![allow(
    clippy::type_complexity,
    clippy::borrowed_box,
    clippy::mutable_key_type,
    clippy::collapsible_if,
    clippy::collapsible_match
)]

extern crate core;

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::PathBuf,
    thread::spawn,
};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use smda::FileArchitecture;
use yaml_rust::Yaml;

// 0.4.2: regexes used in tag-string parsing — compiled once per
// process via `once_cell::Lazy`. Pre-0.4.2 these were re-compiled
// inside the per-rule and per-att&ck/mbc-entry loops in
// `update_capabilities` and `parse_parts_id`. Negligible per-call
// but real cumulative cost on a ~1,000-rule analysis (~10 ms).
static TAG_BRACKET_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r##"[^]]*\[(?P<tag>[^]]*)]"##)
        .expect("compile-time regex literal — pattern is valid")
});
static PARTS_ID_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"^(.*?)(?:\s*\[(.*?)])?$")
        .expect("compile-time regex literal — pattern is valid")
});

use consts::FileFormat;
// 0.4.0: `Os` is referenced only by the properties-gated
// `FileCapabilities::get_os` — gating the import avoids the
// `--no-default-features` unused-import warning.
#[cfg(feature = "properties")]
use consts::Os;
use sede::{from_hex, to_hex};

pub use crate::error::Error;
use crate::security::options::status::SecurityCheckStatus;

pub(crate) mod consts;
mod error;
mod extractor;
// 0.4.3: FLIRT library-function recognition. Always compiled in;
// FLIRT only runs when `AnalyzeBuilder::signatures(path)` is set.
pub mod flirt;
pub mod rules;
mod security;
mod sede;

pub type Result<T> = std::result::Result<T, Error>;

// If this changes, then update the command line reference.
// Used for options for binary security checks.
#[derive(Debug, Copy, Clone)]
pub enum LibCSpec {
    LSB1,
    LSB1dot1,
    LSB1dot2,
    LSB1dot3,
    LSB2,
    LSB2dot0dot1,
    LSB2dot1,
    LSB3,
    LSB3dot1,
    LSB3dot2,
    LSB4,
    LSB4dot1,
    LSB5,
}

// Used for options for binary security checks.
impl fmt::Display for LibCSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let spec_name = match *self {
            LibCSpec::LSB1
            | LibCSpec::LSB1dot1
            | LibCSpec::LSB1dot2
            | LibCSpec::LSB1dot3
            | LibCSpec::LSB2
            | LibCSpec::LSB2dot0dot1
            | LibCSpec::LSB2dot1
            | LibCSpec::LSB3
            | LibCSpec::LSB3dot1
            | LibCSpec::LSB3dot2
            | LibCSpec::LSB4
            | LibCSpec::LSB4dot1
            | LibCSpec::LSB5 => "Linux Standard Base",
        };

        let spec_version = match *self {
            LibCSpec::LSB1 => "1.0.0",
            LibCSpec::LSB1dot1 => "1.1.0",
            LibCSpec::LSB1dot2 => "1.2.0",
            LibCSpec::LSB1dot3 => "1.3.0",
            LibCSpec::LSB2 => "2.0.0",
            LibCSpec::LSB2dot0dot1 => "2.0.1",
            LibCSpec::LSB2dot1 => "2.1.0",
            LibCSpec::LSB3 => "3.0.0",
            LibCSpec::LSB3dot1 => "3.1.0",
            LibCSpec::LSB3dot2 => "3.2.0",
            LibCSpec::LSB4 => "4.0.0",
            LibCSpec::LSB4dot1 => "4.1.0",
            LibCSpec::LSB5 => "5.0.0",
        };

        write!(f, "{spec_name} {spec_version}")
    }
}

// Used for options for binary security checks.
impl LibCSpec {
    pub(crate) fn get_functions_with_checked_versions(self) -> &'static [&'static str] {
        match self {
            LibCSpec::LSB1
            | LibCSpec::LSB1dot1
            | LibCSpec::LSB1dot2
            | LibCSpec::LSB1dot3
            | LibCSpec::LSB2
            | LibCSpec::LSB2dot0dot1
            | LibCSpec::LSB2dot1
            | LibCSpec::LSB3
            | LibCSpec::LSB3dot1
            | LibCSpec::LSB3dot2 => &[],

            LibCSpec::LSB4 | LibCSpec::LSB4dot1 | LibCSpec::LSB5 => {
                security::elf::checked_functions::LSB_4_0_0_FUNCTIONS_WITH_CHECKED_VERSIONS
            }
        }
    }
}

// Used for options for binary security checks.
impl From<String> for LibCSpec {
    fn from(value: String) -> Self {
        match value.as_str() {
            "1.0.0" => LibCSpec::LSB1,
            "1.1.0" => LibCSpec::LSB1dot1,
            "1.2.0" => LibCSpec::LSB1dot2,
            "1.3.0" => LibCSpec::LSB1dot3,
            "2.0.0" => LibCSpec::LSB2,
            "2.0.1" => LibCSpec::LSB2dot0dot1,
            "2.1.0" => LibCSpec::LSB2dot1,
            "3.0.0" => LibCSpec::LSB3,
            "3.1.0" => LibCSpec::LSB3dot1,
            "3.2.0" => LibCSpec::LSB3dot2,
            "4.0.0" => LibCSpec::LSB4,
            "4.1.0" => LibCSpec::LSB4dot1,
            "5.0.0" => LibCSpec::LSB5,
            _ => LibCSpec::LSB5,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BinarySecurityCheckOptions {
    /// Path of the C runtime library file.
    pub(crate) libc: Option<PathBuf>,

    /// Path of the system root for finding the corresponding C runtime library.
    pub(crate) sysroot: Option<PathBuf>,

    /// Use an internal list of checked functions as specified by a specification.
    pub(crate) libc_spec: Option<LibCSpec>,

    /// Assume that input files do not use any C runtime libraries.
    pub(crate) no_libc: bool,

    /// Binary file to analyze.
    pub(crate) input_file: PathBuf,
}

impl BinarySecurityCheckOptions {
    pub fn new(
        libc: Option<PathBuf>,
        sysroot: Option<PathBuf>,
        libc_spec: Option<LibCSpec>,
    ) -> Self {
        //!
        //! Create some options to configure binary security checks.
        //! - libc: This is the path of the C runtime library file.
        //! - sysroot:  The path of the system root for finding the corresponding C runtime library.
        //! - libc_spec: Use an internal list of checked functions as specified by a specification.
        //! - no_libc: Assume that input files do not use any C runtime libraries.
        Self {
            libc,
            sysroot,
            libc_spec,
            no_libc: false,
            input_file: PathBuf::new(),
        }
    }
}

impl Default for BinarySecurityCheckOptions {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

/// 0.4.0: default no-op logger used when [`AnalyzeBuilder::logger`]
/// is not called. Defined as a free fn (not a closure) so its
/// reference has `'static` lifetime — that lets `AnalyzeBuilder`
/// hold a `&'static dyn Fn(&str)` by default without forcing
/// callers to provide one.
fn noop_logger(_: &str) {}

/// 0.5.0: build the library-function filter closure passed to
/// [`find_capabilities`]. When the caller has configured a
/// [`flirt::FlirtMatcher`] (via `AnalyzeBuilder::signatures` or
/// `with_flirt_matcher`), the closure asks the matcher for each
/// function and returns `Some(name)` on match. Otherwise it always
/// returns `None`, leaving the analysis unchanged.
///
/// 0.4.3 returned a `bool`. 0.5.0 returns `Option<String>` so the
/// matched library-function name flows back to the caller and gets
/// surfaced on `FileCapabilities::library_functions` — parity with
/// Python capa's JSON output, and the only way for consumers to see
/// what was FLIRT-skipped.
///
/// Routes through `FlirtMatcher::match_function_at`, which owns the
/// `FLIRT_LOOKAHEAD_BYTES` constant + the byte-read dance — keeping
/// the lookahead size in exactly one place. The arena `&str` is
/// copied to a `String` here because the closure return type can't
/// borrow from the matcher (the borrow would have to outlive the
/// closure itself, defeating the abstraction).
///
/// `Box<dyn>` because the FLIRT and no-op arms produce different
/// closure types. `'a` is the borrow scope of `extractor` and the
/// optional matcher; both live in the calling terminal method
/// (`from_file` / `from_buffer`) and outlive the
/// [`find_capabilities`] call that consumes the boxed closure.
fn make_library_filter<'a>(
    extractor: &'a (dyn extractor::Extractor + '_),
    flirt: Option<&'a flirt::FlirtMatcher>,
) -> Box<dyn Fn(u64) -> Option<String> + Sync + Send + 'a> {
    if let Some(matcher) = flirt {
        return Box::new(move |addr: u64| {
            matcher
                .match_function_at(addr, extractor)
                .map(str::to_owned)
        });
    }
    Box::new(|_addr: u64| None)
}

/// 0.4.0: chained builder for [`FileCapabilities`] analysis. The
/// 0.3.x positional `from_file` / `from_buffer` entry points are
/// gone — `.rules(...)` is the only required setter; everything
/// else has a sensible default.
///
/// ## File analysis
/// ```ignore
/// use capa::{BinarySecurityCheckOptions, FileCapabilities};
///
/// let fc = FileCapabilities::analyze()
///     .rules("./capa-rules")
///     .high_accuracy(true)
///     .resolve_tailcalls(true)
///     .security_checks(BinarySecurityCheckOptions::default())
///     .from_file("Sample.exe")?;
/// # Ok::<(), capa::Error>(())
/// ```
///
/// ## Shellcode / raw buffer
/// ```ignore
/// use capa::FileCapabilities;
///
/// let shellcode = std::fs::read("payload.bin")?;
/// let fc = FileCapabilities::analyze()
///     .rules("./capa-rules")
///     .high_accuracy(true)
///     .from_buffer(&shellcode, 0x1000, 64)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct AnalyzeBuilder<'a> {
    rules: Option<String>,
    high_accuracy: bool,
    resolve_tailcalls: bool,
    // 0.4.2: `+ Sync + Send` added so the logger can cross rayon
    // worker threads in `find_capabilities`'s parallel function loop.
    // `noop_logger` is a fn-pointer, which is unconditionally
    // `Send + Sync`; user-supplied closures need to satisfy the
    // bounds (which they do as long as they capture only
    // `Send + Sync` state).
    logger: &'a (dyn Fn(&str) + Sync + Send),
    features_dump: bool,
    security_checks: Option<BinarySecurityCheckOptions>,
    // 0.4.3: optional FLIRT signatures directory. When set and
    // `flirt_matcher` is None, `from_file` / `from_buffer` load the
    // matcher from this path and use it to mark library functions
    // during analysis. Stored as PathBuf so the builder doesn't
    // carry a borrow lifetime on the path.
    flirt_signatures: Option<std::path::PathBuf>,
    // 0.4.4: pre-built FLIRT matcher, shared via Arc. Set via
    // `with_flirt_matcher` for batch analysis — avoids re-walking
    // the corpus + rebuilding the trie on every `from_file` /
    // `from_buffer` call. Takes precedence over `flirt_signatures`
    // when both are set.
    flirt_matcher: Option<std::sync::Arc<flirt::FlirtMatcher>>,
}

impl<'a> Default for AnalyzeBuilder<'a> {
    fn default() -> Self {
        AnalyzeBuilder {
            rules: None,
            high_accuracy: false,
            resolve_tailcalls: false,
            // `&noop_logger` is `&'static dyn Fn(&str)`, coerces to
            // the builder's `'a`.
            logger: &noop_logger,
            features_dump: false,
            security_checks: None,
            flirt_signatures: None,
            flirt_matcher: None,
        }
    }
}

impl<'a> AnalyzeBuilder<'a> {
    /// Construct a builder with all defaults. Equivalent to
    /// [`FileCapabilities::analyze`].
    pub fn new() -> Self {
        Self::default()
    }

    /// **Required.** Path to a checked-out
    /// [capa-rules](https://github.com/mandiant/capa-rules) directory.
    /// Terminal methods return [`Error::BuilderMissingRules`] if this
    /// was never called.
    pub fn rules(mut self, path: impl Into<String>) -> Self {
        self.rules = Some(path.into());
        self
    }

    /// Default: `false`. Enables smda's slower but more thorough
    /// function-candidate sweep. Matches smda's `SmdaConfig::high_accuracy`.
    pub fn high_accuracy(mut self, on: bool) -> Self {
        self.high_accuracy = on;
        self
    }

    /// Default: `false`. Asks smda to resolve tail calls
    /// (`jmp <function>`) as function boundaries.
    pub fn resolve_tailcalls(mut self, on: bool) -> Self {
        self.resolve_tailcalls = on;
        self
    }

    /// Default: a no-op. Progress callback — capa-rs calls it with
    /// short status strings during the analysis hot loop. Wire it to a
    /// progress bar / log sink if you want visibility into long
    /// analyses.
    pub fn logger(mut self, logger: &'a (dyn Fn(&str) + Sync + Send)) -> Self {
        self.logger = logger;
        self
    }

    /// Default: `false`. When `true`, the resulting `FileCapabilities`
    /// has its `map_features` field populated — every feature that
    /// matched a rule, by address. Disabled by default because it
    /// roughly doubles peak memory.
    pub fn features_dump(mut self, on: bool) -> Self {
        self.features_dump = on;
        self
    }

    /// Default: `None` — security checks are run with default options
    /// for [`from_file`](Self::from_file) regardless. Override to point
    /// at a specific libc / sysroot / spec.
    /// Ignored by [`from_buffer`](Self::from_buffer): shellcode has no
    /// PE/ELF headers for the security checklist to inspect.
    pub fn security_checks(mut self, opts: BinarySecurityCheckOptions) -> Self {
        self.security_checks = Some(opts);
        self
    }

    /// 0.4.3: directory of `.sig` / `.pat` FLIRT signature files.
    /// When set, capa-rs identifies statically-linked library
    /// functions inside the analysed binary and excludes their
    /// capability hits from the user-facing output via the
    /// existing `lib: true` rule-skip path. Useful primarily on
    /// stripped MSVC C/C++ binaries.
    ///
    /// The capa-rs repo ships a `flirt-sigs/` directory with the
    /// Mandiant FLARE corpus + Maktm's FLIRTDB (Apache-2.0 and
    /// community licensed respectively, ~70 MB, ~195 `.sig` files).
    /// GitHub releases also ship the same content as a
    /// `flirt-sigs-vX.Y.Z.tar.gz` artifact alongside the CLI
    /// binaries.
    ///
    /// Default: `None` — no FLIRT, behaviour identical to
    /// pre-0.4.3. Parse errors on individual files are logged via
    /// the builder's `logger` callback and skipped; an empty
    /// directory returns `Error::InvalidRuleFile`.
    pub fn signatures(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.flirt_signatures = Some(path.into());
        self
    }

    /// Use a pre-built FLIRT matcher for this analysis. Wraps the
    /// matcher in `Arc` and clones the handle on each terminal call,
    /// so the same loaded corpus serves many `from_file` /
    /// `from_buffer` invocations without re-walking the directory or
    /// rebuilding the prefix trie.
    ///
    /// Construct once with [`flirt::FlirtMatcher::from_directory`],
    /// then clone the `Arc` per builder. Takes precedence over
    /// [`Self::signatures`] when both are set.
    ///
    /// ```ignore
    /// use capa::{flirt::FlirtMatcher, FileCapabilities};
    /// use std::sync::Arc;
    ///
    /// let matcher = Arc::new(FlirtMatcher::from_directory(
    ///     "./flirt-sigs".as_ref(),
    ///     &|m| eprintln!("{m}"),
    /// )?);
    ///
    /// for path in samples {
    ///     let fc = FileCapabilities::analyze()
    ///         .rules("./capa-rules")
    ///         .with_flirt_matcher(matcher.clone())
    ///         .from_file(path)?;
    ///     // ...
    /// }
    /// # Ok::<(), capa::Error>(())
    /// ```
    pub fn with_flirt_matcher(mut self, matcher: std::sync::Arc<flirt::FlirtMatcher>) -> Self {
        self.flirt_matcher = Some(matcher);
        self
    }

    /// Terminal — analyse a binary on disk. Routes through capa-rs's
    /// magic-byte format detection (PE → dnfile-then-smda, ELF →
    /// smda, Mach-O → smda) and runs the binary security checklist.
    pub fn from_file(self, file_name: impl AsRef<str>) -> Result<FileCapabilities> {
        let rule_path = self.rules.ok_or(Error::BuilderMissingRules)?;
        let f = file_name.as_ref().to_string();
        let (format, buffer) = get_format(&f)?;
        let extractor = get_file_extractors(
            &f,
            format,
            &buffer,
            self.high_accuracy,
            self.resolve_tailcalls,
        )?;
        let rules_thread_handle = spawn(move || rules::RuleSet::new(&rule_path));
        let rules = match rules_thread_handle.join() {
            Ok(Ok(rules)) => rules,
            Ok(Err(_)) | Err(_) => return Err(Error::DescriptionEvaluationError),
        };

        // Security checks — defaults if caller didn't override.
        let mut security_opts = self.security_checks.unwrap_or_default();
        security_opts.input_file = PathBuf::from(&f);
        let security_checks = security::get_security_checks(&f, &security_opts)?;

        // 0.4.3: load FLIRT signatures if configured. Failures
        // propagate via `?`, but per-file parse errors inside the
        // directory are logged and skipped (best-effort, matches
        // Python capa's behaviour). 0.4.4: a pre-built matcher
        // shared via Arc (from `with_flirt_matcher`) takes
        // precedence and skips the load entirely.
        let owned_matcher = match (&self.flirt_matcher, self.flirt_signatures.as_ref()) {
            (Some(_), _) => None,
            (None, Some(p)) => Some(flirt::FlirtMatcher::from_directory(p, self.logger)?),
            (None, None) => None,
        };
        let flirt_ref: Option<&flirt::FlirtMatcher> =
            self.flirt_matcher.as_deref().or(owned_matcher.as_ref());
        let library_function = make_library_filter(&*extractor, flirt_ref);

        let mut file_capabilities;
        #[cfg(not(feature = "properties"))]
        {
            file_capabilities = FileCapabilities::new()?;
        }
        #[cfg(feature = "properties")]
        {
            // PDB metadata is parsed from the raw buffer (returns
            // None for non-PE / no-debug-dir inputs).
            file_capabilities = FileCapabilities::new(&extractor, Some(&buffer))?;
        }
        #[cfg(not(feature = "verbose"))]
        {
            file_capabilities.security_checks = BTreeSet::from_iter(security_checks);
            let (capabilities, counts, _map_features, library_funcs, _map_features_by_scope) =
                find_capabilities(
                    &rules,
                    &extractor,
                    &*library_function,
                    self.logger,
                    self.features_dump,
                )?;
            if self.features_dump {
                file_capabilities.map_features = _map_features;
                file_capabilities.map_features_by_scope = _map_features_by_scope;
            }
            file_capabilities.library_functions = library_funcs;
            // 0.5.0 (D2): direct move — no iteration, no filter, no
            // BTreeMap re-insert. addr=0 is the file-scope sentinel.
            file_capabilities.feature_counts = counts;
            file_capabilities.update_capabilities(&capabilities)?;
        }
        #[cfg(feature = "verbose")]
        {
            file_capabilities.security_checks = BTreeSet::from_iter(security_checks);
            let (capabilities, counts, _map_features, library_funcs, _map_features_by_scope) =
                find_capabilities(
                    &rules,
                    &extractor,
                    &*library_function,
                    self.logger,
                    self.features_dump,
                )?;
            if self.features_dump {
                file_capabilities.map_features = _map_features;
                file_capabilities.map_features_by_scope = _map_features_by_scope;
            }
            file_capabilities.library_functions = library_funcs;
            // 0.5.0 (D2): verbose path still needs &counts for
            // update_capabilities, so clone here. HashMap clone is
            // a single allocation + memcpy, much cheaper than the
            // per-entry iteration + BTreeMap re-insert.
            file_capabilities.feature_counts = counts.clone();
            file_capabilities.update_capabilities(&capabilities, &counts)?;
        }

        Ok(file_capabilities)
    }

    /// Terminal — analyse a raw byte buffer (shellcode, unpacked
    /// module, memory dump). Bypasses magic-byte format detection,
    /// dnfile, and the security-checks pipeline. `bitness` must be 32
    /// or 64; `base_addr` is the VA the buffer is treated as mapped to
    /// (pass `0` if the caller has no preference).
    pub fn from_buffer(self, raw: &[u8], base_addr: u64, bitness: u32) -> Result<FileCapabilities> {
        let rule_path = self.rules.ok_or(Error::BuilderMissingRules)?;
        // Construct the extractor directly via smda's parse_buffer —
        // get_file_extractors routes on PE/ELF/Mach-O magic, which
        // a raw buffer doesn't have.
        let extractor: Box<dyn extractor::Extractor + '_> =
            Box::new(extractor::smda::Extractor::from_buffer(
                raw,
                base_addr,
                bitness,
                self.high_accuracy,
                self.resolve_tailcalls,
            )?);

        let rules_thread_handle = spawn(move || rules::RuleSet::new(&rule_path));
        let rules = match rules_thread_handle.join() {
            Ok(Ok(rules)) => rules,
            Ok(Err(_)) | Err(_) => return Err(Error::DescriptionEvaluationError),
        };

        // 0.4.3: FLIRT setup — see `from_file` for rationale.
        // 0.4.4: pre-built matcher via `with_flirt_matcher` takes
        // precedence over `signatures(path)` and skips the load.
        let owned_matcher = match (&self.flirt_matcher, self.flirt_signatures.as_ref()) {
            (Some(_), _) => None,
            (None, Some(p)) => Some(flirt::FlirtMatcher::from_directory(p, self.logger)?),
            (None, None) => None,
        };
        let flirt_ref: Option<&flirt::FlirtMatcher> =
            self.flirt_matcher.as_deref().or(owned_matcher.as_ref());
        let library_function = make_library_filter(&*extractor, flirt_ref);

        let mut file_capabilities;
        #[cfg(not(feature = "properties"))]
        {
            file_capabilities = FileCapabilities::new()?;
        }
        #[cfg(feature = "properties")]
        {
            // PDB extraction skipped (no PE header in raw shellcode).
            file_capabilities = FileCapabilities::new(&extractor, None)?;
        }

        #[cfg(not(feature = "verbose"))]
        {
            let (capabilities, counts, _map_features, library_funcs, _map_features_by_scope) =
                find_capabilities(
                    &rules,
                    &extractor,
                    &*library_function,
                    self.logger,
                    self.features_dump,
                )?;
            if self.features_dump {
                file_capabilities.map_features = _map_features;
                file_capabilities.map_features_by_scope = _map_features_by_scope;
            }
            file_capabilities.library_functions = library_funcs;
            // 0.5.0 (D2): see `from_file` for rationale.
            file_capabilities.feature_counts = counts;
            file_capabilities.update_capabilities(&capabilities)?;
        }
        #[cfg(feature = "verbose")]
        {
            let (capabilities, counts, _map_features, library_funcs, _map_features_by_scope) =
                find_capabilities(
                    &rules,
                    &extractor,
                    &*library_function,
                    self.logger,
                    self.features_dump,
                )?;
            if self.features_dump {
                file_capabilities.map_features = _map_features;
                file_capabilities.map_features_by_scope = _map_features_by_scope;
            }
            file_capabilities.library_functions = library_funcs;
            // 0.5.0 (D2): see `from_file` for rationale.
            file_capabilities.feature_counts = counts.clone();
            file_capabilities.update_capabilities(&capabilities, &counts)?;
        }

        Ok(file_capabilities)
    }
}

impl FileCapabilities {
    /// 0.4.0: entry point to the [`AnalyzeBuilder`]. Replaces the
    /// 0.3.x positional `from_file` / `from_buffer` constructors.
    ///
    /// ```ignore
    /// use capa::FileCapabilities;
    ///
    /// let fc = FileCapabilities::analyze()
    ///     .rules("./capa-rules")
    ///     .high_accuracy(true)
    ///     .from_file("Sample.exe")?;
    /// # Ok::<(), capa::Error>(())
    /// ```
    pub fn analyze<'a>() -> AnalyzeBuilder<'a> {
        AnalyzeBuilder::new()
    }

    fn new<'a>(
        // 0.4.0: trait object now carries the buffer lifetime through.
        // Implicit `+ 'static` bound was forcing the input buffer in
        // `from_file` to outlive the function, which the compiler
        // rejected. Explicit `'a` lets the borrow scope match.
        #[cfg(feature = "properties")] extractor: &Box<dyn extractor::Extractor + 'a>,
        // 0.4.0: optional input bytes for PDB / debug-directory parsing.
        // `None` for `from_buffer` (shellcode has no PE header to
        // parse a debug directory out of); `Some` for `from_file`.
        // `smda::xmetadata::parse_pe` is internally a no-op on
        // non-PE / no-debug-dir inputs, so passing the bytes
        // unconditionally is safe even for ELF / Mach-O.
        #[cfg(feature = "properties")] raw: Option<&[u8]>,
    ) -> Result<FileCapabilities> {
        #[cfg(feature = "properties")]
        let (pdb_guid, pdb_age, pdb_filename) = raw
            .and_then(smda::xmetadata::parse_pe)
            .map(|m| (m.pdb_guid, m.pdb_age, m.pdb_filename))
            .unwrap_or_default();

        let ss = FileCapabilities {
            #[cfg(feature = "properties")]
            properties: Properties {
                format: FileCapabilities::get_format(extractor)?,
                arch: FileCapabilities::get_arch(extractor)?,
                os: FileCapabilities::get_os(extractor)?,
                base_address: extractor.get_base_address()? as usize,
                pdb_guid,
                pdb_age,
                pdb_filename,
            },
            attacks: BTreeMap::new(),
            mbc: BTreeMap::new(),
            capability_namespaces: BTreeMap::new(),
            #[cfg(feature = "verbose")]
            features: 0,
            #[cfg(feature = "verbose")]
            functions_capabilities: BTreeMap::new(),
            tags: BTreeSet::new(),
            security_checks: BTreeSet::new(),
            map_features: HashMap::new(),
            capabilities_associations: BTreeMap::new(),
            // 0.5.0 (D1): populated by `from_file` / `from_buffer`
            // after `find_capabilities` returns. Starts empty here
            // because `FileCapabilities::new` knows nothing about the
            // FLIRT pass.
            library_functions: BTreeMap::new(),
            // 0.5.0 (D2): per-function feature counts, populated
            // alongside `library_functions` from the `counts` slot
            // returned by `find_capabilities`. Empty until that fill.
            feature_counts: HashMap::new(),
            // 0.5.0 (D3): scope-keyed feature dump. Only populated
            // when `features_dump` is true; otherwise empty.
            map_features_by_scope: HashMap::new(),
        };
        Ok(ss)
    }

    fn update_capabilities(
        &mut self,
        capabilities: &HashMap<crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
        #[cfg(feature = "verbose")] counts: &HashMap<u64, usize>,
    ) -> Result<()> {
        // 0.4.2: cached at module scope (TAG_BRACKET_RE); was compiled
        // per call, which on hot analyses with thousands of att&ck/mbc
        // entries was real work.
        let re = &*TAG_BRACKET_RE;
        for (rule, caps) in capabilities {
            // 0.4.1: belt-and-suspenders for `lib: true` — even though
            // `get_rules_for_scope` already excludes lib rules from
            // top-level evaluation, a lib rule can still appear in
            // `capabilities` if another rule references it via `match:`
            // and the match fired. Filter here so the user-facing
            // ATT&CK / MBC / namespace / tag output stays clean.
            // Matches Python capa's render-time filtering.
            if rules::is_lib_rule(rule) {
                continue;
            }
            let mut local_attacks_set: BTreeSet<Attacks> = BTreeSet::new();
            let mut local_mbc_set: BTreeSet<Mbc> = BTreeSet::new();

            if let Some(Yaml::Array(attacks)) = rule.meta.get(&Yaml::String("att&ck".to_string())) {
                for p in attacks.iter().filter_map(|item| item.as_str()) {
                    if let Ok(attack) = Attacks::from_str(p) {
                        local_attacks_set.insert(attack);
                    }

                    let parts: Vec<&str> = p.split("::").collect();
                    if parts.len() > 1 {
                        let detail = parts[1..].join("::");
                        if let Some(caps) = re.captures(&detail) {
                            if let Some(tag_match) = caps.name("tag") {
                                self.tags.insert(tag_match.as_str().to_string());
                            }
                        }

                        self.attacks
                            .entry(parts[0].to_string())
                            .or_default()
                            .insert(detail);
                    }
                }
            }

            if let Some(Yaml::Array(mbcs)) = rule.meta.get(&Yaml::String("mbc".to_string())) {
                for p in mbcs.iter().filter_map(|item| item.as_str()) {
                    if let Ok(mbc) = Mbc::from_str(p) {
                        local_mbc_set.insert(mbc);
                    }

                    let parts: Vec<&str> = p.split("::").collect();
                    if parts.len() > 1 {
                        let detail = parts[1..].join("::");
                        if let Some(caps) = re.captures(&detail) {
                            if let Some(tag_match) = caps.name("tag") {
                                self.tags.insert(tag_match.as_str().to_string());
                            }
                        }

                        self.mbc
                            .entry(parts[0].to_string())
                            .or_default()
                            .insert(detail);
                    }
                }
            }

            if let Some(Yaml::String(s)) = rule.meta.get(&Yaml::String("namespace".to_string())) {
                self.capability_namespaces
                    .insert(rule.name.clone(), s.clone());
                let first_non_zero_address = caps
                    .iter()
                    .find(|&&(addr, _)| addr != 0)
                    .map(|&(addr, _)| addr)
                    .unwrap_or(0);

                let _ = self
                    .capabilities_associations
                    .entry(rule.name.clone())
                    .or_insert_with(|| CapabilityAssociation {
                        attack: local_attacks_set.clone(),
                        mbc: local_mbc_set.clone(),
                        namespace: s.clone(),
                        name: rule.name.clone(),
                        address: first_non_zero_address as usize,
                    });
            }

            #[cfg(feature = "verbose")]
            {
                for &(addr, _) in caps {
                    if addr != 0 {
                        self.functions_capabilities
                            .entry(addr)
                            .and_modify(|fc| {
                                fc.capabilities.push(rule.name.clone());
                            })
                            .or_insert_with(|| FunctionCapabilities {
                                address: addr as usize,
                                features: *counts.get(&addr).unwrap_or(&0),
                                capabilities: vec![rule.name.clone()],
                            });
                    }
                }
                self.features = counts[&0];
            }
        }

        Ok(())
    }

    pub fn construct_json_for_capabilities_associations(
        &mut self,
        filter: Option<String>,
    ) -> Value {
        if let Some(f) = filter {
            let filters: Vec<&str> = f.split('|').collect();
            self.map_features
                .retain(|k, _v| filters.iter().any(|filter| k.contains(filter)));
        }

        let mut rules = serde_json::Map::new();
        for (name, association) in &self.capabilities_associations {
            let attacks_json = association
                .attack
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "subtechnique": a.subtechnique,
                        "tactic": a.tactic,
                        "technique": a.technique,
                    })
                })
                .collect::<Vec<_>>();

            let mbc_json = association
                .mbc
                .iter()
                .map(|m| {
                    json!({
                        "objective": m.objective,
                        "behavior": m.behavior,
                        "method": m.method,
                        "id": m.id,
                    })
                })
                .collect::<Vec<_>>();

            let association_json = json!({
                "attacks": attacks_json,
                "mbc": mbc_json,
                "namespace": association.namespace,
                "name": association.name,
                "address": association.address,
            });

            rules.insert(name.clone(), association_json);
        }
        Value::Object(rules)
    }
    pub fn serialize_file_capabilities(
        &mut self,
        filter: Option<String>,
    ) -> serde_json::Result<String> {
        let associations_json = self.construct_json_for_capabilities_associations(filter);
        let mut fc_json = serde_json::to_value(self.clone())?;
        fc_json
            .as_object_mut()
            .unwrap()
            .insert("rules".to_string(), associations_json);
        if let Some(map_features) = fc_json.get("map_features") {
            if map_features.as_object().is_some_and(|m| m.is_empty()) {
                fc_json.as_object_mut().unwrap().remove("map_features");
            }
        }

        serde_json::to_string(&fc_json)
    }

    // 0.4.0: trait-object parameters carry an explicit `'_` (anonymous
    // lifetime) — without it the compiler infers `+ 'static`, which
    // forces the smda/dnfile report (and the underlying buffer) to
    // outlive the call. The actual borrow scope is much narrower:
    // these helpers don't hold onto `extractor` past the call boundary.
    //
    // 0.4.0: gated on `properties` — these are only called from
    // `FileCapabilities::new`'s properties-feature-gated body.
    // Without the gate, building `--no-default-features` produces
    // dead-code warnings.
    #[cfg(feature = "properties")]
    fn get_format(extractor: &Box<dyn extractor::Extractor + '_>) -> Result<FileFormat> {
        Ok(extractor.format())
    }

    #[cfg(feature = "properties")]
    fn get_arch(extractor: &Box<dyn extractor::Extractor + '_>) -> Result<FileArchitecture> {
        // 0.5.0 (task #236): ask the extractor for the real
        // architecture instead of inferring from bitness. The old
        // path mapped `bitness == 64 → AMD64` unconditionally, which
        // silently mislabelled every AArch64 binary that smda 0.6
        // started producing as AMD64. The trait method
        // `arch()` now returns smda's `DisassemblyReport.architecture`
        // directly for the smda backend, and the existing CIL-
        // bitness inference for dnfile.
        extractor.arch()
    }

    #[cfg(feature = "properties")]
    fn get_os(extractor: &Box<dyn extractor::Extractor + '_>) -> Result<Os> {
        // 0.5.0: capa's `Os` enum gained `MACOS` + `IOS`; route
        // Mach-O to MACOS so `os: macos` rules fire and `os: linux`
        // rules stop firing incorrectly. Pre-0.5.0 the fall-through
        // (`_ => Os::LINUX`) caught Mach-O as a placeholder.
        match extractor.format() {
            FileFormat::PE | FileFormat::DOTNET => Ok(Os::WINDOWS),
            FileFormat::Macho => Ok(Os::MACOS),
            _ => Ok(Os::LINUX),
        }
    }
}

// 0.4.0: extractor parameter explicitly carries `'_` (anonymous
// lifetime). Without it the trait object would be inferred as
// `+ 'static`, which would force the caller's input buffer in
// `FileCapabilities::from_file` to outlive the function — and the
// buffer is a local `Vec<u8>` that doesn't. The borrow scope is
// the function body, which `'_` correctly captures.
fn find_function_capabilities<'a>(
    ruleset: &'a rules::RuleSet,
    extractor: &Box<dyn extractor::Extractor + '_>,
    f: &Box<dyn extractor::Function>,
    logger: &(dyn Fn(&str) + Sync + Send),
    // 0.5.0 (D3): scope-keyed feature dump. Outer key is one of
    // "function", "basic_block", "instruction" (file scope is filled
    // by `find_file_capabilities`). When `features_dump` is false
    // this stays empty; when true each extractor call's output is
    // tagged with the scope it came from before being merged. The
    // existing flat `map_features` field on `FileCapabilities` is
    // derived from this by collapsing the scope keys.
    map_features_by_scope: &mut HashMap<&'static str, HashMap<rules::features::Feature, Vec<u64>>>,
    features_dump: bool,
) -> Result<(
    HashMap<&'a rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    HashMap<&'a rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut function_features: HashMap<rules::features::Feature, Vec<u64>> = HashMap::new();

    for (feature, va) in extractor.extract_global_features()? {
        // Globals are conceptually function-scope (they fold into
        // each function's evaluation set). Tagged "function" for the
        // dump.
        if features_dump {
            map_features_by_scope
                .entry("function")
                .or_default()
                .entry(feature.clone())
                .or_default()
                .push(va);
        }
        function_features.entry(feature).or_default().push(va);
    }

    for (feature, va) in extractor.extract_function_features(f)? {
        if features_dump {
            map_features_by_scope
                .entry("function")
                .or_default()
                .entry(feature.clone())
                .or_default()
                .push(va);
        }
        function_features.entry(feature).or_default().push(va);
    }

    // Condition for .NET and add file features if necessary
    if extractor.is_dot_net() {
        for (feature, va) in extractor.extract_file_features()? {
            if features_dump {
                map_features_by_scope
                    .entry("file")
                    .or_default()
                    .entry(feature.clone())
                    .or_default()
                    .push(va);
            }
            function_features.entry(feature).or_default().push(va);
        }
    }

    let blocks = extractor.get_basic_blocks(f)?;
    let mut bb_matches: HashMap<&crate::rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();
    for bb in blocks.iter() {
        let mut bb_features: HashMap<crate::rules::features::Feature, Vec<u64>> = HashMap::new();
        for (feature, va) in itertools::chain!(
            extractor.extract_basic_block_features(f, &bb)?,
            extractor.extract_global_features()?
        ) {
            if features_dump {
                map_features_by_scope
                    .entry("basic_block")
                    .or_default()
                    .entry(feature.clone())
                    .or_default()
                    .push(va);
            }
            bb_features.entry(feature.clone()).or_default().push(va);
            function_features.entry(feature).or_default().push(va);
        }

        let insns = extractor.get_instructions(f, &bb)?;
        for insn in insns.iter() {
            for (feature, va) in extractor.extract_insn_features(f, insn)? {
                if features_dump {
                    map_features_by_scope
                        .entry("instruction")
                        .or_default()
                        .entry(feature.clone())
                        .or_default()
                        .push(va);
                }
                bb_features.entry(feature.clone()).or_default().push(va);
                function_features.entry(feature).or_default().push(va);
            }
        }

        let (_, matches) = match_fn(&ruleset.basic_block_rules, &bb_features, bb.0, logger)?;
        for (rule, res) in matches {
            bb_matches
                .entry(rule)
                .or_default()
                .extend(res.iter().cloned());
            index_rule_matches(
                &mut function_features,
                rule,
                res.iter().map(|&(va, _)| va).collect(),
            )?;
        }
    }

    let (_, function_matches) = match_fn(
        &ruleset.function_rules,
        &function_features,
        &f.offset(),
        logger,
    )?;

    Ok((function_matches, bb_matches, function_features.len()))
}
fn aggregate_matches<'a, T: Clone>(
    all_matches: &mut HashMap<&'a rules::Rule, Vec<T>>,
    new_matches: &HashMap<&'a rules::Rule, Vec<T>>,
) {
    for (rule, res) in new_matches {
        all_matches.entry(rule).or_default().extend(res.clone());
    }
}

// 0.4.0: extractor parameter explicitly carries `'_` to allow
// non-`'static` trait objects — see `find_function_capabilities` for
// the underlying reason.
//
// 0.5.0: `library_function` closure — when the closure returns
// `Some(name)` for a function's address, that function is skipped
// (no find_function_capabilities call, no contributions to the
// matches map) and the (address, name) pair is collected for the
// caller. When `.signatures(path)` or `.with_flirt_matcher(arc)` is
// configured the closure consults a `FlirtMatcher`; otherwise it's a
// no-op (`|_| None`) and behaviour is identical to pre-0.4.3.
//
// 0.4.3 used `Fn(u64) -> bool` and discarded the matched name. 0.5.0
// returns `Option<String>` so the name surfaces on
// `FileCapabilities::library_functions` for output parity with
// Python capa's JSON.
//
// Partitioning happens sequentially before the rayon parallel loop:
// FLIRT match is one trie traversal per function so the sequential
// pass is fast, and it keeps the parallel loop free of side effects
// on the library-functions accumulator.
fn find_capabilities(
    ruleset: &rules::RuleSet,
    extractor: &Box<dyn extractor::Extractor + '_>,
    library_function: &(dyn Fn(u64) -> Option<String> + Sync + Send),
    logger: &(dyn Fn(&str) + Sync + Send),
    features_dump: bool,
) -> Result<(
    HashMap<rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    HashMap<u64, usize>,
    // 0.5.0 (D3): flat dump (backwards-compat). Derived from the
    // scope-keyed accumulator by collapsing scope keys.
    HashMap<String, HashMap<String, HashSet<u64>>>,
    BTreeMap<u64, String>,
    // 0.5.0 (D3): scope-keyed dump. Outer key is the scope name
    // ("file" | "function" | "basic_block" | "instruction"); inner
    // shape matches the flat dump. Empty when `features_dump` is
    // false. Parity with Python capa's per-scope feature breakdown.
    HashMap<String, HashMap<String, HashMap<String, HashSet<u64>>>>,
)> {
    use rayon::prelude::*;

    let mut all_function_matches: HashMap<&rules::Rule, Vec<(u64, (bool, Vec<u64>))>> =
        HashMap::new();
    let mut all_bb_matches: HashMap<&rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();

    let mut meta = HashMap::new();

    let functions = extractor.get_functions()?;
    logger("functions capabilities started");

    // 0.5.0 (D3): scope-keyed accumulator. The flat `map_features` is
    // derived at the end by collapsing scope keys.
    let mut map_features_by_scope: HashMap<
        &'static str,
        HashMap<crate::rules::features::Feature, Vec<u64>>,
    > = HashMap::new();

    // 0.5.0: pre-partition FLIRT-marked library functions out of the
    // analysis set. The names are collected for the
    // `library_functions` output field; the addresses are the only
    // thing the parallel loop needs to know about.
    let mut library_functions: BTreeMap<u64, String> = BTreeMap::new();
    let mut real_functions: Vec<_> = Vec::with_capacity(functions.len());
    let total_input = functions.len();
    for (addr, f) in functions.iter() {
        match library_function(*addr) {
            Some(name) => {
                logger(&format!(
                    "flirt: skipping library function at 0x{:02x} as {}",
                    addr, name
                ));
                library_functions.insert(*addr, name);
            }
            None => {
                real_functions.push((addr, f));
            }
        }
    }
    logger(&format!(
        "flirt: {} library / {} non-library out of {} total functions",
        library_functions.len(),
        real_functions.len(),
        total_input
    ));

    // 0.4.2: parallelise the per-function analysis. Each
    // `find_function_capabilities` call is pure — it reads the
    // extractor + ruleset and returns matches without touching shared
    // state. Rayon's work-stealing scheduler distributes functions
    // across worker threads; aggregation happens single-threaded
    // afterwards.
    //
    // BTreeMap lacks a `par_iter` impl, so we collect to a Vec first.
    // The Vec is cheap (just borrowed references), and the borrow
    // outlives the rayon scope below.
    let function_list = real_functions;
    let total = function_list.len();

    let per_function: Vec<(u64, _, _, usize, HashMap<_, _>)> = function_list
        .par_iter()
        .enumerate()
        .map(|(index, (function_address, f))| -> Result<_> {
            // Each worker accumulates into a thread-local scope-keyed
            // dump. If `features_dump` is off we never write to it so
            // the allocation is essentially free.
            let mut local_by_scope: HashMap<
                &'static str,
                HashMap<crate::rules::features::Feature, Vec<u64>>,
            > = HashMap::new();
            let (function_matches, bb_matches, feature_count) = find_function_capabilities(
                ruleset,
                extractor,
                f,
                logger,
                &mut local_by_scope,
                features_dump,
            )?;
            logger(&format!(
                "function 0x{:02x} {} from {} processed",
                function_address, index, total
            ));
            // Convert HashMap<&Rule, ...> to HashMap<&Rule (with the
            // ruleset's lifetime)> by collecting; references are
            // already 'a-bound from `ruleset`, no clone needed.
            Ok((
                **function_address,
                function_matches,
                bb_matches,
                feature_count,
                local_by_scope,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    // Sequential merge — small per-function HashMaps fold into the
    // shared accumulators. With ~hundreds of functions and ~thousands
    // of matches total this is microseconds; the parallel work above
    // is the only place that benefits from threading.
    for (addr, function_matches, bb_matches, feature_count, local_by_scope) in per_function {
        meta.insert(addr, feature_count);
        aggregate_matches(&mut all_function_matches, &function_matches);
        aggregate_matches(&mut all_bb_matches, &bb_matches);
        if features_dump {
            for (scope, scope_map) in local_by_scope {
                let dest = map_features_by_scope.entry(scope).or_default();
                for (k, v) in scope_map {
                    dest.entry(k).or_default().extend(v);
                }
            }
        }
    }

    logger("functions capabilities finish");
    //# collection of features that captures the rule matches within function and BB scopes.
    //# mapping from feature (matched rule) to set of addresses at which it matched.
    let mut function_and_lower_features = HashMap::new();
    for (rule, results) in itertools::chain!(&all_function_matches, &all_bb_matches) {
        let locations: Vec<u64> = results.iter().map(|a| a.0).collect();
        index_rule_matches(&mut function_and_lower_features, rule, locations)?;
    }

    let (all_file_matches, feature_count) = find_file_capabilities(
        ruleset,
        extractor,
        &function_and_lower_features,
        logger,
        &mut map_features_by_scope,
        features_dump,
    )?;

    let mut matches = HashMap::new();
    for (rule, res) in itertools::chain!(&all_bb_matches, &all_function_matches, &all_file_matches)
    {
        matches.insert((*rule).clone(), res.clone());
    }

    meta.insert(0, feature_count);

    // 0.5.0 (D3): build both outputs from the scope-keyed
    // accumulator. The flat `map_features_string` collapses across
    // scopes (parity with pre-0.5.0 shape); the scope-keyed
    // `map_features_by_scope_string` preserves the scope dimension.
    // Both are populated only when features_dump was true; otherwise
    // they're empty (no extractor calls wrote into
    // `map_features_by_scope`).
    let mut map_features_string: HashMap<String, HashMap<String, HashSet<u64>>> = HashMap::new();
    let mut map_features_by_scope_string: HashMap<
        String,
        HashMap<String, HashMap<String, HashSet<u64>>>,
    > = HashMap::new();

    for (scope, scope_map) in &map_features_by_scope {
        let scope_string = (*scope).to_string();
        let scope_dest = map_features_by_scope_string
            .entry(scope_string)
            .or_default();
        for (key, offsets) in scope_map {
            let feature_type = key.get_name();
            let feature_value = key.get_value()?;

            // Scope-keyed copy.
            let by_value = scope_dest
                .entry(feature_type.clone())
                .or_default()
                .entry(feature_value.clone())
                .or_default();
            for offset in offsets {
                by_value.insert(*offset);
            }

            // Flat copy — collapsed across scopes for backwards
            // compatibility with pre-0.5.0 consumers reading
            // `map_features`.
            let flat_by_value = map_features_string
                .entry(feature_type)
                .or_default()
                .entry(feature_value)
                .or_default();
            for offset in offsets {
                flat_by_value.insert(*offset);
            }
        }
    }

    Ok((
        matches,
        meta,
        map_features_string,
        library_functions,
        map_features_by_scope_string,
    ))
}

// 0.4.0: extractor parameter explicitly carries `'_` to allow
// non-`'static` trait objects — see `find_function_capabilities` for
// the underlying reason.
fn find_file_capabilities<'a>(
    ruleset: &'a rules::RuleSet,
    extractor: &Box<dyn extractor::Extractor + '_>,
    function_features: &HashMap<rules::features::Feature, Vec<u64>>,
    logger: &(dyn Fn(&str) + Sync + Send),
    // 0.5.0 (D3): see `find_function_capabilities` for shape. This
    // call populates the "file" scope bucket with features extracted
    // at file scope + globals. Function-scope features cascaded into
    // the file evaluation set (for cross-scope match support) are
    // NOT re-tagged "file" — they keep their original scope to avoid
    // double-counting in the dump.
    map_features_by_scope: &mut HashMap<&'static str, HashMap<rules::features::Feature, Vec<u64>>>,
    features_dump: bool,
) -> Result<(
    HashMap<&'a rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
    usize,
)> {
    let mut file_features: HashMap<rules::features::Feature, Vec<u64>> = HashMap::new();
    for (feature, va) in itertools::chain!(
        extractor.extract_file_features()?,
        extractor.extract_global_features()?
    ) {
        if features_dump {
            map_features_by_scope
                .entry("file")
                .or_default()
                .entry(feature.clone())
                .or_default()
                .push(va);
        }
        file_features.entry(feature.clone()).or_default().push(va);
    }

    for (feature, addresses) in function_features {
        file_features
            .entry(feature.clone())
            .or_default()
            .extend(addresses.iter().cloned());
    }

    let (_, matches) = match_fn(&ruleset.file_rules, &file_features, &0x0, logger)?;

    Ok((matches, file_features.len()))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionCapabilities {
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    address: usize,
    features: usize,
    capabilities: Vec<String>,
}

fn parse_parts_id(s: &str) -> Result<(Vec<String>, String)> {
    // 0.4.2: cached at module scope (PARTS_ID_RE); was compiled per call.
    let re = &*PARTS_ID_RE;
    if let Some(caps) = re.captures(s) {
        let parts_str = caps.get(1).map_or("", |m| m.as_str());
        let parts: Vec<String> = parts_str
            .split("::")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let id = caps.get(2).map_or("", |m| m.as_str()).to_string();
        Ok((parts, id))
    } else {
        Err(Error::InvalidRule(0, s.to_string()))
    }
}
#[cfg(feature = "properties")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Properties {
    pub format: FileFormat,
    pub arch: FileArchitecture,
    pub os: Os,
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    pub base_address: usize,
    // 0.4.0: PDB debug metadata surfaced from smda's xmetadata block.
    // Populated only for PE inputs that carry a CodeView debug
    // directory entry. `None` for ELF/Mach-O/shellcode, and for PEs
    // built without /DEBUG. Serialized only when present so existing
    // JSON consumers that don't know about these fields don't see
    // surprise `null`s. Symbol-server lookups (Microsoft SymSrv,
    // Mozilla, Chromium) key off `{pdb_filename, pdb_guid + pdb_age}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb_age: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb_filename: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Attacks {
    pub id: String,
    pub subtechnique: String,
    pub tactic: String,
    pub technique: String,
}
impl Attacks {
    fn from_str(s: &str) -> Result<Self> {
        let (parts, id) = parse_parts_id(s)?;
        let tactic = parts.first().cloned().unwrap_or_default();
        let technique = parts.get(1).cloned().unwrap_or_default();
        let subtechnique = parts.get(2).cloned().unwrap_or_default();

        Ok(Self {
            tactic,
            technique,
            subtechnique,
            id,
        })
    }
}

impl Default for Attacks {
    fn default() -> Self {
        Attacks {
            id: "".to_string(),
            subtechnique: "".to_string(),
            tactic: "".to_string(),
            technique: "".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Mbc {
    pub behavior: String,
    pub id: String,
    pub objective: String,
    pub method: String,
}
impl Default for Mbc {
    fn default() -> Self {
        Mbc {
            behavior: "".to_string(),
            id: "".to_string(),
            objective: "".to_string(),
            method: "".to_string(),
        }
    }
}
impl Mbc {
    fn from_str(s: &str) -> Result<Self> {
        let (parts, id) = parse_parts_id(s)?;
        let objective = parts.first().cloned().unwrap_or_default();
        let behavior = parts.get(1).cloned().unwrap_or_default();
        let method = parts.get(2).cloned().unwrap_or_default();

        Ok(Self {
            objective,
            behavior,
            method,
            id,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CapabilityAssociation {
    pub attack: BTreeSet<Attacks>,
    pub mbc: BTreeSet<Mbc>,
    pub namespace: String,
    pub name: String,
    pub address: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileCapabilities {
    #[cfg(feature = "properties")]
    pub properties: Properties,
    pub attacks: BTreeMap<String, BTreeSet<String>>,
    pub mbc: BTreeMap<String, BTreeSet<String>>,
    pub capability_namespaces: BTreeMap<String, String>,
    #[cfg(feature = "verbose")]
    pub features: usize,
    #[cfg(feature = "verbose")]
    pub functions_capabilities: BTreeMap<u64, FunctionCapabilities>,
    pub tags: BTreeSet<String>,
    pub security_checks: BTreeSet<SecurityCheckStatus>,
    pub map_features: HashMap<String, HashMap<String, HashSet<u64>>>,
    pub capabilities_associations: BTreeMap<String, CapabilityAssociation>,
    /// 0.5.0 (D1): map from function VA to the FLIRT-resolved
    /// library-function name for every function that the configured
    /// `FlirtMatcher` matched and that capa-rs therefore skipped
    /// during capability analysis. Empty when no signatures were
    /// configured (matches pre-0.5.0 behaviour). Parity with Python
    /// capa's JSON `library_functions` output — gives consumers
    /// visibility into what was filtered as MSVC CRT / ATL / OpenSSL
    /// / etc., so a missing capability can be traced back to a
    /// FLIRT skip rather than a rule miss.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub library_functions: BTreeMap<u64, String>,

    /// 0.5.0 (D2): map from function VA to the number of features
    /// emitted for that function during capability analysis. The
    /// `addr=0` sentinel entry carries the file-scope count.
    /// Skipped FLIRT-marked library functions (see
    /// `library_functions`) don't appear here. Parity with Python
    /// capa's `StaticFeatureCounts.functions` JSON output — needed
    /// for `capa --json` diffing and any consumer doing per-function
    /// statistics over a binary.
    ///
    /// `HashMap` (not `BTreeMap`) because the source type from
    /// `find_capabilities` is already a `HashMap` and we can move
    /// the whole map into this field without a per-entry re-insert.
    /// Sorted-order presentation is the consumer's responsibility
    /// (cheap one-shot sort on the way out).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub feature_counts: HashMap<u64, usize>,

    /// 0.5.0 (D3): scope-keyed feature dump. Outer key is the scope
    /// name (`"file"`, `"function"`, `"basic_block"`,
    /// `"instruction"`); inner shape matches `map_features`. Only
    /// populated when `AnalyzeBuilder::features_dump(true)` is set —
    /// otherwise empty, like `map_features`.
    ///
    /// Parity with Python capa's per-scope feature breakdown. The
    /// existing flat `map_features` field is preserved (and derived
    /// from this by collapsing scope keys) so pre-0.5.0 consumers
    /// reading `map_features` continue to work unchanged. New code
    /// that needs to know whether a feature was emitted at function
    /// vs instruction scope should consult this field instead.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub map_features_by_scope: HashMap<String, HashMap<String, HashMap<String, HashSet<u64>>>>,
}

fn match_fn<'a>(
    rules: &'a [rules::Rule],
    features: &HashMap<rules::features::Feature, Vec<u64>>,
    va: &u64,
    logger: &(dyn Fn(&str) + Sync + Send),
) -> Result<(
    HashMap<rules::features::Feature, Vec<u64>>,
    HashMap<&'a rules::Rule, Vec<(u64, (bool, Vec<u64>))>>,
)> {
    let mut results: HashMap<&rules::Rule, Vec<(u64, (bool, Vec<u64>))>> = HashMap::new();
    let mut features = features.clone();
    for (_index, rule) in rules.iter().enumerate() {
        logger(&format!(
            "\t\t\tmatches rule {} from {}",
            _index,
            rules.len()
        ));
        if let Ok(res) = rule.evaluate(&features) {
            if res.0 {
                match results.get_mut(rule) {
                    Some(s) => {
                        s.push((*va, res));
                    }
                    _ => {
                        results.insert(rule, vec![(*va, res)]);
                    }
                }
                index_rule_matches(&mut features, rule, vec![*va])?;
            }
        }
    }
    Ok((features, results))
}

fn index_rule_matches(
    features: &mut HashMap<rules::features::Feature, Vec<u64>>,
    rule: &rules::Rule,
    locations: Vec<u64>,
) -> Result<()> {
    let matched_rule_feature = rules::features::Feature::MatchedRule(
        rules::features::MatchedRuleFeature::new(&rule.name, "")?,
    );

    features
        .entry(matched_rule_feature.clone())
        .or_default()
        .extend(locations.iter().cloned());

    if let Some(Yaml::String(namespace)) = rule.meta.get(&Yaml::String("namespace".to_string())) {
        let parts: Vec<&str> = namespace.split('/').collect();
        for i in 0..parts.len() {
            let sub_namespace = parts[..=i].join("/");
            let ns_feature = crate::rules::features::Feature::MatchedRule(
                crate::rules::features::MatchedRuleFeature::new(&sub_namespace, "")?,
            );
            features
                .entry(ns_feature)
                .or_default()
                .extend(locations.iter().cloned());
        }
    }
    Ok(())
}

fn get_format(f: &str) -> Result<(FileFormat, Vec<u8>)> {
    let buffer = std::fs::read(f)?;
    // 0.4.0: Mach-O detection added. Magic bytes cover the four Mach-O
    // flavours: 32-bit and 64-bit, both little-endian (Intel/ARM native)
    // and big-endian (PowerPC / fat-arch byte-swapped). Fat (universal)
    // binaries are not yet routed here — smda's Mach-O loader picks the
    // matching slice itself when called via `from_file` on a fat binary.
    if buffer.starts_with(b"MZ") {
        Ok((FileFormat::PE, buffer))
    } else if buffer.starts_with(b"\x7fELF") {
        Ok((FileFormat::ELF, buffer))
    } else if is_macho_magic(&buffer) {
        Ok((FileFormat::Macho, buffer))
    } else {
        Err(Error::UnsupportedFormatError)
    }
}

/// 0.4.0: returns true if `buf` starts with any Mach-O magic — thin
/// 32-bit (`feedface`), thin 64-bit (`feedfacf`), or the byte-swapped
/// variants for the opposite endianness.
///
/// 0.5.0: fat/universal magics (`cafebabe` + 64-bit `cafebabf`, plus
/// the byte-swapped pair) are now also accepted. Apple-Silicon macOS
/// system binaries (`/bin/ls`, `/usr/bin/file`, …) ship as universal
/// binaries — without this, `capa /bin/ls` returned
/// `UnsupportedFormatError` even though smda's
/// `extract_macho_with_offset` has explicit fat-slice selection wired
/// up. Caveat: `cafebabe` is also the Java `.class` file magic.
/// goblin's `Mach::parse` rejects class files (the nfat_arch field
/// fails its sanity check), so misrouting a `.class` file here
/// surfaces as a smda parse error rather than a silent
/// misinterpretation.
fn is_macho_magic(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    matches!(
        &buf[..4],
        b"\xfe\xed\xfa\xce"  // MH_MAGIC      (32-bit, host-endian)
        | b"\xce\xfa\xed\xfe" // MH_CIGAM      (32-bit, swapped)
        | b"\xfe\xed\xfa\xcf" // MH_MAGIC_64   (64-bit, host-endian)
        | b"\xcf\xfa\xed\xfe" // MH_CIGAM_64   (64-bit, swapped)
        | b"\xca\xfe\xba\xbe" // FAT_MAGIC     (32-bit fat header)
        | b"\xbe\xba\xfe\xca" // FAT_CIGAM     (swapped)
        | b"\xca\xfe\xba\xbf" // FAT_MAGIC_64  (64-bit fat header)
        | b"\xbf\xba\xfe\xca" // FAT_CIGAM_64  (swapped)
    )
}

/// 0.4.0: returns `Box<dyn extractor::Extractor + 'a>` — the boxed
/// extractor borrows from `data` for the lifetime `'a`. dnfile's
/// `Extractor::new` likewise switched from `(file_path: &str)` (which
/// read internally) to `(data: &'a [u8])` (which borrows). The caller
/// reads the file once into a `Vec<u8>` and passes `&buf` here.
fn get_file_extractors<'a>(
    f: &str,
    format: FileFormat,
    data: &'a [u8],
    high_accuracy: bool,
    resolve_tailcalls: bool,
) -> Result<Box<dyn extractor::Extractor + 'a>> {
    match format {
        FileFormat::PE => {
            // PE first tries dnfile (managed/.NET). If dnfile rejects
            // the file (native PE, not a CLR image), fall back to smda.
            if let Ok(e) = extractor::dnfile::Extractor::new(data) {
                Ok(Box::new(e))
            } else {
                Ok(Box::new(extractor::smda::Extractor::new(
                    f,
                    high_accuracy,
                    resolve_tailcalls,
                    data,
                )?))
            }
        }
        // 0.4.0: ELF and Mach-O both route through smda — smda 0.5's
        // loader dispatches on magic bytes internally and produces a
        // unified DisassemblyReport regardless of source format.
        FileFormat::ELF | FileFormat::Macho => Ok(Box::new(extractor::smda::Extractor::new(
            f,
            high_accuracy,
            resolve_tailcalls,
            data,
        )?)),
        _ => Ok(Box::new(extractor::smda::Extractor::new(
            f,
            high_accuracy,
            resolve_tailcalls,
            data,
        )?)),
    }
}
