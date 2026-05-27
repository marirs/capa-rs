//! FLIRT library-function recognition (0.4.4).
//!
//! Drives the [`fast-flirt`] engine to identify statically-linked
//! library functions (MSVC CRT, ATL/MFC, OpenSSL, zlib, etc.) inside
//! an analysed binary. When a function matches a known library
//! signature, capa-rs flags it as a library function and the existing
//! `lib: true` rule-skip path (introduced in 0.4.1) excludes its
//! capability hits from the user-facing output — so a stripped MSVC
//! malware sample doesn't drown the real malicious capabilities in
//! `memcpy` / `strlen` / `_RTC_CheckEsp` noise.
//!
//! [`fast-flirt`]: https://crates.io/crates/fast-flirt
//!
//! ## Coverage
//!
//! The Mandiant FLARE signature corpus (Apache-2.0, lives in
//! `mandiant/capa/sigs/`) covers stripped MSVC C/C++ binaries —
//! roughly 70%+ of typical malware-triage workloads. Other
//! toolchains are better served by smda's symbol-based filtering:
//!
//! - Rust → `rustc-demangle` (already wired in smda 0.4.2)
//! - Go → pclntab parser (already wired in smda 0.4.2)
//! - MinGW → DWARF resolver (smda 0.4.2)
//! - Delphi → VMT scanner (smda 0.4.2)
//! - .NET → handled by dnfile partitioning
//!
//! No open-source FLIRT signature corpus exists for Rust stdlib, Go
//! stdlib, libc6, or libstdc++. Generating them requires the
//! proprietary Hex-Rays FLAIR toolkit.
//!
//! ## Limitations vs. Python capa
//!
//! - **No recursive reference resolution yet.** Python's driver
//!   walks a matched signature's `reference` names against the
//!   function's callees to disambiguate trivial wrappers. capa-rs
//!   0.4.3 ships the simpler "first matching signature wins"
//!   policy. For most MSVC patterns this gives the same answer
//!   because the head-bytes + CRC are unique enough. Refinement is
//!   tracked as a follow-up.
//! - **No .pat.gz support yet** — only `.sig` (binary) and `.pat`
//!   (ASCII) are accepted. The Mandiant FLARE corpus ships as
//!   `.sig`, so this isn't a practical limitation for the default
//!   workflow.
//!
//! ## Why a hand-rolled walker rather than `fast_flirt::FlirtSet::load_dir`
//!
//! fast-flirt's `load_dir` fails fast on the first malformed file.
//! capa-rs prefers best-effort loading (matches Python capa's
//! behaviour) — log + skip — so it can keep going past a single
//! corrupt `.sig`. The hand-rolled `walkdir` loop here also:
//! 1. Reports each parse failure through the user's `logger`.
//! 2. Counts skipped `.pat.gz` files separately so users can decide
//!    whether to gunzip their corpus.
//! 3. Skips symlinks explicitly (consistent with the engine's own
//!    walker policy).

use fast_flirt::{FlirtSet, FlirtSetBuilder};
use std::path::Path;

use crate::{Error, Result};

/// Number of leading bytes to feed the matcher per function. Matches
/// Python capa's lookahead. The FLIRT head pattern is typically 32
/// bytes, and the optional tail extends further; 256 covers every
/// signature in the Mandiant FLARE corpus with margin.
pub(crate) const FLIRT_LOOKAHEAD_BYTES: u32 = 256;

/// FLIRT signature matcher loaded from a directory of `.sig` / `.pat`
/// files. Construction is one-time at builder configuration; matching
/// is per-function during analysis. Cheap to share across rayon
/// worker threads — `FlirtSet` is `Send + Sync`.
///
/// To analyse many binaries against the same corpus, build one
/// `FlirtMatcher` and wrap it in `Arc` — pass via
/// `AnalyzeBuilder::with_flirt_matcher` to amortise the ~360 ms /
/// ~70 MB load across runs.
pub struct FlirtMatcher {
    set: FlirtSet,
    sig_count: usize,
    source_count: usize,
}

impl FlirtMatcher {
    /// Load all `.sig` and `.pat` files from a directory tree
    /// (recursive). Files that fail to parse are reported through
    /// `logger` and skipped — they don't abort the build, matching
    /// Python capa's best-effort behaviour. `.pat.gz` files are
    /// counted and surfaced in the final summary (gzipped pat is a
    /// 0.4.x limitation — gunzip ahead of time as a workaround).
    ///
    /// Returns an error if `path` can't be read or contains no valid
    /// signatures. A successful matcher with zero signatures would
    /// silently mark nothing as a library function — better to fail
    /// loudly than to ship that surprise.
    pub fn from_directory(path: &Path, logger: &(dyn Fn(&str) + Sync + Send)) -> Result<Self> {
        if !path.is_dir() {
            return Err(Error::InvalidRuleFile(format!(
                "flirt: signatures path is not a directory: {}",
                path.display()
            )));
        }

        // Per-file best-effort accumulation via FlirtSetBuilder. We
        // walk with `walkdir` so a single malformed `.sig` can be
        // logged and skipped instead of aborting the whole load
        // (matches Python capa behaviour). `FlirtSet::load_dir`
        // exists in fast-flirt but is fail-fast on first error;
        // that's not what we want here.
        let mut builder = FlirtSetBuilder::new();
        let mut source_count = 0usize;
        let mut gz_skipped = 0usize;

        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            // Skip symlinks — consistent with fast-flirt's own walker
            // and prevents a symlinked file from being read at all.
            // (follow_links(false) only stops directory descent.)
            if entry.file_type().is_symlink() {
                continue;
            }
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Case-insensitive extension match — many vendor zips
            // ship `.SIG` uppercase. fast-flirt's own load_dir does
            // the same lowercase normalisation.
            let lower = name.to_ascii_lowercase();
            let parsed_ok = if lower.ends_with(".sig") {
                match std::fs::read(p) {
                    Ok(bytes) => match builder.add_sig(&bytes) {
                        Ok(_) => true,
                        Err(e) => {
                            logger(&format!("flirt: failed to parse .sig {}: {}", name, e));
                            false
                        }
                    },
                    Err(e) => {
                        logger(&format!("flirt: failed to read .sig {}: {}", name, e));
                        false
                    }
                }
            } else if lower.ends_with(".pat.gz") {
                // 0.4.x limitation: gzipped pat files not yet
                // unpacked. Counted separately so the summary line
                // can call attention to it.
                gz_skipped += 1;
                false
            } else if lower.ends_with(".pat") {
                match std::fs::read_to_string(p) {
                    Ok(text) => match builder.add_pat(&text) {
                        Ok(_) => true,
                        Err(e) => {
                            logger(&format!("flirt: failed to parse .pat {}: {}", name, e));
                            false
                        }
                    },
                    Err(e) => {
                        logger(&format!("flirt: failed to read .pat {}: {}", name, e));
                        false
                    }
                }
            } else {
                false
            };

            if parsed_ok {
                source_count += 1;
            }
        }

        // `build()` itself can fail (arena bounds validation in
        // fast-flirt 0.2.1+). Map the error through capa's Result.
        let set = builder
            .build()
            .map_err(|e| Error::InvalidRuleFile(format!("flirt: build failed: {}", e)))?;
        let sig_count = set.len();
        if sig_count == 0 {
            return Err(Error::InvalidRuleFile(format!(
                "flirt: no signatures loaded from {} ({} sources attempted, {} .pat.gz skipped)",
                path.display(),
                source_count,
                gz_skipped
            )));
        }

        if gz_skipped > 0 {
            logger(&format!(
                "flirt: loaded {} signatures from {} files in {} ({} .pat.gz skipped — gunzip to enable)",
                sig_count,
                source_count,
                path.display(),
                gz_skipped
            ));
        } else {
            logger(&format!(
                "flirt: loaded {} signatures from {} files in {}",
                sig_count,
                source_count,
                path.display()
            ));
        }

        Ok(Self {
            set,
            sig_count,
            source_count,
        })
    }

    /// Number of FLIRT signatures loaded. Diagnostic / metrics use.
    pub fn signature_count(&self) -> usize {
        self.sig_count
    }

    /// Number of source files successfully parsed. Diagnostic use.
    pub fn source_file_count(&self) -> usize {
        self.source_count
    }

    /// Test the given function-leading byte slice against every loaded
    /// signature; returns the first matched public name, or `None`.
    ///
    /// "Public name" semantics: a FLIRT signature can carry multiple
    /// names tagged as `public` (the canonical function name),
    /// `local` (a name internal to the function body), or `reference`
    /// (the name of a callee used for recursive disambiguation).
    /// We surface only the `public` name — the local/reference names
    /// aren't user-meaningful and Python capa's driver makes the
    /// same choice.
    ///
    /// 0.4.x doesn't yet perform recursive reference resolution. When
    /// two signatures collide on head + CRC, the first match wins.
    /// This matches what Python capa does without `viv_utils.flirt`'s
    /// recursive resolver — i.e. it's still useful, just not maximally
    /// disambiguating. Most MSVC CRT signatures have unique enough
    /// head bytes that collisions are rare.
    ///
    /// Returns `Option<&str>` borrowed from the underlying `FlirtSet`
    /// arena — no per-call allocation. Callers that need an owned
    /// `String` can `.map(str::to_owned)` themselves.
    pub fn match_function<'a>(&'a self, function_bytes: &[u8]) -> Option<&'a str> {
        self.set.match_public_name(function_bytes)
    }

    /// Convenience: read up to `FLIRT_LOOKAHEAD_BYTES` (256) from the
    /// extractor at `function_addr` and return the matched library
    /// function name, if any. Returns `None` when the extractor can't
    /// produce bytes for the VA (truncated section, unmapped address,
    /// no backing section) — those addresses simply don't get
    /// FLIRT-marked.
    pub fn match_function_at<'a>(
        &'a self,
        function_addr: u64,
        extractor: &dyn crate::extractor::Extractor,
    ) -> Option<&'a str> {
        let bytes = extractor.function_bytes(function_addr, FLIRT_LOOKAHEAD_BYTES)?;
        if bytes.is_empty() {
            return None;
        }
        self.match_function(bytes)
    }
}

impl std::fmt::Debug for FlirtMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlirtMatcher")
            .field("signatures", &self.sig_count)
            .field("source_files", &self.source_count)
            .finish_non_exhaustive()
    }
}
