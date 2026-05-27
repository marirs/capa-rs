//! FLIRT library-function recognition (0.4.3).
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

use fast_flirt::{FlirtSet, FlirtSetBuilder};
use std::path::Path;

use crate::{Error, Result};

/// Number of leading bytes to feed the matcher per function. Matches
/// Python capa's lookahead. The FLIRT head pattern is typically 32
/// bytes, and the optional tail extends further; 256 covers every
/// signature in the Mandiant FLARE corpus with margin.
const FLIRT_LOOKAHEAD_BYTES: u32 = 256;

/// FLIRT signature matcher loaded from a directory of `.sig` / `.pat`
/// files. Construction is one-time at builder configuration; matching
/// is per-function during analysis. Cheap to share across rayon
/// worker threads — `FlirtSet` is `Send + Sync`.
pub struct FlirtMatcher {
    set: FlirtSet,
    sig_count: usize,
    source_count: usize,
}

impl FlirtMatcher {
    /// Load all `.sig` and `.pat` files from a directory tree
    /// (recursive). Files that fail to parse are reported through
    /// `logger` and skipped — they don't abort the build, matching
    /// Python capa's best-effort behaviour.
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

        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let parsed_ok = if name.ends_with(".sig") {
                // Binary FLIRT signature file (the format `sigmake`
                // produces and IDA consumes natively).
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
            } else if name.ends_with(".pat.gz") {
                // 0.4.3 limitation: gzipped pat files not yet
                // unpacked. The Mandiant FLARE corpus is `.sig` so
                // this only affects community sources like FLIRTDB.
                logger(&format!(
                    "flirt: .pat.gz not yet supported, skipping {}",
                    name
                ));
                false
            } else if name.ends_with(".pat") {
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

        let set = builder.build();
        let sig_count = set.len();
        if sig_count == 0 {
            return Err(Error::InvalidRuleFile(format!(
                "flirt: no signatures loaded from {} ({} sources attempted)",
                path.display(),
                source_count
            )));
        }

        logger(&format!(
            "flirt: loaded {} signatures from {} files in {}",
            sig_count,
            source_count,
            path.display()
        ));

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
    /// 0.4.3 doesn't yet perform recursive reference resolution. When
    /// two signatures collide on head + CRC, the first match wins.
    /// This matches what Python capa does without `viv_utils.flirt`'s
    /// recursive resolver — i.e. it's still useful, just not maximally
    /// disambiguating. Most MSVC CRT signatures have unique enough
    /// head bytes that collisions are rare.
    pub fn match_function(&self, function_bytes: &[u8]) -> Option<String> {
        // fast-flirt's `match_public_name` does exactly the
        // "first matching signature, public name only" walk we
        // want — including the trie-narrowed candidate filter and
        // ControlFlow short-circuit. One call instead of an
        // explicit loop.
        self.set
            .match_public_name(function_bytes)
            .map(|s| s.to_string())
    }

    /// Convenience: read up to `FLIRT_LOOKAHEAD_BYTES` (256) from the
    /// extractor at `function_addr` and return the matched library
    /// function name, if any. Returns `None` when the byte read fails
    /// (truncated section, unmapped VA) — those addresses simply
    /// don't get FLIRT-marked.
    pub fn match_function_at(
        &self,
        function_addr: u64,
        extractor: &crate::extractor::smda::Extractor<'_>,
    ) -> Option<String> {
        let bytes = extractor
            .report()
            .binary_info
            .bytes_at_best_effort(function_addr, FLIRT_LOOKAHEAD_BYTES)
            .ok()?;
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
