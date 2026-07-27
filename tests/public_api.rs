//! #22: public API surface — downstream must be able to *name* the
//! types that appear in public fields, and the documented options must
//! be reachable. Most assertions here only need to type-check: pre-#22
//! these types were unreachable because their modules are private.

use capa::{BinarySecurityCheckOptions, LibCSpec};
use std::str::FromStr;

#[test]
fn exported_field_types_are_nameable() {
    // Pre-#22 none of these paths resolved from outside the crate.
    let _f: Option<capa::FileFormat> = None;
    let _o: Option<capa::Os> = None;
    let _a: Option<capa::FileArchitecture> = None;
    let _s: Option<capa::SecurityCheckStatus> = None;
}

#[test]
fn function_capabilities_getters_exist() {
    // Fields stay private; getters are the read API (verbose feature).
    let _: fn(&capa::FunctionCapabilities) -> usize = capa::FunctionCapabilities::address;
    let _: fn(&capa::FunctionCapabilities) -> usize = capa::FunctionCapabilities::features;
    let _: fn(&capa::FunctionCapabilities) -> &[String] = capa::FunctionCapabilities::capabilities;
}

#[test]
fn no_libc_option_is_reachable() {
    // Pre-#22 `no_libc` was pub(crate) and `new()` hard-coded false.
    let _opts = BinarySecurityCheckOptions::default().no_libc(true);
}

#[test]
fn libc_spec_from_str_is_strict() {
    assert!(matches!(
        LibCSpec::from_str("4.1.0"),
        Ok(LibCSpec::LSB4dot1)
    ));
    assert!(matches!(LibCSpec::from_str("5.0.0"), Ok(LibCSpec::LSB5)));
    // Unknown versions error (pre-#22 they silently became LSB5).
    assert!(LibCSpec::from_str("4.0.1").is_err());
    assert!(LibCSpec::from_str("").is_err());
    // The lenient From<String> stays for compatibility.
    assert!(matches!(
        LibCSpec::from("4.0.1".to_string()),
        LibCSpec::LSB5
    ));
}

#[test]
fn from_file_accepts_path_like_arguments() {
    // Only checks the signature: &str, String, &Path and PathBuf must
    // all compile (pre-#22 only AsRef<str> was accepted). The calls
    // fail at runtime for a missing rules dir — that's fine, we never
    // execute them.
    let _ = |p: &std::path::Path| {
        capa::FileCapabilities::analyze()
            .rules("definitely-missing-rules-dir")
            .from_file(p)
    };
}
