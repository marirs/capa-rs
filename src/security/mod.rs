use crate::{
    Result,
    error::Error,
    security::{options::status::SecurityCheckStatus, parser::BinaryParser},
};
use std::path::Path;

pub(crate) mod elf;
mod macho;
pub(crate) mod options;
mod parser;
mod pe;

pub fn get_security_checks(
    path: &impl AsRef<Path>,
    options: &crate::BinarySecurityCheckOptions,
) -> Result<Vec<SecurityCheckStatus>> {
    use goblin::Object;

    let parser = BinaryParser::open(path.as_ref())?;

    let results = match parser.object() {
        Object::Elf(_elf) => {
            // "Binary file format is 'ELF'."
            elf::analyze_binary(&parser, options)
        }

        Object::PE(_pe) => {
            // "Binary file format is 'PE'."
            pe::analyze_binary(&parser, options)
        }

        Object::Mach(_mach) => {
            // 0.5.0: real Mach-O security checklist (capa-rs
            // 0.5.0 → security/macho.rs). Pre-0.5.0 returned
            // UnsupportedBinaryFormat (blocked analysis entirely);
            // a brief intermediate cut returned Ok(Vec::new())
            // (empty table, analysis ran but the security column
            // was useless). Now: PIE, DATA-EXEC-PREVENT,
            // STACK-CANARY, RESTRICT, CODE-SIGNATURE,
            // TWO-LEVEL-NAMESPACE, NO-UNDEF-SYMS,
            // HARDENED-RUNTIME (Unknown — code-sig blob parser
            // deferred), ALLOW-JIT (Unknown — entitlements PLIST
            // parser deferred). 9 entries total.
            macho::analyze_binary(&parser, options)
        }

        Object::Unknown(_magic) => Err(Error::UnknownBinaryFormat(path.as_ref().into())),

        _ => Err(Error::UnknownBinaryFormat(path.as_ref().into())),
    }?;
    let statuses = results
        .into_iter()
        .map(|r| r.get_security_check_status().unwrap())
        .collect::<Vec<_>>();

    Ok(statuses)
}
