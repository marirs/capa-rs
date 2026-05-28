// 0.3.21: same clippy allowlist rationale as the library crate — see the
// comment at the top of `src/lib.rs`. Examples are compiled as a separate
// crate so the lib-level `#![allow]` doesn't reach them automatically.
#![allow(clippy::collapsible_if, clippy::collapsible_match)]

use std::fs;
use std::time::Instant;

use clap::Parser;
use prettytable::{Attr, Cell, Row, Table, color, format::Alignment};
use serde_json::{Map, Value, to_value};

use capa::{BinarySecurityCheckOptions, FileCapabilities};

#[derive(Parser)]
#[clap(
    author,
    version,
    about,
    long_about = "Find Capabilities of a given file!"
)]
struct CliOpts {
    /// File to analyse
    #[clap(value_name = "FILE")]
    name: String,
    /// Path to CAPA Rules
    #[clap(short = 'r', long, value_name = "CAPA_RULES")]
    rules_path: String,
    /// verbose output
    #[clap(short = 'v', long, default_value = "false")]
    verbose: bool,
    /// file path to save the result in json format
    #[clap(short = 'o', long, value_name = "JSON_PATH")]
    output: Option<String>,
    /// map_features
    #[clap(
        short = 'm',
        long,
        value_name = "MAP_FEATURES",
        default_value = "false"
    )]
    map_features: bool,
    /// filter map_features
    #[clap(short = 'f', long, value_name = "FILTER_MAP_FEATURES")]
    filter_map_features: Option<String>,

    /// Path of the C runtime library file.
    #[clap(long, value_name = "LIBC")]
    libc: Option<String>,

    /// Path of the system root for finding the corresponding C runtime library.
    #[clap(long, value_name = "SYSROOT")]
    sysroot: Option<String>,

    /// Use an internal list of checked functions as specified by a specification. Provide the version of the specification. eg 3.2.0
    #[clap(long, value_name = "LIBC_SPEC")]
    libc_spec: Option<String>,

    /// 0.4.3: directory of FLIRT signature files (.sig / .pat).
    /// When present, capa-rs identifies statically-linked library
    /// functions and excludes their capability hits from the
    /// report. The capa-rs repo ships a `flirt-sigs/` directory
    /// with the Mandiant FLARE corpus + Maktm's FLIRTDB
    /// (~195 .sig files, ~70 MB). GitHub releases also ship a
    /// `flirt-sigs-vX.Y.Z.tar.gz` artifact alongside the CLI
    /// binaries.
    #[clap(long, value_name = "SIGNATURES_DIR")]
    signatures: Option<String>,
}

fn main() {
    let cli = CliOpts::parse();
    let filename = cli.name;
    let rules_path = cli.rules_path;
    let verbose = cli.verbose;
    let map_features = cli.map_features;
    let json_path = cli.output;
    let libc = cli.libc.map(|s| s.into());
    let sysroot = cli.sysroot.map(|s| s.into());
    let libc_spec = cli.libc_spec.map(|s| s.into());
    let security_check_opts = BinarySecurityCheckOptions::new(libc, sysroot, libc_spec);

    let start = Instant::now();
    // 0.4.0: chained AnalyzeBuilder replaces the 0.3.x positional
    // `FileCapabilities::from_file(...)`. Same arguments, just
    // self-documenting at call sites — and no more counting bool
    // positions.
    //
    // 0.4.3: optional `.signatures()` for FLIRT library-function
    // recognition. Always available — engine is in the lib by
    // default; absence of a path = no FLIRT, same as pre-0.4.3.
    let builder = FileCapabilities::analyze()
        .rules(rules_path)
        .high_accuracy(true)
        .resolve_tailcalls(true)
        .features_dump(map_features)
        .security_checks(security_check_opts);
    let builder = match cli.signatures {
        Some(path) => builder.signatures(path),
        None => builder,
    };
    match builder.from_file(filename) {
        Err(e) => println!("{:?}", e),
        Ok(mut s) => {
            match to_value(&s) {
                Err(e) => println!("serde_json_error: {}", e),
                Ok(data) => {
                    let data = data.as_object().unwrap();
                    let features = data.get("features");

                    // print the file basic properties
                    if let Some(props) = data.get("properties") {
                        let tbl = get_properties(props, features);
                        tbl.printstd();
                    }
                    println!();

                    // print the Security Checks
                    if let Some(security_checks) = data.get("security_checks") {
                        let tbl = get_security_checks(security_checks);
                        tbl.printstd();
                    }
                    println!();

                    // print the Mitre ATT&CK information
                    if let Some(attacks) = data.get("attacks") {
                        let attacks = attacks.as_object().unwrap();
                        if !attacks.is_empty() {
                            let tbl = get_mitre(attacks);
                            tbl.printstd();
                        }
                    }
                    println!();

                    // print the Malware Behaviour Catalog
                    if let Some(mbc) = data.get("mbc") {
                        let mbc = mbc.as_object().unwrap();
                        if !mbc.is_empty() {
                            let tbl = get_mbc(mbc);
                            tbl.printstd();
                        }
                    }
                    println!();

                    // print the Capability/Namespace
                    if let Some(namespace) = data.get("capability_namespaces") {
                        let namespace = namespace.as_object().unwrap();
                        if !namespace.is_empty() {
                            let tbl = get_namespace(namespace);
                            tbl.printstd();
                        }
                    }
                    println!();

                    // print the Function/feature/capabilities
                    if verbose {
                        if let Some(extra) = data.get("functions_capabilities") {
                            let extra = extra.as_object().unwrap();
                            if !extra.is_empty() {
                                let tbl = get_verbose_info(extra);
                                tbl.printstd();
                            }
                        }
                    }
                    println!();

                    // 0.5.0 (D3): print scope-keyed feature dump summary
                    // when `-m` is set. The full per-feature breakdown
                    // is in the JSON output (`-o`); this stdout view
                    // gives a quick "how many of each feature type per
                    // scope" sanity check.
                    if map_features {
                        if let Some(by_scope) = data.get("map_features_by_scope") {
                            if let Some(obj) = by_scope.as_object() {
                                if !obj.is_empty() {
                                    let tbl = get_features_by_scope_summary(obj);
                                    tbl.printstd();
                                    println!();
                                }
                            }
                        }
                    }

                    //print tags

                    if let Some(tags) = data.get("tags") {
                        let tt = tags.as_array().unwrap();
                        if !tt.is_empty() {
                            println!(
                                "TAGS: [{}]",
                                tt.iter()
                                    .map(|s| s.as_str().unwrap().to_string())
                                    .collect::<Vec<String>>()
                                    .join(", ")
                            );
                        }
                    }
                    println!();
                }
            }
            if let Some(json_path) = json_path {
                let json = s
                    .serialize_file_capabilities(cli.filter_map_features)
                    .unwrap();
                fs::write(json_path.clone(), json).expect("Unable to write file");
                println!("Analysis result saved in JSON format at: {}", json_path);
            }
        }
    }
    println!("Time taken (seconds): {:?}", start.elapsed());
    println!();
}

/// Gets the Meta information and returns as a TABLE for stdout
fn get_properties(props: &Value, features: Option<&Value>) -> Table {
    let meta = props.as_object().unwrap();
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("File Properties", Alignment::CENTER).with_hspan(2),
    ]));
    for (k, v) in meta {
        // 0.4.0: Properties now contains numeric `pdb_age` alongside
        // string fields — `v.as_str().unwrap()` would panic on it.
        // Fall back to JSON serialization for non-string scalars so
        // the table renders for any future Properties addition.
        let rendered = match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        tbl.add_row(Row::new(vec![
            Cell::new(k)
                .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))
                .with_style(Attr::Bold),
            Cell::new(&rendered),
        ]));
    }
    if let Some(f) = features {
        tbl.add_row(Row::new(vec![
            Cell::new("features")
                .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))
                .with_style(Attr::Bold),
            Cell::new(&f.as_u64().unwrap().to_string()),
        ]));
    }

    tbl
}

/// Gets the MITRE ATT&CK information and returns as a TABLE for stdout
fn get_mitre(attacks: &Map<String, Value>) -> Table {
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("MITRE ATT&CK", Alignment::CENTER).with_hspan(2),
    ]));
    tbl.set_titles(Row::new(vec![
        Cell::new_align("ATT&CK Tactic", Alignment::LEFT),
        Cell::new_align("ATT&CK Technique", Alignment::LEFT),
    ]));

    for (tatic, v) in attacks {
        let techniques = v.as_array().unwrap();
        let techniques = techniques
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        tbl.add_row(Row::new(vec![
            Cell::new(tatic)
                .with_style(Attr::ForegroundColor(color::MAGENTA))
                .with_style(Attr::Bold),
            Cell::new(&techniques.join("\n")),
        ]));
    }

    tbl
}

/// Gets the Malware Behavior Catalog information and returns as a TABLE for stdout
fn get_mbc(mbc: &Map<String, Value>) -> Table {
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("Malware Behavior Catalog", Alignment::CENTER).with_hspan(2),
    ]));
    tbl.set_titles(Row::new(vec![
        Cell::new_align("MBC Objective", Alignment::LEFT),
        Cell::new_align("MBC Behavior", Alignment::LEFT),
    ]));
    for (objective, v) in mbc {
        let behaviors = v.as_array().unwrap();
        let behaviours = behaviors
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        tbl.add_row(Row::new(vec![
            Cell::new(objective)
                .with_style(Attr::ForegroundColor(color::RED))
                .with_style(Attr::Bold),
            Cell::new(&behaviours.join("\n")),
        ]));
    }

    tbl
}

fn get_security_checks(security_checks: &Value) -> Table {
    let security_checks = security_checks.as_array().unwrap();
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("Security Checks", Alignment::CENTER).with_hspan(2),
    ]));
    for check in security_checks {
        let check = check.as_object().unwrap();
        let check_name = check.get("name").unwrap().as_str().unwrap();
        let v = check.get("status").unwrap();
        let status = v.as_str().unwrap().to_string();

        tbl.add_row(Row::new(vec![
            Cell::new(check_name)
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
            if status.eq_ignore_ascii_case("fail") || status.eq_ignore_ascii_case("unsupported") {
                Cell::new(&status).with_style(Attr::ForegroundColor(color::RED))
            } else if status.eq_ignore_ascii_case("Pass")
                || status.eq_ignore_ascii_case("Supported")
            {
                Cell::new(&status).with_style(Attr::ForegroundColor(color::GREEN))
            } else {
                Cell::new(&status)
            },
        ]));
    }

    tbl
}

/// Gets the Capability & Namespace information and returns as a TABLE for stdout
fn get_namespace(namespace: &Map<String, Value>) -> Table {
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("File Capability/Namespace", Alignment::CENTER).with_hspan(2),
    ]));
    tbl.set_titles(Row::new(vec![
        Cell::new_align("Capability", Alignment::LEFT),
        Cell::new_align("Namespace", Alignment::LEFT),
    ]));
    for (capability, v) in namespace {
        let ns = v.as_str().unwrap().to_string();

        tbl.add_row(Row::new(vec![
            Cell::new(capability)
                .with_style(Attr::ForegroundColor(color::CYAN))
                .with_style(Attr::Bold),
            Cell::new(&ns),
        ]));
    }

    tbl
}

/// 0.5.0 (D3): summarises the scope-keyed feature dump as
/// `scope → feature_type → count` so users running with `-m` get a
/// quick visual signal that scope info is being tracked. The full
/// per-value breakdown is in the JSON output (`-o`).
fn get_features_by_scope_summary(by_scope: &Map<String, Value>) -> Table {
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("Features by Scope (D3 dump)", Alignment::CENTER).with_hspan(3),
    ]));
    tbl.set_titles(Row::new(vec![
        Cell::new_align("Scope", Alignment::LEFT),
        Cell::new_align("Feature Type", Alignment::LEFT),
        Cell::new_align("Distinct Values", Alignment::RIGHT),
    ]));

    // Sort scopes for stable output (file → function → basic_block → instruction is roughly outer-to-inner).
    let mut scopes: Vec<&String> = by_scope.keys().collect();
    scopes.sort_by_key(|s| match s.as_str() {
        "file" => 0,
        "function" => 1,
        "basic_block" => 2,
        "instruction" => 3,
        _ => 99,
    });
    for scope in scopes {
        let scope_obj = by_scope.get(scope).and_then(|v| v.as_object());
        let Some(scope_obj) = scope_obj else { continue };
        let mut ftypes: Vec<&String> = scope_obj.keys().collect();
        ftypes.sort();
        for ftype in ftypes {
            let count = scope_obj
                .get(ftype)
                .and_then(|v| v.as_object())
                .map(|m| m.len())
                .unwrap_or(0);
            tbl.add_row(Row::new(vec![
                Cell::new(scope).with_style(Attr::ForegroundColor(color::CYAN)),
                Cell::new(ftype),
                Cell::new(&count.to_string()),
            ]));
        }
    }

    tbl
}

/// Gets Verbose information and returns as a TABLE for stdout
fn get_verbose_info(extra: &Map<String, Value>) -> Table {
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![
        Cell::new_align("Function", Alignment::LEFT),
        Cell::new_align("Address", Alignment::LEFT),
        Cell::new_align("Features", Alignment::LEFT),
        Cell::new_align("Capabilities", Alignment::LEFT),
    ]));
    for (function, v) in extra {
        let caps = v.as_object().unwrap();
        let address = caps.get("address").unwrap().as_str().unwrap();
        let features = caps.get("features").unwrap().as_u64().unwrap().to_string();
        let capabilities = caps.get("capabilities").unwrap().as_array().unwrap();
        let capabilities = capabilities
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        tbl.add_row(Row::new(vec![
            Cell::new(&("@".to_string() + function))
                .with_style(Attr::ForegroundColor(color::GREEN))
                .with_style(Attr::Bold),
            Cell::new(address),
            Cell::new(&features),
            Cell::new(&capabilities.join("\n")),
        ]));
    }

    tbl
}
