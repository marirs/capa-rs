use capa::FileCapabilities;
use clap::Parser;
use prettytable::{color, format::Alignment, Attr, Cell, Row, Table};
use serde_json::{to_value, Map, Value};
use std::time::Instant;

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
    #[clap(long)]
    verbose: bool,
}

fn main() {
    let cli = CliOpts::parse();
    let filename = cli.name;
    let rules_path = cli.rules_path;
    let verbose = cli.verbose;

    let start = Instant::now();
    match FileCapabilities::from_file(&filename, &rules_path, true, true, &|_s| {}) {
        Err(e) => println!("{:?}", e),
        Ok(s) => {
            match to_value(s) {
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
        }
    }
    println!("Time taken (seconds): {:?}", start.elapsed());
    println!();
}

/// Gets the Meta information and returns as a TABLE for stdout
fn get_properties(props: &Value, features: Option<&Value>) -> Table {
    let meta = props.as_object().unwrap();
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "File Properties",
        Alignment::CENTER,
    )
    .with_hspan(2)]));
    for (k, v) in meta {
        tbl.add_row(Row::new(vec![
            Cell::new(k)
                .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE))
                .with_style(Attr::Bold),
            Cell::new(v.as_str().unwrap()),
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
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "MITRE ATT&CK",
        Alignment::CENTER,
    )
    .with_hspan(2)]));
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
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "Malware Behavior Catalog",
        Alignment::CENTER,
    )
    .with_hspan(2)]));
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

/// Gets the Capability & Namespace information and returns as a TABLE for stdout
fn get_namespace(namespace: &Map<String, Value>) -> Table {
    let mut tbl = Table::new();
    tbl.set_titles(Row::new(vec![Cell::new_align(
        "File Capability/Namespace",
        Alignment::CENTER,
    )
    .with_hspan(2)]));
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
