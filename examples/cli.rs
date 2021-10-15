use prettytable::{color, format::Alignment, Attr, Cell, Row, Table};
use serde_json::to_value;

fn main() {
    for (i, arg) in std::env::args().enumerate() {
        if i == 1 {
            match capa::proceed_file(
                arg.as_str(),
                "rules",
                &|_s| {
                    //                                           println!("{}", s);
                },
                true,
            ) {
                Err(e) => println!("{:?}", e),
                Ok(s) => {
                    match to_value(&s) {
                        Err(e) => println!("serde_json_error: {}", e),
                        Ok(data) => {
                            let data = data.as_object().unwrap();
                            // print the file basic properties
                            if let Some(meta) = data.get("meta") {
                                let meta = meta.as_object().unwrap();
                                let mut tbl = Table::new();
                                tbl.set_titles(Row::new(vec![Cell::new_align(
                                    "File Properties",
                                    Alignment::CENTER,
                                )
                                .with_hspan(2)]));
                                for (k, v) in &*meta {
                                    tbl.add_row(Row::new(vec![
                                        Cell::new(k)
                                            .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE)),
                                        Cell::new(v.as_str().unwrap()),
                                    ]));
                                }
                                tbl.printstd();
                            }
                            println!();

                            // print the Mitre ATT&CK information
                            if let Some(attacks) = data.get("attacks") {
                                let attacks = attacks.as_object().unwrap();
                                if !attacks.is_empty() {
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
                                    for (tatic, v) in &*attacks {
                                        let techniques = v.as_array().unwrap();
                                        let techniques = techniques
                                            .iter()
                                            .map(|x| x.as_str().unwrap().to_string())
                                            .collect::<Vec<_>>();

                                        tbl.add_row(Row::new(vec![
                                            Cell::new(tatic).with_style(Attr::ForegroundColor(
                                                color::BRIGHT_CYAN,
                                            )),
                                            Cell::new(&techniques.join("\n")),
                                        ]));
                                    }
                                    tbl.printstd();
                                }
                            }
                            println!();

                            // print the Malware Behaviour Catalog
                            if let Some(mbc) = data.get("mbc") {
                                let mbc = mbc.as_object().unwrap();
                                if !mbc.is_empty() {
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
                                    for (objective, v) in &*mbc {
                                        let behaviors = v.as_array().unwrap();
                                        let behaviours = behaviors
                                            .iter()
                                            .map(|x| x.as_str().unwrap().to_string())
                                            .collect::<Vec<_>>();

                                        tbl.add_row(Row::new(vec![
                                            Cell::new(objective).with_style(Attr::ForegroundColor(
                                                color::BRIGHT_CYAN,
                                            )),
                                            Cell::new(&behaviours.join("\n")),
                                        ]));
                                    }
                                    tbl.printstd();
                                }
                            }
                            println!();

                            // print the Capability/Namespace
                            if let Some(namespace) = data.get("capability_namespaces") {
                                let namespace = namespace.as_object().unwrap();
                                if !namespace.is_empty() {
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
                                    for (capability, v) in &*namespace {
                                        let ns = v.as_str().unwrap().to_string();

                                        tbl.add_row(Row::new(vec![
                                            Cell::new(capability).with_style(
                                                Attr::ForegroundColor(color::BRIGHT_CYAN),
                                            ),
                                            Cell::new(&ns),
                                        ]));
                                    }
                                    tbl.printstd();
                                }
                            }
                            println!();
                        }
                    }
                }
            }
        }
    }
}
