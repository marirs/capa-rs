# capa-rs — File Capability Extractor

[![CI](https://github.com/marirs/capa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/capa.svg)](https://crates.io/crates/capa)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)

Try it online: <https://www.analyze.rs/>

`capa-rs` detects capabilities in executable files. Point it at a PE, ELF, or .NET binary and it tells you what the program can do — for example, that the file is a backdoor, installs Windows services, communicates over HTTP, or uses RC4. It also runs a binary-security checklist (ASLR, NX, stack canary, CFG, etc.).

This is a Rust port of Mandiant's [Python capa](https://github.com/mandiant/capa) without the IDA / Ghidra plugins — a pure library that emits capability reports. The bundled `capa_cli` example wraps it as a command-line tool. Rules come from the official [capa-rules](https://github.com/mandiant/capa-rules) repository.

## Quick start

```toml
[dependencies]
capa = "0.3"
```

```rust
use capa::{BinarySecurityCheckOptions, FileCapabilities};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fc = FileCapabilities::from_file(
        "Sample.exe",
        "path/to/capa-rules",
        false,                                       // high_accuracy
        false,                                       // resolve_tailcalls
        &|_status| {},                               // progress callback
        false,                                       // map_features
        Some(BinarySecurityCheckOptions::default()), // libc / sysroot / spec
    )?;

    let json = fc.serialize_file_capabilities(None)?;
    println!("{}", json);
    Ok(())
}
```

## CLI example

```text
$ capa_cli --rules-path capa-rules data/Demo64.dll
+--------------+-------------+
|      File Properties       |
+==============+=============+
| arch         | AMD64       |
+--------------+-------------+
| base_address | 0x180000000 |
+--------------+-------------+
| format       | PE          |
+--------------+-------------+
| os           | WINDOWS     |
+--------------+-------------+

+-----------------------+-------------+
|           Security Checks           |
+=======================+=============+
| ASLR                  | Supported   |
| CHECKSUM              | Fail        |
| CONTROL-FLOW-GUARD    | Unsupported |
| DATA-EXEC-PREVENT     | Pass        |
| SAFE-SEH              | Pass        |
| VERIFY-DIGITAL-CERT   | Fail        |
+-----------------------+-------------+

+---------------+------------------------+
| ATT&CK Tactic | ATT&CK Technique       |
+===============+========================+
| Execution     | Shared Modules [T1129] |
+---------------+------------------------+

+----------------------------------+-------------------------------------------------+
| Capability                       | Namespace                                       |
+----------------------------------+-------------------------------------------------+
| check for software breakpoints   | anti-analysis/anti-debugging/debugger-detection |
| contains PDB path                | executable/pe/pdb                               |
| hash data using djb2             | data-manipulation/hashing/djb2                  |
| match known PlugX module         | malware-family/plugx                            |
+----------------------------------+-------------------------------------------------+

TAGS: [B0001.025, C0030.001, C0030.006, T1129]
```

Verbose mode adds per-function feature + capability tables:

```bash
capa_cli --rules-path capa-rules --verbose data/Demo64.dll
```

## Features

The crate ships two cargo features:

- `properties` *(default)* — file metadata (architecture, base address, format, OS) on `FileCapabilities`.
- `verbose` — per-function feature / capability breakdown on `FileCapabilities`.

Build combinations:

```bash
cargo build                                # default = properties
cargo build --features verbose             # verbose only
cargo build --features verbose,properties  # both
```

## Requirements

- Rust **1.95** or newer (2024 edition).
- No C/C++ toolchain — pure Rust.

## Architecture

```
┌──────────────────────────────┐
│  FileCapabilities (capa-rs)  │  rules engine, capability matching,
│  src/lib.rs                  │  rendering, security checks
└──────────────┬───────────────┘
               │
               ├──► src/extractor/smda.rs ───► smda 0.5  (PE/ELF/MachO disassembly,
               │                                          function names, hashes)
               └──► src/extractor/dnfile.rs ──► dnfile 0.4 (.NET CLR metadata)
```

## Related crates in this ecosystem

- [`smda`](https://crates.io/crates/smda) — recursive x86/x64 disassembler (zero-copy, iced-x86 backend).
- [`dnfile`](https://crates.io/crates/dnfile) — .NET CLR metadata parser (zero-copy).

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
