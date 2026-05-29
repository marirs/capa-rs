# capa-rs — File Capability Extractor

[![CI](https://github.com/marirs/capa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/capa.svg)](https://crates.io/crates/capa)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)

Try it online: <https://www.analyze.rs/>

`capa-rs` detects capabilities in executable files. Point it at a PE, ELF, Mach-O, .NET binary, or raw shellcode and it tells you what the program can do — for example, that the file is a backdoor, installs Windows services, communicates over HTTP, or uses RC4. It also runs a binary-security checklist (PE: ASLR, NX, stack canary, CFG, SafeSEH, App-Container, …; ELF: ASLR, immediate-bind, RELRO, stack-prot; Mach-O: PIE, NX, stack-canary, restrict, code-signature, hardened-runtime, allow-JIT, two-level-namespace, no-undef-syms).

Supported inputs: **PE / .NET / ELF / Mach-O** (thin and fat / universal) across **x86, x86_64, AArch64** — on Windows / Linux / macOS / iOS targets.

This is a Rust port of Mandiant's [Python capa](https://github.com/mandiant/capa) without the IDA / Ghidra plugins — a pure library that emits capability reports. The bundled `capa_cli` example wraps it as a command-line tool. Rules come from the official [capa-rules](https://github.com/mandiant/capa-rules) repository.

## Quick start

```toml
[dependencies]
capa = "0.5"
```

```rust
use capa::{BinarySecurityCheckOptions, FileCapabilities};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fc = FileCapabilities::analyze()
        .rules("path/to/capa-rules")
        .high_accuracy(true)
        .resolve_tailcalls(true)
        .security_checks(BinarySecurityCheckOptions::default())
        .from_file("Sample.exe")?;

    let json = fc.serialize_file_capabilities(None)?;
    println!("{}", json);
    Ok(())
}
```

`.rules(...)` is the only required setter. All other builder methods default to off / no-op — most callers only need a couple of them.

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

## Shellcode / raw-buffer analysis

For payloads with no PE/ELF/Mach-O header — shellcode, unpacked modules, memory dumps — use the builder's `.from_buffer(...)` terminal instead of `.from_file(...)`:

```rust
use capa::FileCapabilities;

let shellcode = std::fs::read("payload.bin")?;
let fc = FileCapabilities::analyze()
    .rules("path/to/capa-rules")
    .high_accuracy(true)
    .resolve_tailcalls(true)
    .from_buffer(&shellcode, 0x1000, 64)?;  // base_addr, bitness
```

The shellcode is treated as a single section mapped at `base_addr`. dnfile and the security-checks pipeline are skipped (no PE/ELF header to inspect).

## PDB metadata (symbol-server lookup)

For PE inputs with a CodeView debug record, `FileCapabilities.properties` exposes `pdb_guid`, `pdb_age`, and `pdb_filename` — the keys Microsoft SymSrv / Mozilla / Chromium symbol stores look up. Fields are omitted from the JSON output when the input has no debug directory or isn't a PE.

## FLIRT library-function recognition

Point `.signatures(path)` at a directory of `.sig` / `.pat` files and matched library functions (MSVC CRT, ATL/MFC, OpenSSL, zlib, boost, libcurl, lua, protobuf, DirectX, Intel libs, etc.) are excluded from the capability output.

```rust
let fc = FileCapabilities::analyze()
    .rules("path/to/capa-rules")
    .signatures("path/to/flirt-sigs")
    .from_file("Sample.exe")?;
```

```bash
capa_cli --rules-path capa-rules --signatures flirt-sigs Sample.exe
```

The repo ships a `flirt-sigs/` directory with 195 signatures sourced from [Mandiant FLARE](https://github.com/mandiant/capa/tree/master/sigs) and [Maktm's FLIRTDB](https://github.com/Maktm/FLIRTDB). GitHub releases include the same content as a `flirt-sigs-vX.Y.Z.tar.gz` artifact.

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

## Related crates in this ecosystem

- [`smda`](https://crates.io/crates/smda) — recursive **x86 / x86_64 / AArch64** disassembler (zero-copy, iced-x86 + disarm64 backends). PE / ELF / Mach-O loader, full Mach-O API resolution via bind-opcode stream + `LC_DYSYMTAB` stub walker.
- [`dnfile`](https://crates.io/crates/dnfile) — .NET CLR metadata parser (zero-copy).
- [`fast-flirt`](https://crates.io/crates/fast-flirt) — pure-Rust FLIRT (`.sig` / `.pat`) signature matcher. Always linked into capa-rs; only does work when you pass `--signatures`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
