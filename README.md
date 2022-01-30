# File Capability Extractor

[![Linux Arm7](https://github.com/marirs/capa-rs/actions/workflows/linux_arm7.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/linux_arm7.yml)
[![Linux x86_64](https://github.com/marirs/capa-rs/actions/workflows/linux_x86-64.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/linux_x86-64.yml)
[![macOS](https://github.com/marirs/capa-rs/actions/workflows/macos.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/macos.yml)
[![Windows](https://github.com/marirs/capa-rs/actions/workflows/windows.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/windows.yml)

capa detects capabilities in executable files. You run it against a PE, ELF, or shellcode file and it tells you what it thinks the program can do. 
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

It is a port from https://github.com/mandiant/capa without IDA plugins, etc. Its just a capa library that gives out capability information. 
The Library itself can be used in other applications. The rules are available here: `https://github.com/mandiant/capa-rules`

The example contains a `CLI` to output the extracted capabilities to `stdout`.

### Requirements
- Rust 1.56+ (edition 2021)

### Running the example cli
```bash
./capa_cli --rules-path capa-rules data/Demo64.dll
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

+---------------+------------------------+
| ATT&CK Tactic | ATT&CK Technique       |
+===============+========================+
| Execution     | Shared Modules [T1129] |
+---------------+------------------------+

+---------------+---------------------------+
| MBC Objective | MBC Behavior              |
+===============+===========================+
| Process       | Terminate Process [C0018] |
+---------------+---------------------------+

+-----------------------------------------------+------------------------------------+
| Capability                                    | Namespace                          |
+===============================================+====================================+
| contain a resource (.rsrc) section            | executable/pe/section/rsrc         |
+-----------------------------------------------+------------------------------------+
| contain a thread local storage (.tls) section | executable/pe/section/tls          |
+-----------------------------------------------+------------------------------------+
| parse PE header                               | load-code/pe                       |
+-----------------------------------------------+------------------------------------+
| terminate process via fastfail                | host-interaction/process/terminate |
+-----------------------------------------------+------------------------------------+
```

- With verbose output use
```bash
./capa_cli --rules-path capa-rules --verbose data/Demo64.dll
```

### Features
- properties (gets the meta information/properties of the file)
- verbose (gets the verbose information such as: function, address, features, etc...)

### Compiling with or without features

- with properties
```bash
cargo b --features=properties
```

- verbose mode
```bash
carbo b --features=verbose
```

- verbose & properties
```bash
cargo b --features=verbose,properties
```

- with default features (default - includes the properties feature)
```bash
cargo b
```
---
LICENSE: Apache