# File Capability Extractor

[![x86_64](https://github.com/marirs/capa-rs/actions/workflows/linux_arm7.yml/badge.svg?branch=master)](https://github.com/marirs/capa-rs/actions/workflows/linux_arm7.yml)

capa detects capabilities in executable files. You run it against a PE, ELF, or shellcode file and it tells you what it thinks the program can do. 
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

It is a port from https://github.com/mandiant/capa without IDA plugins, etc. Its just a capa library that gives out capability information. 
The Library itself can be used in other applications. 

The example contains a `CLI` to output the extracted capabilities to `stdout`.

### Requirements
- Rust 1.50+ (edition 2018)

### Running the example cli
```bash
./capa_cli Demo64.dll
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

### Features
- meta (gets the meta information of the file)
- verbose (gets the verbose information such as: function, address, features, etc...)

### Compiling with or without features

- with Meta
```bash
cargo b --features=meta
```

- verbose mode
```bash
carbo b --features=verbose
```

- verbose & meta
```bash
cargo b --features=verbose,meta
```

- without any features (default)
```bash
cargo b
```

without the features flag, it will be compiled ot only show the ATT&CK, MBC & Capability/Namespace details only.

---
