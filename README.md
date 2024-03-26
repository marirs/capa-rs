# File Capability Extractor

[![Linux Arm7](https://github.com/marirs/capa-rs/actions/workflows/linux_arm7.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/linux_arm7.yml)
[![Linux x86_64](https://github.com/marirs/capa-rs/actions/workflows/linux_x86-64.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/linux_x86-64.yml)
[![macOS](https://github.com/marirs/capa-rs/actions/workflows/macos.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/macos.yml)
[![Windows](https://github.com/marirs/capa-rs/actions/workflows/windows.yml/badge.svg)](https://github.com/marirs/capa-rs/actions/workflows/windows.yml)

Test it online: https://www.analyze.rs/

capa detects capabilities in executable files. You run it against a PE, ELF, or shellcode file and it tells you what it thinks the program can do. 
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate. It also performs a binary security check to see if the binary is compiled with security features enabled.

It is a port from https://github.com/mandiant/capa without IDA plugins, etc. Its just a capa library that gives out capability information. 
The Library itself can be used in other applications. The rules are available here: `https://github.com/mandiant/capa-rules`

The example contains a `CLI` to output the extracted capabilities to `stdout`.

### Requirements
- Rust 1.56+ (edition 2021)

### Running the example cli
```
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

+-----------------------+-------------+
|           Security Checks           |
+=======================+=============+
| ASLR                  | Supported   |
+-----------------------+-------------+
| CHECKSUM              | Fail        |
+-----------------------+-------------+
| CONSIDER-MANIFEST     | Pass        |
+-----------------------+-------------+
| CONTROL-FLOW-GUARD    | Unsupported |
+-----------------------+-------------+
| DATA-EXEC-PREVENT     | Pass        |
+-----------------------+-------------+
| HANDLES-ADDR-GT-2GB   | Pass        |
+-----------------------+-------------+
| RUNS-IN-APP-CONTAINER | Fail        |
+-----------------------+-------------+
| SAFE-SEH              | Pass        |
+-----------------------+-------------+
| VERIFY-DIGITAL-CERT   | Fail        |
+-----------------------+-------------+

+---------------+------------------------+
| ATT&CK Tactic | ATT&CK Technique       |
+===============+========================+
| Execution     | Shared Modules [T1129] |
+---------------+------------------------+

+--------------------------+------------------------------------------------------+
| MBC Objective            | MBC Behavior                                         |
+==========================+======================================================+
| Anti-Behavioral Analysis | Debugger Detection::Software Breakpoints [B0001.025] |
+--------------------------+------------------------------------------------------+
| Data                     | Non-Cryptographic Hash::MurmurHash [C0030.001]       |
|                          | Non-Cryptographic Hash::djb2 [C0030.006]             |
+--------------------------+------------------------------------------------------+

+-----------------------------------------------+-------------------------------------------------+
| Capability                                    | Namespace                                       |
+===============================================+=================================================+
| check for software breakpoints                | anti-analysis/anti-debugging/debugger-detection |
+-----------------------------------------------+-------------------------------------------------+
| contain a thread local storage (.tls) section | executable/pe/section/tls                       |
+-----------------------------------------------+-------------------------------------------------+
| contains PDB path                             | executable/pe/pdb                               |
+-----------------------------------------------+-------------------------------------------------+
| hash data using djb2                          | data-manipulation/hashing/djb2                  |
+-----------------------------------------------+-------------------------------------------------+
| hash data using murmur3                       | data-manipulation/hashing/murmur                |
+-----------------------------------------------+-------------------------------------------------+
| match known PlugX module                      | malware-family/plugx                            |
+-----------------------------------------------+-------------------------------------------------+
| parse PE header                               | load-code/pe                                    |
+-----------------------------------------------+-------------------------------------------------+
| reference Cloudflare DNS server               | communication/dns                               |
+-----------------------------------------------+-------------------------------------------------+


TAGS: [B0001.025, C0030.001, C0030.006, T1129]

Time taken (seconds): 1.227743833s
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
