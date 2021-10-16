# File Capability Extractor

capa detects capabilities in executable files. You run it against a PE, ELF, or shellcode file and it tells you what it thinks the program can do. 
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

### Requirements
- Rust 1.50+ (edition 2018)

### Features
- meta (gets the meta information of the file)
- verbose (gets the verbose information such as: function, address, features, etc...)

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

---
