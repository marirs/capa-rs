# File Capability Extractor

capa detects capabilities in executable files. You run it against a PE, ELF, or shellcode file and it tells you what it thinks the program can do. 
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

### Requirements
- Rust 1.50+ (edition 2018)

