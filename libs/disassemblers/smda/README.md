# SMDA

SMDA is a minimalist recursive disassembler library that is 
optimized for accurate Control Flow Graph (CFG) recovery 
from memory dumps. It is based on Capstone and currently 
supports x86/x64 Intel machine code. As input, arbitrary 
memory dumps (ideally with known base address) can be processed. 

The output is a collection of functions, basic blocks, 
and instructions with their respective edges between blocks and 
functions (in/out). Optionally, references to the Windows API 
can be inferred by using the ApiScout method.

### Requirements
- Rust 1.50+ (edition 2018)

---
