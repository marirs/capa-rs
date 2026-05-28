#!/usr/bin/env python3
"""
Generate src/rules/features/com_db.rs from Python capa's COM tables.

Reads:
  ../capa/capa/features/com/classes.py
  ../capa/capa/features/com/interfaces.py
Writes:
  src/rules/features/com_db.rs

The Python files define COM_CLASSES / COM_INTERFACES as dict[str, list[str]]
where each value is a list of canonical GUID strings
("4590F811-1D3A-11D0-891F-00AA004B2E24"). Each GUID is stored in memory as
16 bytes with the first three groups byte-reversed (Microsoft mixed-endian
GUID layout per RPC).

We emit two sorted `&[(&str, &[[u8; 16]])]` slices so the runtime can
`binary_search_by` on the name.
"""
import ast
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent.resolve()
CAPA_RS = HERE.parent

# Search standard layouts: PYTHON_CAPA env override, then sibling
# directories. Dev-mode is typically Dev/capa with capa-rs under
# Dev/Projects/malware-analysis/ — two levels up.
_candidates = []
if env := os.environ.get("PYTHON_CAPA"):
    _candidates.append(Path(env))
_candidates += [
    CAPA_RS.parent / "capa",              # malware-analysis/capa
    CAPA_RS.parent.parent / "capa",       # Dev/capa  (typical)
    CAPA_RS.parent.parent.parent / "capa",
]
PYTHON_CAPA = next(
    (p for p in _candidates if (p / "capa" / "features" / "com" / "classes.py").exists()),
    None,
)
if PYTHON_CAPA is None:
    sys.exit(
        "Python capa source not found. Searched:\n  "
        + "\n  ".join(str(p) for p in _candidates)
        + "\nSet PYTHON_CAPA=/path/to/capa to override."
    )

CLASSES_PY = PYTHON_CAPA / "capa" / "features" / "com" / "classes.py"
INTERFACES_PY = PYTHON_CAPA / "capa" / "features" / "com" / "interfaces.py"
OUT = CAPA_RS / "src" / "rules" / "com_db.rs"

def parse_dict(py_path: Path, dict_name: str) -> dict[str, list[str]]:
    """Parse a `dict_name: dict[str, list[str]] = {...}` literal from py source."""
    src = py_path.read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == dict_name:
            return ast.literal_eval(node.value)
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == dict_name:
                    return ast.literal_eval(node.value)
    raise RuntimeError(f"{dict_name} not found in {py_path}")

def guid_str_to_bytes(s: str) -> bytes:
    """Convert "4590F811-1D3A-11D0-891F-00AA004B2E24" to the 16-byte mixed-endian
    form Windows stores in memory: 11 F8 90 45 3A 1D D0 11 89 1F 00 AA 00 4B 2E 24."""
    parts = s.split("-")
    if len(parts) != 5 or [len(p) for p in parts] != [8, 4, 4, 4, 12]:
        raise ValueError(f"bad GUID: {s!r}")
    a = bytes.fromhex(parts[0])[::-1]   # little-endian u32
    b = bytes.fromhex(parts[1])[::-1]   # little-endian u16
    c = bytes.fromhex(parts[2])[::-1]   # little-endian u16
    d = bytes.fromhex(parts[3])         # big-endian 2 bytes
    e = bytes.fromhex(parts[4])         # big-endian 6 bytes
    out = a + b + c + d + e
    assert len(out) == 16
    return out

def emit_table(name: str, entries: dict[str, list[str]]) -> str:
    # Sort by name (case-sensitive — matches Python dict-insertion-order
    # lookup semantics + we use binary_search at runtime, which needs sorted).
    sorted_items = sorted(entries.items())
    lines = [f"pub static {name}: &[(&str, &[[u8; 16]])] = &["]
    for name_str, guids in sorted_items:
        # escape `"` in name (rare but possible)
        esc = name_str.replace("\\", "\\\\").replace('"', '\\"')
        guid_arrays = []
        for g in guids:
            try:
                b = guid_str_to_bytes(g)
            except ValueError as exc:
                print(f"  skip {esc} -> {g}: {exc}", file=sys.stderr)
                continue
            hex_bytes = ", ".join(f"0x{x:02x}" for x in b)
            guid_arrays.append(f"[{hex_bytes}]")
        if not guid_arrays:
            continue
        joined = ", ".join(guid_arrays)
        lines.append(f'    ("{esc}", &[{joined}]),')
    lines.append("];")
    return "\n".join(lines)

def main() -> None:
    print(f"reading {CLASSES_PY}", file=sys.stderr)
    classes = parse_dict(CLASSES_PY, "COM_CLASSES")
    print(f"  {len(classes)} entries", file=sys.stderr)

    print(f"reading {INTERFACES_PY}", file=sys.stderr)
    interfaces = parse_dict(INTERFACES_PY, "COM_INTERFACES")
    print(f"  {len(interfaces)} entries", file=sys.stderr)

    header = """\
//! COM class / interface GUID database, generated from Python capa's
//! `capa/features/com/classes.py` + `capa/features/com/interfaces.py`.
//!
//! DO NOT EDIT MANUALLY. Regenerate with:
//!
//! ```sh
//! python3 scripts/gen_com_tables.py
//! ```
//!
//! Each entry maps a friendly name (`"WbemLocator"`) to one or more
//! 16-byte CLSIDs/IIDs in Microsoft mixed-endian on-disk byte order.
//! Sorted by name so the runtime can `binary_search_by` lookup at
//! rule-load time. Some COM classes / interfaces had multiple GUIDs
//! across Windows versions, hence the slice-of-arrays shape.
//!
//! Combined size is ~2.3 MB of source, ~250 KB of static data in the
//! final binary after the compiler interns the byte literals.

#![allow(clippy::unreadable_literal)]

"""
    out_text = header + emit_table("COM_CLASSES", classes) + "\n\n" + emit_table("COM_INTERFACES", interfaces) + "\n"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(out_text)
    sz = OUT.stat().st_size
    print(f"wrote {OUT} ({sz / 1024:.1f} KiB)", file=sys.stderr)

if __name__ == "__main__":
    main()
