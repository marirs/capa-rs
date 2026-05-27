# FLIRT signatures for capa-rs

This directory contains FLIRT (Fast Library Identification and
Recognition Technology) signature files that capa-rs uses to
identify statically-linked library functions in analysed binaries
and exclude them from the capability output. Without this filter,
stripped MSVC malware samples drown in `memcpy` / `strlen` /
`_RTC_*` noise.

## Layout

```
flirt-sigs/
├── mandiant/
│   ├── 1_flare_msvc_rtf_32_64.sig    — MSVC CRT/runtime (x86 + x64)
│   ├── 2_flare_msvc_atlmfc_32_64.sig — ATL / MFC
│   └── 3_flare_common_libs.sig        — OpenSSL, zlib, common
│                                        Windows static libs
└── flirtdb/
    ├── boost/windows/        — Boost (multiple versions)
    ├── cmt/windows/          — MSVC C runtime (cmt.lib)
    ├── cpmt/windows/         — MSVC C++ standard library (cpmt.lib)
    ├── directx5/windows/     — DirectX 5
    ├── directx6.1/windows/   — DirectX 6.1
    ├── directx8/windows/     — DirectX 8
    ├── intel/windows/        — Intel libraries
    ├── libcurl/windows/      — libcurl
    ├── lua/windows/          — Lua
    ├── openssl/windows/      — OpenSSL (multiple versions)
    ├── protobuf/windows/     — Protocol Buffers
    └── vcruntime/windows/    — MSVC vcruntime (modern CRT)
```

195 `.sig` files in total, ~70 MB on disk.

## Usage

```sh
capa_cli --signatures path/to/flirt-sigs/ -r path/to/capa-rules/ sample.exe
```

The matcher recurses the directory, so pointing at the root loads
both `mandiant/` and `flirtdb/` automatically.

## Credits

The signatures in this directory are redistributed under their
upstream Apache-2.0 / community-permissive licenses and remain the
work of their original authors. capa-rs ships them unmodified.

### Mandiant FLARE corpus (`mandiant/`)

The three `.sig` files in `mandiant/` come from Mandiant's
[**capa**](https://github.com/mandiant/capa) repository, specifically
[`mandiant/capa/sigs/`](https://github.com/mandiant/capa/tree/master/sigs).
Apache-2.0 licensed. Built by the FLARE team at Mandiant using the
proprietary Hex-Rays FLAIR toolkit against MSVC `.lib` files.

### FLIRTDB (`flirtdb/`)

The signatures in `flirtdb/` come from
[**FLIRTDB**](https://github.com/Maktm/FLIRTDB) by
**Michael Kiros** ([@Maktm](https://github.com/Maktm)) — a
community-driven collection of IDA FLIRT signature files covering
many MSVC versions, OpenSSL builds, boost, libcurl, lua,
protobuf, DirectX, and Intel libraries on Windows.

Both upstream sources do the hard work of generating, deduplicating,
and curating these signatures across the many library versions that
appear in real-world binaries. capa-rs's contribution is purely the
matching engine integration (via the
[`lancelot-flirt`](https://crates.io/crates/lancelot-flirt) crate by
Willi Ballenthin) and convenient packaging — none of the signature
content originates here.

## Updating

To pull fresh signatures from upstream:

```sh
# Mandiant
cp /path/to/capa-checkout/sigs/*.sig mandiant/

# FLIRTDB (sigs only, skip .pat / .lib / .exc / .txt)
cd /path/to/FLIRTDB-checkout
find . -name "*.sig" -type f | while read f; do
    rel="${f#./}"
    mkdir -p "/path/to/capa-rs/flirt-sigs/flirtdb/$(dirname "$rel")"
    cp "$f" "/path/to/capa-rs/flirt-sigs/flirtdb/$(dirname "$rel")/"
done
```
