#!/bin/bash

CURRENT_VER=$(head Cargo.toml | grep version | cut -f2 -d'=' | cut -f2 -d\")

# current M1 (aarch) apple binary
cargo b --release --example capa_cli

# rest of the platforms binary
cargo b --release --example capa_cli --target x86_64-apple-darwin
cargo b --release --example capa_cli --target x86_64-pc-windows-gnu
cargo b --release --example capa_cli --target aarch64-unknown-linux-gnu
cargo b --release --example capa_cli --target x86_64-unknown-linux-gnu

# remove existing files
rm -rf tmp
# make the folder again
mkdir -p tmp

# copy files to the tmp folder
# win
cp target/x86_64-pc-windows-gnu/release/examples/capa_cli.exe tmp/capa_cli_x86-64.exe
# macos
cp target/release/examples/capa_cli tmp/capa_macos_aarch64
cp target/x86_64-apple-darwin/release/examples/capa_cli tmp/capa_macos_x86-64
# linux
cp target/aarch64-unknown-linux-gnu/release/examples/capa_cli tmp/capa_linux_aarch64
cp target/x86_64-unknown-linux-gnu/release/examples/capa_cli tmp/capa_linux_x86-64

# create the new zip files
cd tmp
zip -9r capa-rs"$CURRENT_VER"-windows.zip capa_cli_x86-64.exe
zip -9r capa-rs"$CURRENT_VER"-macos.zip capa_macos_aarch64 capa_macos_x86-64
zip -9r capa-rs"$CURRENT_VER"-linux.zip capa_linux_aarch64 capa_linux_x86-64
cd ..

# delete the tmp files
rm -f tmp/capa_cli_x86-64.exe tmp/capa_macos_aarch64 tmp/capa_macos_x86-64 tmp/capa_linux_aarch64 tmp/capa_linux_x86-64
