#!/bin/bash

cargo b --release
cargo b --release --target x86_64-apple-darwin
cargo b --release --target x86_64-pc-windows-gnu
cargo b --release --target aarch64-unknown-linux-gnu
cargo b --release --target x86_64-unknown-linux-gnu
cargo b --release --target i686-pc-windows-gnu

cp target/release/auto-ioc dist/auto-ioc-apple-aarch64
cp target/x86_64-apple-darwin/release/auto-ioc dist/auto-ioc-apple-x86_64
cp target/x86_64-unknown-linux-gnu/release/auto-ioc dist/auto-ioc-linux-x86_64
cp target/aarch64-unknown-linux-gnu/release/auto-ioc dist/auto-ioc-linux-aarch64
