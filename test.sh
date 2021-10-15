#!/bin/bash

rm -rf ./tests_res
mkdir ./tests_res

for filename in ./capa-testfiles/*.dll_; do
    echo $filename
    cargo run --release --example cli -- $filename 1>./tests_res/$(basename $filename).json 2>./tests_res/$(basename $filename).err
    ./capa -b smda $filename 1>./tests_res/$(basename $filename).capa 2>./tests_res/$(basename $filename).capa.err
done

for filename in ./capa-testfiles/*.exe_; do
    echo $filename
    cargo run --release --example cli -- $filename 1>./tests_res/$(basename $filename).json 2>./tests_res/$(basename $filename).err
    ./capa -b smda $filename 1>./tests_res/$(basename $filename).capa 2>./tests_res/$(basename $filename).capa.err
done
