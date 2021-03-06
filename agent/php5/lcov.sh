#!/bin/bash

cd "$(dirname "$0")"

set -ex
base_path="$(readlink -f $(dirname "$0"))"

mkdir -p output
output_path="$base_path/output"

rm -rf $output_path/*
rm -f .libs/openrasp.gcda
lcov --directory ./ --capture --no-external --output-file $output_path/original.info
lcov --remove $output_path/original.info "/php5/third_party/*" "/php5/openrasp_v8*" "/php5/utils/DoubleArrayTrie*" "/php5/hook/openrasp_pgsql_utils*" -o $output_path/openrasp.info
genhtml -o $output_path $output_path/openrasp.info
