#!/bin/sh
set -eu

cargo bench --offline --all-features --bench backend_matrix -- "$@"
