#!/bin/sh
set -eu

# Benchmark each provider compiled as the sole provider. Co-compiling
# providers into one binary can skew results (see AGENTS.md).
for provider in aws-lc-rs boring ring rustcrypto; do
    for bench in backend_matrix io_adapters; do
        echo "=== provider: $provider bench: $bench ==="
        RUSTFLAGS="-C target-cpu=native" cargo bench --offline \
            --no-default-features --features "$provider" \
            --bench "$bench" -- "$@"
    done
done
