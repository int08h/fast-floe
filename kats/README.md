# FLOE known-answer tests

This directory contains the FLOE known-answer tests (KATs) for 64-byte, 4 KiB,
and 1 MiB segment sizes, plus test-only 40-byte vectors that rotate keys every
four segments. Each test case has a plaintext (`*_pt.txt`) and ciphertext
(`*_ct.txt`) encoded as lowercase hexadecimal.

The KATs were copied without modification from the [Snowflake FLOE
specification repository](https://github.com/Snowflake-Labs/floe-specification/tree/main/kats) at commit
`b2380dbb8ee45b0f27b1007545aa9fb2c368f90f`. They are copyright (c) Snowflake Inc. All rights reserved. 
Licensed under the Apache 2.0 license.
