# Provider feature-unification fixture

This workspace has two libraries enabling different FLOE providers in one
application dependency graph. Cargo must successfully unify both provider 
features.

Run it from the repository root:

```sh
cargo test --manifest-path tests/fixtures/provider-unification/Cargo.toml
```
