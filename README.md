# operator-core (tombstone)

This crate's contents have been **absorbed into [`hanzoai/operator`](https://github.com/hanzoai/operator)** as the `src/core/` module.

Going forward:
- The canonical Rust operator (and its core primitives) lives in `~/work/hanzo/operator/src/`.
- The `src/core/` subdirectory contains the modules that previously lived here: `error.rs`, `leader.rs`, `iam_admin.rs`, `secret.rs`, `status.rs`, `reconciler.rs`.
- The standalone `hanzoai/operator-core` repo and its `hanzo-operator-core` crate are deprecated.

## Why

The operator family (Hanzo, Lux, Zoo, Liquidity, Osage) is being unified onto a single Rust operator binary parameterized by API group. Splitting the core primitives into a separate crate that only the operator depends on adds a release-coupling step without buying any reuse — they always shipped together.

One repo, one binary, one place to look. See [PHILOSOPHY.md](https://raw.githubusercontent.com/hanzoai/.claude/main/agents/PHILOSOPHY.md): "one and only one way to do everything".

## Downstream consumers (Cargo.toml updates needed)

Repos that currently depend on `hanzo-operator-core` via path or git ref need a follow-up PR to depend on `hanzoai/operator` directly (or, if they only need a subset of the primitives, they should vendor the relevant module under their own `src/`):

- `~/work/liquidity/operator`
- `~/work/lux/operator`
- `~/work/zoo/operator`

This is out of scope for the absorption commit; coordinate with each repo's maintainer.

## Archaeology

The original code is preserved in this repo's git history. The `legacy/go-impl-before-rust-port` branch on `hanzoai/operator` preserves the predecessor Go implementation of the operator itself (before it was ported to Rust + collapsed with this crate).
