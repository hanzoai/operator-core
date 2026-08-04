# operator-core

Shared reconciler primitives for the Hanzo / Lux / Zoo / Osage Kubernetes
operators. One crate, the load-bearing core that every operator binary
builds on: leader election, IAM admin client, KMSSecret sync guard,
status-condition helpers, the requeue reconciler cadence, and the error
type they all return.

```toml
[dependencies]
hanzo-operator-core = { git = "https://github.com/hanzoai/operator-core", tag = "v0.2.0" }
```

## Modules

| Module          | Provides |
|-----------------|----------|
| `error`         | `OperatorError` + `Result` — the shared error type |
| `leader`        | `coordination.k8s.io/v1` lease-based leader election loop |
| `iam_admin`     | `POST /v1/iam/admin/applications/upsert` client (idempotent app upsert) |
| `secret`        | KMSSecret hijack guard, owner-ref builder, NUL-byte rejection |
| `status`        | `status.conditions` upsert + truncation + degradation convergence |
| `reconciler`    | `Action` requeue cadence + `clamp_resync` |

## Consumers

| Repo                 | Depends via |
|----------------------|-------------|
| `hanzoai/operator`   | vendors the same primitives under `src/core/` (kept in sync) |
| `zooai/operator`     | git dependency, pinned tag |

`zooai/operator` pins `tag = "v0.1.0"` — that tag is immutable and keeps
resolving regardless of `main`. Bumping to `v0.2.0` is additive; existing
pins are untouched.

`hanzoai/operator`'s `src/core/` and this crate are the same primitives.
Any change to one must land in the other (they always ship together).

## Build / Test

```bash
cargo build
cargo test                              # 32 unit tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

MIT OR Apache-2.0, at your option — see [HIP-0137](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0137-one-license.md).
