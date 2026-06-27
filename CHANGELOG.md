# Changelog

All notable changes to **aiueos** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); this crate is pre-1.0 (Phase-0).

## [Unreleased]

The Phase-0 substrate plus the runtime/robotics/agent work built on top of it.

### Capability OS core
- Component **manifests** as kotoba (EDN) with strict, fail-loud validation —
  unknown `:aiueos/*` keys, bad kind/trust, out-of-range limits, non-integer
  args, empty entry, and malformed topic maps are all hard errors.
- **Capability graph** + **policy reasoner**: imports must resolve (exporter /
  kernel primitive / grant), effect-vs-trust lockdown (`:ai-generated` denied
  network/secrets/persist), and the driver **DMA→IOMMU** rule.
- **Fail-loud policy files**: unknown `:aiueos/*` policy keys, an unknown trust in
  `:aiueos/forbid`, and non-map `grants`/`forbid` are hard errors (a typo can't
  silently drop a grant or a lockdown).
- **Broker**: verify → safe-check → compile/load → run, every decision audited.
- **Safe-kotoba subset** gate (no eval/require/slurp/reflection/dotted host
  classes) before compiling source.
- **Staged boot** (`aiueos up`, Stage 0–4): link → topological order → verify →
  launch; boot order derived from the capability graph.
- **Duplicate component id** and **device-binding exclusivity** (one driver per
  `bus:vendor:device`) are rejected.

### Runtime + robotics
- Broker-mediated **`aiueos:host` ABI**, capability-gated per call:
  `log` / `clock` / `random` / `publish` / `poll` / `take` / `count`.
- **Topic bus**: latest-value (`poll`) + per-topic **FIFO** queue (`take`) +
  publish `count`; the ROS-topic analogue.
- **Per-topic isolation**: `:aiueos/publishes` / `:aiueos/subscribes` confine a
  component to declared topic ids; a call to an undeclared topic traps.
- **Named topics linked to ids** via `:aiueos/topics {:name id}` — publishes/
  subscribes are derived from the `:topic/<name>` exports/imports.
- **Periodic control loop** (`aiueos up --rounds N`): one bus threaded across N
  rounds; `clock()` returns the monotonic cycle.
- Fuel + linear-memory limits enforced; runaways trap.
- **Per-cycle IO quota** (`:aiueos/quota`, ADR-0006): host-call / publish rate caps
  enforced in the host ABI — an over-budget call traps like an ungranted capability.
- **Cooperative scheduler** (`:aiueos/schedule`, ADR-0006): deterministic
  period-skipping (run every N cycles) + priority ordering *within* dependency
  depth, so an urgent node runs earlier without ever preceding its provider.

### Security / supply chain
- **Artifact integrity**: `:aiueos/wasm-sha256` is verified before run
  (tamper detection); `aiueos hash` computes it.
- **Manifest authenticity (ed25519 signatures, ADR-0003)**: `:aiueos/signature`
  over the identity↔artifact binding, verified against the policy
  `:aiueos/signers` registry. Valid → trust elevated to `:verified` + signer
  audited; forged/unregistered → denied. `:aiueos/require-signed` rejects unsigned
  components. `aiueos sign` produces signatures (`signing` feature, default-on).
- **Audit**: append-only EDN log records grant/deny/compile/run **and runtime
  traps (reject)**; queryable with `aiueos audit --event/--component/--edn`.

### Code as data (agent admission)
- **`Broker::admit` / `aiueos admit`** (ADR-0004): the front door for a component
  an AI agent emits at runtime. Trust is **floored to `:ai-generated`** before
  verification — agent code can never grant itself trust (a signature can still
  elevate it). Returns a structured verdict `{admitted, result, reason,
  reason-code}` so an agent loop branches on a stable `:reason-code`
  (`:denied` / `:unsafe` / `:run` / …) and iterates.

### Tooling / agent surface
- Machine-readable **`--edn`** on `verify`/`inspect`/`up`/`run`/`audit` (verdicts,
  denials, and structural errors all as EDN).
- **`inspect --dot`** — Graphviz of the component dependency graph (named topics
  render as the actual dataflow edges).
- **`up --dry-run`** — link → order → verify a whole system without launching
  anything (CI / pre-boot validation, no side effects).
- `aiueos hash`, helpful errors (e.g. `inspect`/`up` on a single manifest point at
  `verify`/`run`), robust CLI arg parsing.
- A runnable **authoring example** (`examples/authoring/`) kept verified by a test.

### Build / project
- Standalone build: `kotoba-edn` is a git dependency; the CLJ compiler
  (`kototama`) is an opt-in monorepo-only feature.
- **CI** (GitHub Actions): core + exec-only + rustfmt.
- **193 tests + 3 doctests** green across the core / exec-only / full configs.

[Unreleased]: https://github.com/com-junkawasaki/aiueos/commits/main
