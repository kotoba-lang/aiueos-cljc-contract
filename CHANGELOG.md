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
- **Broker**: verify → safe-check → compile/load → run, every decision audited.
- **Safe-kotoba subset** gate (no eval/require/slurp/reflection/dotted host
  classes) before compiling source.
- **Staged boot** (`aiueos up`, Stage 0–4): link → topological order → verify →
  launch; boot order derived from the capability graph.
- **Duplicate component id** and **device-binding exclusivity** (one driver per
  `bus:vendor:device`) are rejected.

### Runtime + robotics
- Broker-mediated **`aiueos:host` ABI**, capability-gated per call:
  `log` / `clock` / `publish` / `poll` / `take` / `count`.
- **Topic bus**: latest-value (`poll`) + per-topic **FIFO** queue (`take`) +
  publish `count`; the ROS-topic analogue.
- **Per-topic isolation**: `:aiueos/publishes` / `:aiueos/subscribes` confine a
  component to declared topic ids; a call to an undeclared topic traps.
- **Named topics linked to ids** via `:aiueos/topics {:name id}` — publishes/
  subscribes are derived from the `:topic/<name>` exports/imports.
- **Periodic control loop** (`aiueos up --rounds N`): one bus threaded across N
  rounds; `clock()` returns the monotonic cycle.
- Fuel + linear-memory limits enforced; runaways trap.

### Security / supply chain
- **Artifact integrity**: `:aiueos/wasm-sha256` is verified before run
  (tamper detection); `aiueos hash` computes it.
- **Audit**: append-only EDN log records grant/deny/compile/run **and runtime
  traps (reject)**; queryable with `aiueos audit --event/--component/--edn`.

### Tooling / agent surface
- Machine-readable **`--edn`** on `verify`/`inspect`/`up`/`run`/`audit` (verdicts,
  denials, and structural errors all as EDN).
- **`inspect --dot`** — Graphviz of the component dependency graph.
- `aiueos hash`, helpful errors (e.g. `inspect` on a single manifest), robust CLI
  arg parsing.

### Build / project
- Standalone build: `kotoba-edn` is a git dependency; the CLJ compiler
  (`kototama`) is an opt-in monorepo-only feature.
- **CI** (GitHub Actions): core + exec-only + rustfmt.
- **142 tests + 3 doctests** green across the core / exec-only / full configs.

[Unreleased]: https://github.com/com-junkawasaki/aiueos/commits/main
