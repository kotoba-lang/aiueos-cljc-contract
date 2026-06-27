# Security model & threat model

aiueos is designed for **containment under mythos-class adversaries** — the
assumption that any individual component (an app, a driver, an AI-generated task)
may be hostile or compromised, and the OS's job is to ensure that this stays a
*contained* event rather than a system-wide one.

This document is deliberately honest: aiueos is an **architecture for
containment**, not a claim of invulnerability. It tells you both what the design
defends and what it explicitly does not (yet) defend.

## What "mythos-class" means here

A mythos-class adversary is the worst plausible case we design *toward*:

- supplies a malicious component (including via an AI agent that writes code),
- knows the source, manifests and policy,
- will try to reach capabilities it was not granted, exfiltrate secrets, escape
  the sandbox, or take down the whole system from one node.

The goal is that none of those succeed **from inside a component** without an
explicit grant, and that whatever does happen is **audited**.

## Defense layers

1. **Deny-by-default capabilities.** A component can touch *only* what its
   manifest is granted. Imports must resolve to a real provider, a kernel
   primitive, or an explicit policy grant; anything else is an
   `unresolved-capability` denial before launch.
2. **Runtime-enforced gates, not convention.** Capabilities aren't just a static
   claim — the `aiueos:host` ABI checks the conferred set on **every host call**.
   A call to an ungranted capability *traps*; holding some capabilities never
   leaks the ones you weren't given (capability attenuation is tested).
   Enforcement reaches **individual data channels**: a manifest declares the
   topic ids it may publish to / read (`:aiueos/publishes` / `:aiueos/subscribes`),
   and a publish/read to an undeclared topic traps even with the coarse
   `topic/*` capability held — so a compromised sensor cannot command the
   actuator's topic.
3. **Small TCB.** Only the broker, the wasm runtime/host ABI, the safe-subset
   checker and the manifest reader are trusted. Apps, services, drivers and
   agents live *outside* the TCB. Drivers are Wasm components precisely so they
   can be evicted from it.
4. **Wasm isolation + resource limits.** Each component runs in its own linear
   memory under a **fuel** budget (bounds CPU) and a **memory-page cap** (bounds
   RAM). A runaway traps instead of hanging or starving the host.
5. **The IOMMU/DMA rule.** DMA is the one residual way a driver could escape its
   sandbox, so any component with the `:dma` effect *must* declare
   `:requires #{:iommu}` **and** be granted `:iommu`, or it is denied.
6. **Safe-kotoba subset.** Source-built components are screened for escape
   hatches (`eval`, runtime `require`, `slurp`/`spit`, reflection, dotted host
   classes like `java.util.*`) *before* compilation — a security-shaped error,
   not an opaque failure.
7. **AI-generated containment.** A component authored by an AI agent is
   `:ai-generated`: untrusted, ephemeral, and denied `:network`, `:secrets` and
   `:persistent-write` by default policy.
8. **Append-only audit.** Every grant, denial, compile and run is recorded as
   EDN — the same data model as everything else — so post-incident forensics and
   "who commanded the actuator, and why" are first-class.
9. **Manifest authenticity (ed25519 signatures).** A manifest may carry an
   `:aiueos/signature` over the canonical identity↔artifact binding
   (`"<id>\n<wasm-sha256>"`), verified against the policy's `:aiueos/signers`
   registry of trusted public keys. A valid signature elevates the component to
   `:verified` and records the signer in the audit log (provenance); a forged or
   unregistered signature is a hard denial — never downgraded to "unsigned". A
   `:aiueos/require-signed` policy rejects unsigned components outright. (ADR-0003.)

## Per-surface notes

The same component model runs on **edge, robotics, cloud, browser, client**. The
*capabilities offered differ per surface* (a robot grants `topic/*` and device
buses; a browser grants DOM/fetch shims; cloud grants storage/net brokers) but
the deny-by-default gate is identical. A component proven safe on one surface
carries its manifest's capability requirements to the next; the host simply
refuses to provide what that surface shouldn't.

## What aiueos does NOT defend (yet) — honest limitations

- **Side channels.** Timing, cache, Spectre-class and power side channels are
  *not* addressed. Capability isolation is about explicit information flow, not
  microarchitectural leakage.
- **The TCB itself.** A bug in wasmtime, the host adapters, or the broker is
  game over. The TCB is small by design, but it is trusted, not verified — there
  is no formal proof yet.
- **Signing key lifecycle (rotation / revocation / expiry / chains).** Manifest
  *authenticity* now exists — ed25519 signatures over the identity↔artifact
  binding, verified against a trusted-signer registry (defense layer 9). What is
  *not* yet present is the key **lifecycle**: the registry is a flat list with no
  expiry, no revocation, and no certificate chains / delegation. A compromised
  signer key can only be handled by editing the policy. CID-addressed
  supply-chain integrity is also still future work.
- **Preemptive / hard real-time scheduling.** Per-cycle **IO quotas** now bound
  host-call rate (`:aiueos/quota {:host-calls N :publishes N}` — an over-budget
  call traps like any other), and a **deterministic cooperative scheduler**
  (`:aiueos/schedule`, ADR-0006) gives period-skipping and priority ordering
  within dependency depth. What is *not* present is **preemption**: execution is
  cooperative (a component runs to completion or to a fuel/quota trap), so a
  deadline is an audited service-level signal, not an enforced one. True
  preemptive hard-real-time needs the Phase-6 microkernel.
- **Lowest-level drivers.** Real MMIO/DMA/IRQ adapters (Phase 7) will contain
  small `unsafe` code; that code, once written, is part of the TCB and must be
  audited as such.
- **The topic bus is in-process.** Per-topic *isolation* by id-set is enforced
  (a node can only touch the topics it declared), but **cross-machine messaging**
  and **publisher authentication** are not — within one process the bus trusts
  the broker, and topics are still numeric ids rather than named, graph-wired
  capabilities.
- **No confidentiality/crypto** of audit logs or component state at rest.
- **`random()` is deterministic, not a CSPRNG.** The `aiueos:host` `random()` call
  is a reproducible pseudo-random stream (splitmix64 over the run signature +
  control-loop cycle + call index) — chosen for deterministic, replayable boots,
  with distinct components drawing independent streams. It is **predictable** and
  must **not** be used for keys, nonces, tokens, or any security-sensitive value.
  A real entropy source is future work.

If a deployment needs any of the above, it must add it above aiueos — the design
makes room for these (signing hooks, per-surface providers, scheduler) but
Phase-0 does not ship them.

## Reporting

This is a research substrate under active development. If you find a flaw in the
capability model or the TCB, please open an issue describing the component
manifest, the capability it reached, and the expected denial.
