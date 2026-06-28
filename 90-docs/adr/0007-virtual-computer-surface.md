# ADR-0007 — The `computer` surface: capability-isolated computer-use

- Status: proposed (Phase 3, builds on ADR-0005)
- Date: 2026-06-28

## Context

"Computer-use" — an agent that screenshots a screen and drives a pointer and
keyboard — is the single most dangerous capability an AI agent can hold: it can
move *your* mouse, type into *your* windows, and click *your* irreversible
buttons. The usual host-side implementations (a macOS `CGEvent`/Accessibility
driver, `xdotool` on the live `:0` display) are coupled to the **real** input
devices and display, so running the agent *takes over the host* — the operator
loses the keyboard and mouse while the agent works, and a misfire lands on the
operator's actual desktop.

The ask: keep computer-use's freedom (drive any GUI app, not just a headless DOM)
**without** the host keyboard/mouse/display ever going active. The naive fix —
point a host-side computer-use driver at a VM *window* — does **not** work: the
host cursor still moves into that window, so the host HID is still used. True
isolation requires the agent to operate a **virtual display + synthetic input**
that the host devices are not wired to, with the agent running *against* that
virtual surface, not the host's `WindowServer`.

aiueos already has the exact machinery for this. ADR-0005 made "the surface is a
value the broker is configured with": a `Surface` binds capability names to
concrete host implementations, the deny-by-default `gate()` (ADR-0002) is
identical on every surface, and **a capability a surface offers no provider for
is a loud `unresolved-capability` denial, never a silent no-op.** ADR-0004's
`admit` forces submitted agent code to the `:ai-generated` trust floor so it
cannot grant itself trust. ADR-0001's audit trail records every decision. The
only thing missing is a surface whose providers are a *virtual* computer.

## Decision

Introduce the **`computer` surface family** — a surface (per ADR-0005) whose
providers back computer-use capabilities with a **virtual display and synthetic
input**, and whose key safety property is *what it deliberately does not offer*:
no provider touches the host's real HID. The capability model, gate, admit floor
and audit are unchanged; this is one more `Surface` in the registry.

### 1. Capabilities (the computer-use ABI)

New `aiueos:host` imports, each gated on its capability exactly like the robot's
seven (ADR-0002):

| import                         | capability          | effect              |
|--------------------------------|---------------------|---------------------|
| `frame() -> i64`               | `display/frame`     | `:display-capture`  |
| `pointer_move(i32,i32)`        | `pointer/move`      | `:synthetic-input`  |
| `pointer_click(i32)`           | `pointer/click`     | `:synthetic-input`  |
| `key(i32)`                     | `keyboard/key`      | `:synthetic-input`  |
| `type(i32,i32)`                | `keyboard/type`     | `:synthetic-input`  |
| `fetch(i32,i32) -> i64`        | `net/fetch`         | `:network`          |
| `clock() -> i64`               | `clock/monotonic`   | —                   |
| `log(i64)`                     | `log/write`         | —                   |

`display/frame` returns a content-addressed handle to a captured framebuffer
(kotoba/CID), not raw memory — Phase-0 numeric ABI, no linear-memory marshaling,
consistent with ADR-0002.

### 2. The anti-capabilities the surface refuses to offer

There is **no** `pointer/host`, `keyboard/host`, or `display/host` provider in
`Surface::computer()`. A component that imports one resolves to a capability the
surface offers no provider for → `unresolved-capability` (ADR-0005 §2), surfaced
loudly at `verify_component`, *before* anything runs. The host HID is unreachable
**by construction**, not by a runtime check the agent might race. As belt-and-
suspenders, the default policy also lists the host-input effect in `:aiueos/forbid`
for `:ai-generated` and `:untrusted`, so a manifest declaring `:host-input` is a
`ForbiddenEffect` denial even earlier. Two independent layers, same verdict.

### 3. Three backings, one manifest (ADR-0005 "one model, many surfaces")

The `computer` surface is a *family*: the same computer-use component manifest
runs against any of these without edits — only the active surface differs.

| surface id          | backing implementation                                  | host isolation                         | WebGPU / GPU        | use |
|---------------------|---------------------------------------------------------|----------------------------------------|---------------------|-----|
| `computer:virtual`  | Linux container (OrbStack/Lima): **Xvfb `:1`** + WM + `x11vnc`/noVNC + Chrome; synthetic input via the X server | **full** — the container has no host HID to reach | software / WebGL2 fallback | headless CI, UX/interaction QA |
| `computer:vm`       | Parallels/QEMU **microVM** with virtio-gpu + a guest input agent | **full** — guest HID, separate from host | near-native (GPU)   | GPU/WebGPU-accurate render checks |
| `computer:host`     | the host `WindowServer` (today's `macos-computer-use`)  | **none** — drives the real desktop     | native              | only via human-signed elevation |

`computer:host` is the dangerous one. It is *not* in the default offered set for
`:ai-generated`; reaching it requires a **signed manifest** (ADR-0003) elevating
the component to `:verified` *and* a policy that names `:aiueos/surface
:computer:host`. Choosing to drive the real desktop is therefore an explicit,
vouched, audited decision — never the default, never self-granted.

### 4. Admission flow (ADR-0004)

The computer-use agent is code-as-data: `aiueos admit` forces its trust to
`:ai-generated` (it cannot claim `:trusted`), checks its imports against the
active surface's offered set, and either runs it (synthetic input → virtual
display) or returns a machine-readable rejection the agent loop reads and retries.
A QA loop becomes: *generate an action plan → `admit` → on reject read the reason
→ regenerate*, with the host physically untouched throughout.

### 5. Attenuated network (capability scoping)

Computer-use QA must reach the target page but nothing else. `net/fetch` is
granted **scoped to an origin allow-list** — the surface analogue of per-topic
`TopicAccess` (ADR-0005 future work): the provider checks the requested origin
against the policy's `:aiueos/net-allow` set and traps otherwise. So the agent can
load `https://isekai.network/**` and is denied every other host, audited.

### 6. Audit (ADR-0001)

Every provider call appends to the audit log with the component id, the active
surface id, and the action (`pointer/click @ (x,y)`, `keyboard/type len`,
`net/fetch origin`, `display/frame -> cid`). The append-only trail is the record
of exactly what the agent did on the virtual surface — reviewable after the fact,
and the provenance for any artifact (e.g. a QA screenshot CID).

## Example

`examples/computer/` (this ADR ships it):

- `computer-use.edn` — the agent component: `:ai-generated`, imports the virtual
  computer-use ABI + a scoped `net/fetch`, no host-HID imports.
- `policy.edn` — `:aiueos/surface :computer:virtual`; grants the surface caps;
  `:aiueos/net-allow #{"isekai.network"}`; forbids `:host-input` for
  `:ai-generated`/`:untrusted`.
- `system.aiueos.edn` — the one-component system graph.

```edn
;; computer-use.edn — drives a virtual screen; CANNOT touch the host.
{:aiueos/component :app/computer-use
 :aiueos/kind :app
 :aiueos/trust :ai-generated            ; admit forces this floor anyway
 :aiueos/source "computer_use.clj"
 :aiueos/entry "run"
 :aiueos/surface #{:computer:virtual :computer:vm}   ; never :computer:host
 :aiueos/imports #{:display/frame :pointer/move :pointer/click
                   :keyboard/key :keyboard/type :net/fetch :clock/monotonic :log/write}
 :aiueos/exports #{:app/main}
 :aiueos/effects #{:display-capture :synthetic-input :network}
 :aiueos/limits {:memory-pages 128 :fuel 50000000}}
```

Boot: `aiueos up examples/computer/system.aiueos.edn --surface computer:virtual`.

## Increments

1. **This ADR + `examples/computer/`** — the manifests, policy, and system graph;
   the capability names added to the documented ABI. *(no code yet)*
2. **`Surface::computer_virtual()`** — the providers as host-side closures over an
   Xvfb display + synthetic X input, each calling `gate()` first; `frame` returns
   a CID. A container recipe (OrbStack/Lima) under `examples/computer/`.
3. **Scoped `net/fetch`** — the origin allow-list provider + `:aiueos/net-allow`
   policy key (closed key allow-list, ADR-0003 fail-loud).
4. **`computer:vm`** — the Parallels/QEMU microVM backing for GPU-accurate runs,
   proving the manifest moves between `:virtual` and `:vm` unchanged.
5. **`computer:host` behind signing** — the host `WindowServer` provider, offered
   only to `:verified` (signed) components with an explicit policy surface, with a
   prominent audit line. The escape hatch, made deliberate.

## Consequences

- (+) Computer-use's freedom is preserved (a full GUI surface, any app) while the
  host keyboard/mouse/display never go active — the operator keeps their machine.
- (+) The isolation is **structural**: the host HID is an un-offered capability,
  denied by the same gate as everything else, not a convention the agent could
  bypass. ADR-0005's "the host refuses to provide what a surface shouldn't" is
  exactly the property we needed.
- (+) The dangerous case (`computer:host`) is not removed but made **explicit,
  signed, and audited** — you can still drive the real desktop, but only by
  vouching for it on purpose.
- (+) The same component runs headless in CI (`computer:virtual`) and GPU-accurate
  on a microVM (`computer:vm`) with no manifest change — portable QA.
- (−) The provider host-side code (Xvfb/X-input bindings, the microVM input
  agent, the `WindowServer` adapter) is **TCB** and must be audited as such,
  exactly like the Phase-7 MMIO/DMA adapters and the browser/cloud brokers of
  ADR-0005. A bug there is a surface bug, not a capability-model bug.
- (−) `computer:virtual` renders WebGPU in software / WebGL2 fallback; pixel-exact
  GPU checks need `computer:vm`. The capability surface is identical; only fidelity
  differs.

## Notes

- This realizes, for computer-use specifically, the SECURITY.md "containment, not
  invulnerability" stance: a compromised or mis-prompted computer-use component is
  a *contained* event on a virtual surface, not a takeover of the operator's
  desktop.
- Relationship to the host MCP: today's `macos-computer-use` is precisely the
  `computer:host` provider — the un-isolated one. Under this ADR it stops being
  the only option and becomes the signed, opt-in escape hatch; the default is a
  virtual surface.
