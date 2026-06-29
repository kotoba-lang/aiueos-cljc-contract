# `computer-virtual` backing — the real virtual screen (ADR-0007)

The aiueos `computer-virtual` providers (`src/host.rs`: `frame`, `pointer-move`,
`pointer-click`, `key`, `type`) define the **gated, audited** computer-use ABI. This
directory is the **host-side TCB** that implements them on a *real* virtual screen —
so a computer-use agent drives a browser with synthetic input while the operator's
keyboard/mouse/display **never go active**.

> **The isolated Linux container is the default backing.** When you use computer-use
> (the CLJ/aiueos path), drive it through the container — it has no host display or HID
> at all, so isolation is the baseline, not an opt-in. The headless-Playwright path is
> a dev-machine convenience, not the default. Quick start:
>
> ```sh
> AIUEOS_COMPUTER_BACKING="examples/computer/backing/run.sh" \
> AIUEOS_COMPUTER_URL="https://isekai.network/gftd/orbs" \
>   aiueos run examples/computer/drive.edn --policy examples/computer/policy.edn \
>             --surface computer-virtual            # needs --features computer-backing
> # → ./out/aiueos-frame-0.png, captured inside the container. Your screen is untouched.
> ```

There is deliberately **no host-HID provider** here (no `pointer-host` etc.), so the
real desktop is unreachable by construction — exactly as the surface registry says
(`Surface::computer_virtual` does not offer them; `computer-host` is the signed
escape hatch, not part of this backing).

## The ABI (newline-delimited JSON over stdio)

`surface.mjs` reads one JSON command per line on stdin and writes one JSON reply per
line on stdout. Commands mirror the `aiueos:host` provider names:

| command                                | provider        | effect on the virtual screen        |
|----------------------------------------|-----------------|-------------------------------------|
| `{"op":"goto","url":"…"}`              | (session setup) | load a page (headless Chromium)     |
| `{"op":"pointer-move","x":N,"y":N}`    | `pointer/move`  | `page.mouse.move`                   |
| `{"op":"pointer-click","button":N}`    | `pointer/click` | `page.mouse.down/up` (0=L,1=M,2=R)  |
| `{"op":"key","code":N}`                | `keyboard/key`  | `page.keyboard.press` (13=Enter)    |
| `{"op":"type","text":"…"}`             | `keyboard/type` | `page.keyboard.type`                |
| `{"op":"frame","path":"…"}`            | `display/frame` | `page.screenshot` → PNG, returns id |
| `{"op":"text"}` / `{"op":"close"}`     | —               | read page text / shut down          |

## Backings, same ABI

- **① Isolated container — THE DEFAULT (full Linux isolation, verified).** `run.sh`
  builds (on first use) and runs the `Dockerfile` image: bundled Chromium on a virtual
  framebuffer, **no host HID at all**. `run.sh` IS the backing command — point
  `AIUEOS_COMPUTER_BACKING` at it (see the quick start above) and aiueos pipes the ABI
  to the container; frames land in `./out` (mounted to `/out`, the container's
  `AIUEOS_FRAME_DIR`). Or drive it directly:

  ```sh
  docker build -t aiueos-computer-virtual examples/computer/backing
  mkdir -p out
  docker run --rm -i --init -v "$PWD/out:/out" aiueos-computer-virtual < actions.jsonl
  # → out/<frame>.png captured inside the container; the host screen is never touched.
  ```

- **② Headless Playwright — dev-machine convenience (not the default).** `node
  surface.mjs` — headless Chromium, no host display, no Docker. Needs `playwright`
  resolvable (or `AIUEOS_PW=<path>`). `AIUEOS_PW_CHANNEL=chrome` uses the system Google
  Chrome on a dev Mac; unset uses the bundled Chromium. Lighter for quick local loops,
  but the container is what you should standardize on.

## Proven

A scripted session driven entirely through the ABI — no host display touched —
loaded `https://isekai.network/gftd/orbs`, moved the pointer, clicked, pressed
Enter, typed, and captured a frame:

```
{"ok":true,"title":"isekai.network — play, fork & co-design CLJ/EDN games …"}
{"ok":true}                       # pointer-move 640,400
{"ok":true}                       # pointer-click 0
{"ok":true}                       # key 13 (Enter)
{"ok":true}                       # type "hello orbs"
{"ok":true,"id":1,"path":"…","bytes":354238}   # frame → PNG of the live orbs board
```

## How aiueos routes to it

The in-process providers (`src/host.rs`) are the deterministic, CI-safe contract:
they gate on the capability and append the action to the audit ledger. With the
`computer-backing` feature and `AIUEOS_COMPUTER_BACKING` set, each *already-gated*
action is forwarded to this daemon (the default = the container via `run.sh`), so the
synthetic input drives the real virtual screen. The daemon is TCB — audited like the
Phase-7 MMIO/DMA adapters — and the audit ledger remains the record of what the agent
did, now reflected on a real (isolated) surface instead of an in-process stub. Without
the feature/env, the providers stay the pure in-process ledger.
