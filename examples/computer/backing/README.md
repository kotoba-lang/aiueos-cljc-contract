# `computer-virtual` backing — the real virtual screen (ADR-0007 increment 2/4)

The aiueos `computer-virtual` providers (`src/host.rs`: `frame`, `pointer-move`,
`pointer-click`, `key`, `type`) define the **gated, audited** computer-use ABI. This
directory is the **host-side TCB** that implements them on a *real* virtual screen —
so a computer-use agent drives a browser with synthetic input while the operator's
keyboard/mouse/display **never go active**.

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

## Two deployments, same ABI

- **Headless Playwright (local / CI-light).** `node surface.mjs` — headless Chromium,
  no host display, no Docker. Needs `playwright` resolvable (or `AIUEOS_PW=<path>`).
  Set `AIUEOS_PW_CHANNEL=chrome` to use the system Google Chrome on a dev Mac;
  unset uses Playwright's bundled Chromium.
- **Xvfb-in-container (full Linux isolation, verified).** `Dockerfile` builds an image
  with the bundled Chromium + a virtual framebuffer; under OrbStack/Docker the
  container has **no host HID at all**.

  ```sh
  docker build -t aiueos-computer-virtual examples/computer/backing
  mkdir -p out
  docker run --rm -i --init -v "$PWD/out:/out" aiueos-computer-virtual < actions.jsonl
  # → out/<frame>.png captured inside the container; the host screen is never touched.
  ```

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
they gate on the capability and append the action to the audit ledger. To drive the
*real* screen, a deployment spawns this daemon and forwards each gated action to it
over the ABI above (`computer-backing` glue). The daemon is TCB — audited like the
Phase-7 MMIO/DMA adapters — and the audit ledger remains the record of what the
agent did, now reflected on a real virtual surface instead of an in-process stub.
