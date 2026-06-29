#!/usr/bin/env node
// computer-virtual backing daemon (aiueos ADR-0007). Implements the computer-use
// provider ABI — frame / pointer-move / pointer-click / key / type — over a real
// VIRTUAL screen (headless Chromium). No host display, no host HID. The host-side
// TCB that sits behind the aiueos `computer-virtual` providers.
//
// Protocol: newline-delimited JSON on stdin; one JSON reply per line on stdout.
//   {"op":"goto","url":"…"}            -> {"ok":true,"title":…}
//   {"op":"pointer-move","x":N,"y":N}  -> {"ok":true}
//   {"op":"pointer-click","button":N}  -> {"ok":true}   (0=left,1=middle,2=right)
//   {"op":"key","code":N}              -> {"ok":true}   (DOM key code; 13=Enter)
//   {"op":"type","text":"…"}           -> {"ok":true}
//   {"op":"frame","path":"…"}          -> {"ok":true,"id":N,"path":…,"bytes":N}
//   {"op":"text"}                      -> {"ok":true,"text":…}
//   {"op":"close"}                     -> {"ok":true}  then exit
import readline from "node:readline";
const PW = process.env.AIUEOS_PW || "playwright";
const _pw = await import(PW); const chromium = _pw.chromium ?? _pw.default?.chromium;
const KEY = { 13: "Enter", 9: "Tab", 27: "Escape", 32: " ", 37: "ArrowLeft", 38: "ArrowUp", 39: "ArrowRight", 40: "ArrowDown", 8: "Backspace" };
// AIUEOS_PW_CHANNEL=chrome uses the system Google Chrome (handy on a dev Mac);
// unset uses Playwright's bundled Chromium (the portable default — e.g. in the
// container image, where no system Chrome exists).
const CHANNEL = process.env.AIUEOS_PW_CHANNEL || undefined;
const browser = await chromium.launch({ channel: CHANNEL, headless: true,
  args: ["--enable-unsafe-webgpu","--use-angle=metal","--ignore-gpu-blocklist","--no-sandbox"] });
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
let frames = 0;
const reply = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const rl = readline.createInterface({ input: process.stdin });
for await (const line of rl) {
  const s = line.trim(); if (!s) continue;
  let cmd; try { cmd = JSON.parse(s); } catch { reply({ ok:false, err:"bad json" }); continue; }
  try {
    switch (cmd.op) {
      case "goto":          await page.goto(cmd.url, { waitUntil: "networkidle" }); reply({ ok:true, title: await page.title() }); break;
      case "pointer-move":  await page.mouse.move(cmd.x, cmd.y); reply({ ok:true }); break;
      case "pointer-click": await page.mouse.down({ button: ["left","middle","right"][cmd.button||0] }); await page.mouse.up({ button: ["left","middle","right"][cmd.button||0] }); reply({ ok:true }); break;
      case "key":           await page.keyboard.press(KEY[cmd.code] || String.fromCharCode(cmd.code)); reply({ ok:true }); break;
      case "type":          await page.keyboard.type(cmd.text ?? ""); reply({ ok:true }); break;
      case "frame": {       const dir = process.env.AIUEOS_FRAME_DIR || "/tmp"; const path = cmd.path || `${dir}/aiueos-frame-${frames}.png`; const buf = await page.screenshot({ path }); frames++; reply({ ok:true, id: frames, path, bytes: buf.length }); break; }
      case "text":          reply({ ok:true, text: (await page.evaluate(()=>document.body?.innerText||"")).slice(0,2000) }); break;
      case "close":         reply({ ok:true }); await browser.close(); process.exit(0);
      default:              reply({ ok:false, err:"unknown op "+cmd.op });
    }
  } catch (e) { reply({ ok:false, err: String(e.message||e) }); }
}
