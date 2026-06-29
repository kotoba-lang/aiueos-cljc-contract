;; A computer-use agent body (Phase-0 WAT stand-in): drive a virtual screen —
;; move the pointer, click, press Enter, type, then capture a frame. With the
;; `computer-backing` feature + AIUEOS_COMPUTER_BACKING set, each gated call is
;; forwarded to the daemon and drives a REAL headless browser.
(module
  (import "aiueos:host" "pointer-move" (func $move (param i32 i32)))
  (import "aiueos:host" "pointer-click" (func $click (param i32)))
  (import "aiueos:host" "key" (func $key (param i32)))
  (import "aiueos:host" "type" (func $type (param i32 i32)))
  (import "aiueos:host" "frame" (func $frame (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 0) "hello orbs")
  (func (export "run") (result i64)
    (call $move (i32.const 640) (i32.const 400))
    (call $click (i32.const 0))
    (call $key (i32.const 13))
    (call $type (i32.const 0) (i32.const 10))
    (call $frame)))   ;; returns the daemon's frame id
