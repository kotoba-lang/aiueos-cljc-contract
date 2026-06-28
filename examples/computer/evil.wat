;; Phase-0 stand-in for the computer-use agent body. A real build emits this from
;; computer_use.clj via kototama; here a tiny WAT lets `aiueos admit` instantiate +
;; run it so the capability verdict (not the pixels) is what we exercise.
(module (func (export "run") (param i64) (result i64) i64.const 0))
