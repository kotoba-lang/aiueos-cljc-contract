# aiueos-cljc-contract (archived — merged into aiueos)

**This repository has been merged back into
[kotoba-lang/aiueos](https://github.com/kotoba-lang/aiueos)** (2026-07-08,
`aiueos@63c13fd`). The split into a separate repo turned out not to need
physical repo separation — the "decides never executes" boundary it existed
to enforce is a code/namespace boundary, already held by `aiueos.broker`/
`aiueos.execute`'s own structure — and the split had produced real drift
(a stale duplicate of `src/aiueos/` living in the wrong repo, a GitHub
content-mismatch, and a package name that leaked an implementation-language
detail into a public coordinate).

All of this repository's history and content (`src/aiueos/*.cljc`,
`test/aiueos/*.cljc`, `resources/aiueos/*.edn`, `bb.edn`, `deps.edn`) now
lives at `kotoba-lang/aiueos`. This repo is kept archived (not deleted) so
existing links and git-dependency pins referencing its old commits keep
resolving.
