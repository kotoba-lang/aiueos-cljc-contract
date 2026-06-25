//! `aiueos` — the Phase-0 aiueos command line.
//!
//!   aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]   capability + policy check
//!   aiueos inspect <system>.edn          [--policy p.edn] [--edn]   print the capability graph
//!   aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]
//!   aiueos compile <source.clj|manifest> [-o out.wasm]      CLJ/Kotoba → wasm
//!   aiueos check   <source.clj>                             safe-kotoba subset gate
//!   aiueos hash    <file> [--edn]                           sha256 for :aiueos/wasm-sha256
//!   aiueos audit   [--log <audit.edn>]                      replay the audit log

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::{CapabilityGraph, System};
use aiueos::manifest::Manifest;
use aiueos::policy::{self, Grant, Policy, Violation};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args.get(1..).unwrap_or(&[]);
    let r = match cmd {
        "verify" => cmd_verify(rest),
        "inspect" => cmd_inspect(rest),
        "up" => cmd_up(rest),
        "run" => cmd_run(rest),
        "compile" => cmd_compile(rest),
        "check" => cmd_check(rest),
        "hash" => cmd_hash(rest),
        "audit" => cmd_audit(rest),
        "" | "-h" | "--help" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("aiueos: unknown command `{other}`\n");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // In --edn mode, a structural failure is reported as EDN on stdout too,
            // so an agent consuming the machine-readable surface never has to fall
            // back to parsing human prose.
            let edn = rest.iter().any(|a| a == "--edn")
                && matches!(cmd, "verify" | "inspect" | "up" | "run");
            if edn {
                println!("{}", error_edn(&e));
            } else {
                eprintln!("aiueos: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

/// A structural error rendered as EDN (for --edn mode): `{:aiueos/error "..."
/// :aiueos/kind :io|:edn|:schema|:denied|:unsafe|:compile|:run}`.
fn error_edn(e: &aiueos::AiueosError) -> String {
    use aiueos::AiueosError as Err;
    use kotoba_edn::EdnValue as E;
    let kind = match e {
        Err::Io(_) => "io",
        Err::Edn(_) => "edn",
        Err::Schema(_) => "schema",
        Err::Denied(_) => "denied",
        Err::Unsafe(_) => "unsafe",
        Err::Compile(_) => "compile",
        Err::Run(_) => "run",
    };
    kotoba_edn::to_string(&E::map([
        (E::kw("aiueos", "error"), E::string(e.to_string())),
        (E::kw("aiueos", "kind"), E::kw_bare(kind)),
    ]))
}

fn print_usage() {
    eprintln!(
        "aiueos — capability-secure wasm component OS (Phase-0)\n\n\
         USAGE:\n  \
         aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]\n  \
         aiueos inspect <system>.edn          [--policy p.edn] [--edn]\n  \
         aiueos up      <system>.edn          [--policy p.edn] [--edn]   boot the whole system\n  \
         aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]\n  \
         aiueos compile <source.clj|manifest> [-o out.wasm]\n  \
         aiueos check   <source.clj>\n  \
         aiueos hash    <file> [--edn]\n  \
         aiueos audit   [--log <audit.edn>]"
    );
}

/// Flags that consume the following argument as their value.
const VALUE_FLAGS: &[&str] = &["--policy", "--system", "--log", "-o", "--out"];

/// Tiny flag reader: pull `--name <value>` (or `-o <value>`) out of args.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// First positional argument, skipping flags *and* the values they consume — so
/// `verify --policy p.edn sys.edn` returns `sys.edn`, not the policy file.
fn positional(args: &[String]) -> Option<&String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if VALUE_FLAGS.contains(&a.as_str()) {
            i += 2; // skip the flag and its value
        } else if a.starts_with('-') {
            i += 1; // a boolean flag like --edn
        } else {
            return Some(a);
        }
    }
    None
}

fn load_policy(args: &[String]) -> aiueos::Result<Policy> {
    match flag(args, "--policy") {
        Some(p) => Policy::load(Path::new(&p)),
        None => Ok(Policy::default()),
    }
}

fn audit_for(path: &Path) -> aiueos::Result<AuditLog> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    AuditLog::under(dir)
}

/// True if the EDN file is a system graph (`:aiueos/components`) rather than a
/// single component manifest.
fn is_system(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| kotoba_edn::parse(&s).ok())
        .map(|v| aiueos::edn::get(&v, "aiueos", "components").is_some())
        .unwrap_or(false)
}

fn cmd_verify(args: &[String]) -> aiueos::Result<()> {
    let edn_mode = args.iter().any(|a| a == "--edn");
    let target = positional(args).ok_or_else(|| schema("verify needs a file"))?;
    let path = PathBuf::from(target);
    let policy = load_policy(args)?;
    let broker = Broker::new(policy, audit_for(&path)?);

    // Collapse to (name, Ok(grants) | Err(violations)); structural errors (bad
    // file, schema) still propagate as before.
    let denied = |e: aiueos::AiueosError| match e {
        aiueos::AiueosError::Denied(vs) => Ok(Err(vs)),
        other => Err(other),
    };
    let (name, result): (String, std::result::Result<Vec<Grant>, Vec<Violation>>) =
        if is_system(&path) {
            let sys = System::load(&path)?;
            let r = broker.verify_system(&sys).map(Ok).or_else(denied)?;
            (sys.name, r)
        } else {
            let m = Manifest::load(&path)?;
            let graph = CapabilityGraph::build(std::slice::from_ref(&m));
            let r = broker
                .verify_one(&m, &graph)
                .map(|g| Ok(vec![g]))
                .or_else(denied)?;
            (m.id.clone(), r)
        };

    if edn_mode {
        // Machine-readable verdict for tooling / AI agents; exit code still
        // reflects pass (0) / fail (1).
        println!("{}", verdict_edn(&name, &result));
        return match result {
            Ok(_) => Ok(()),
            Err(_) => std::process::exit(1),
        };
    }

    match result {
        Ok(grants) => {
            println!("✓ `{name}` verified — {} component(s):", grants.len());
            for g in &grants {
                println!(
                    "  ✓ {}  caps: {}",
                    g.component,
                    g.capabilities.iter().cloned().collect::<Vec<_>>().join(" ")
                );
            }
            Ok(())
        }
        Err(vs) => Err(aiueos::AiueosError::Denied(vs)),
    }
}

/// Build a machine-readable EDN verdict (consistent with the EDN audit log).
fn verdict_edn(name: &str, result: &std::result::Result<Vec<Grant>, Vec<Violation>>) -> String {
    use kotoba_edn::EdnValue as E;
    let mut entries = vec![
        (E::kw("aiueos", "system"), E::string(name)),
        (E::kw("aiueos", "verified"), E::bool(result.is_ok())),
    ];
    match result {
        Ok(grants) => {
            let g = grants.iter().map(|g| {
                (
                    E::string(g.component.clone()),
                    E::set(g.capabilities.iter().map(|c| E::string(c.clone()))),
                )
            });
            entries.push((E::kw("aiueos", "grants"), E::map(g)));
        }
        Err(vs) => {
            let v = vs.iter().map(|v| {
                E::map([
                    (E::kw_bare("component"), E::string(v.component.clone())),
                    (E::kw_bare("kind"), E::kw_bare(v.kind.label())),
                    (E::kw_bare("message"), E::string(v.message.clone())),
                ])
            });
            entries.push((E::kw("aiueos", "violations"), E::vector(v)));
        }
    }
    kotoba_edn::to_string(&E::map(entries))
}

fn cmd_inspect(args: &[String]) -> aiueos::Result<()> {
    let target = positional(args).ok_or_else(|| schema("inspect needs a system file"))?;
    let path = PathBuf::from(target);
    let sys = System::load(&path)?;
    let graph = sys.graph();
    let policy = load_policy(args)?;

    if args.iter().any(|a| a == "--edn") {
        println!("{}", inspect_edn(&sys, &graph, &policy));
        return Ok(());
    }

    println!("system: {}", sys.name);
    println!("\ncomponents ({}):", sys.components.len());
    for c in &sys.components {
        println!(
            "  • {:24} kind={:<16} trust={:<12} effects={{{}}}",
            c.id,
            c.kind.label(),
            c.trust.label(),
            c.effects.join(" ")
        );
        if let Some(d) = &c.device {
            let id = match (&d.vendor, &d.device) {
                (Some(v), Some(dev)) => format!(" {v}:{dev}"),
                _ => String::new(),
            };
            println!(
                "      device: bus={}{}",
                d.bus.as_deref().unwrap_or("?"),
                id
            );
        }
    }

    println!("\ncapability graph (capability → providers):");
    if graph.all().is_empty() {
        println!("  (no exported capabilities)");
    }
    for (cap, providers) in graph.all() {
        println!("  {cap}  ⇐  {}", providers.join(", "));
    }

    println!("\npolicy verification:");
    for c in &sys.components {
        match policy::verify_component(c, &graph, &policy) {
            Ok(g) => println!(
                "  ✓ {:24} → {}",
                c.id,
                g.capabilities.iter().cloned().collect::<Vec<_>>().join(" ")
            ),
            Err(vs) => {
                for v in vs {
                    println!("  ✗ {:24} [{}] {}", c.id, v.kind.label(), v.message);
                }
            }
        }
    }
    Ok(())
}

/// Machine-readable system snapshot: components, the capability graph, and the
/// per-component policy verdicts — all as EDN.
fn inspect_edn(sys: &System, graph: &CapabilityGraph, policy: &Policy) -> String {
    use kotoba_edn::EdnValue as E;
    let strset = |xs: &[String]| E::set(xs.iter().map(|s| E::string(s.clone())));

    let components = E::vector(sys.components.iter().map(|c| {
        let mut fields = vec![
            (E::kw_bare("id"), E::string(c.id.clone())),
            (E::kw_bare("kind"), E::kw_bare(c.kind.label())),
            (E::kw_bare("trust"), E::kw_bare(c.trust.label())),
            (E::kw_bare("imports"), strset(&c.imports)),
            (E::kw_bare("exports"), strset(&c.exports)),
            (E::kw_bare("effects"), strset(&c.effects)),
        ];
        if let Some(d) = &c.device {
            let dev = E::map(
                [
                    ("bus", &d.bus),
                    ("vendor", &d.vendor),
                    ("device", &d.device),
                ]
                .into_iter()
                .filter_map(|(k, v)| v.as_ref().map(|s| (E::kw_bare(k), E::string(s.clone())))),
            );
            fields.push((E::kw_bare("device"), dev));
        }
        E::map(fields)
    }));

    let graph_edn = E::map(
        graph
            .all()
            .iter()
            .map(|(cap, ps)| (E::string(cap.clone()), strset(ps))),
    );

    let verdicts = E::vector(sys.components.iter().map(|c| {
        match policy::verify_component(c, graph, policy) {
            Ok(g) => E::map([
                (E::kw_bare("component"), E::string(c.id.clone())),
                (E::kw_bare("verified"), E::bool(true)),
                (
                    E::kw_bare("caps"),
                    E::set(g.capabilities.iter().map(|s| E::string(s.clone()))),
                ),
            ]),
            Err(vs) => E::map([
                (E::kw_bare("component"), E::string(c.id.clone())),
                (E::kw_bare("verified"), E::bool(false)),
                (
                    E::kw_bare("violations"),
                    E::vector(vs.iter().map(|v| {
                        E::map([
                            (E::kw_bare("kind"), E::kw_bare(v.kind.label())),
                            (E::kw_bare("message"), E::string(v.message.clone())),
                        ])
                    })),
                ),
            ]),
        }
    }));

    kotoba_edn::to_string(&E::map([
        (E::kw("aiueos", "system"), E::string(sys.name.clone())),
        (E::kw("aiueos", "components"), components),
        (E::kw("aiueos", "graph"), graph_edn),
        (E::kw("aiueos", "verdicts"), verdicts),
    ]))
}

fn cmd_run(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("run needs a manifest"))?;
        let path = PathBuf::from(target);
        let base = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let m = Manifest::load(&path)?;
        let policy = load_policy(args)?;
        let broker = Broker::new(policy, audit_for(&path)?);

        // Build the capability graph: from a system if given, else just this one.
        let graph = match flag(args, "--system") {
            Some(s) => System::load(Path::new(&s))?.graph(),
            None => CapabilityGraph::build(std::slice::from_ref(&m)),
        };

        let result = broker.launch(&m, &base, &graph)?;
        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            println!(
                "{}",
                kotoba_edn::to_string(&E::map([
                    (E::kw("aiueos", "component"), E::string(m.id.clone())),
                    (E::kw("aiueos", "entry"), E::string(m.entry.clone())),
                    (
                        E::kw("aiueos", "args"),
                        E::vector(m.args.iter().map(|a| E::int(*a))),
                    ),
                    (E::kw("aiueos", "result"), E::int(result)),
                ]))
            );
        } else {
            println!("✓ {} :: {}({:?}) = {}", m.id, m.entry, m.args, result);
            println!("  audit: {}", broker.audit.path().display());
        }
        Ok(())
    }
}

fn cmd_up(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("up needs a system file"))?;
        let path = PathBuf::from(target);
        let base = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let sys = System::load(&path)?;
        let policy = load_policy(args)?;
        let broker = Broker::new(policy, audit_for(&path)?);
        let edn_mode = args.iter().any(|a| a == "--edn");

        if !edn_mode {
            println!("aiueos boot — system `{}`", sys.name);
            // Stage 1–2: capability link → boot order (shown before launching).
            let graph = sys.graph();
            println!(
                "  link: {} capabilities across {} components",
                graph.all().len(),
                sys.components.len()
            );
            match sys.boot_order() {
                Ok(order) => {
                    let names: Vec<&str> = order
                        .iter()
                        .map(|&i| sys.components[i].id.as_str())
                        .collect();
                    println!("  order: {}", names.join(" → "));
                }
                Err(cycle) => {
                    return Err(schema(&format!("dependency cycle: {}", cycle.join(" → "))));
                }
            }
        }

        // Stages 3–4: verify + launch in order (audited inside the broker).
        let report = broker.boot(&sys, &base)?;

        if edn_mode {
            use kotoba_edn::EdnValue as E;
            let launched = E::vector(report.launched.iter().map(|o| {
                let mut f = vec![
                    (E::kw_bare("component"), E::string(o.component.clone())),
                    (E::kw_bare("kind"), E::kw_bare(o.kind)),
                ];
                match o.result {
                    Some(r) => f.push((E::kw_bare("result"), E::int(r))),
                    None => f.push((E::kw_bare("resident"), E::bool(true))),
                }
                E::map(f)
            }));
            println!(
                "{}",
                kotoba_edn::to_string(&E::map([
                    (E::kw("aiueos", "system"), E::string(report.system.clone())),
                    (E::kw("aiueos", "launched"), launched),
                ]))
            );
            return Ok(());
        }

        for o in &report.launched {
            match o.result {
                Some(v) => println!("  ✓ {:24} ({:<8}) → {}", o.component, o.kind, v),
                None => println!("  ✓ {:24} ({:<8})   resident", o.component, o.kind),
            }
        }
        println!(
            "✓ system up — {}/{} components launched",
            report.launched.len(),
            sys.components.len()
        );
        println!("  audit: {}", broker.audit.path().display());
        Ok(())
    }
}

fn cmd_compile(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "kototama"))]
    {
        let _ = args;
        return Err(run_err(
            "built without the `kototama` feature (CLJ compiler)",
        ));
    }
    #[cfg(feature = "kototama")]
    {
        let target = positional(args).ok_or_else(|| schema("compile needs a source/manifest"))?;
        let path = PathBuf::from(target);
        // A manifest (`.edn`) names its source; a `.clj` is the source itself.
        let (src_path, src) = if path.extension().and_then(|e| e.to_str()) == Some("edn") {
            let m = Manifest::load(&path)?;
            let rel = m
                .source
                .ok_or_else(|| schema("manifest has no :aiueos/source to compile"))?;
            let sp = path.parent().unwrap_or_else(|| Path::new(".")).join(&rel);
            let s = std::fs::read_to_string(&sp)?;
            (sp, s)
        } else {
            let s = std::fs::read_to_string(&path)?;
            (path.clone(), s)
        };

        aiueos::safe::check(&src)?;
        let wasm = aiueos::runtime::compile_source(&src)?;
        let out = flag(args, "-o")
            .or_else(|| flag(args, "--out"))
            .map(PathBuf::from)
            .unwrap_or_else(|| src_path.with_extension("wasm"));
        std::fs::write(&out, &wasm)?;
        println!(
            "✓ compiled {} → {} ({} bytes)",
            src_path.display(),
            out.display(),
            wasm.len()
        );
        Ok(())
    }
}

fn cmd_check(args: &[String]) -> aiueos::Result<()> {
    let target = positional(args).ok_or_else(|| schema("check needs a source file"))?;
    let src = std::fs::read_to_string(target)?;
    aiueos::safe::check(&src)?;
    println!("✓ {target} is within the safe-kotoba subset");
    Ok(())
}

fn cmd_hash(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("hash needs a file"))?;
        let bytes = std::fs::read(target)?;
        let hex = aiueos::runtime::sha256_hex(&bytes);
        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            println!(
                "{}",
                kotoba_edn::to_string(&E::map([
                    (E::kw("aiueos", "path"), E::string(target.clone())),
                    (E::kw("aiueos", "sha256"), E::string(hex)),
                ]))
            );
        } else {
            // `<hex>  <path>` — paste the hex into the manifest's :aiueos/wasm-sha256.
            println!("{hex}  {target}");
        }
        Ok(())
    }
}

fn cmd_audit(args: &[String]) -> aiueos::Result<()> {
    let log = match flag(args, "--log") {
        Some(p) => AuditLog::new(p),
        None => AuditLog::new(PathBuf::from(".aiueos/audit.edn")),
    };
    let entries = log.read()?;
    if entries.is_empty() {
        println!("(no audit entries at {})", log.path().display());
        return Ok(());
    }
    println!(
        "audit log: {} ({} entries)",
        log.path().display(),
        entries.len()
    );
    for e in &entries {
        let ts = aiueos::edn::get(e, "aiueos", "ts")
            .and_then(|v| v.as_integer())
            .unwrap_or(0);
        let ev = aiueos::edn::get_kw(e, "aiueos", "event").unwrap_or_default();
        let comp = aiueos::edn::get_str(e, "aiueos", "component").unwrap_or_default();
        let detail = aiueos::edn::get_str(e, "aiueos", "detail").unwrap_or_default();
        println!("  [{ts}] {ev:<8} {comp:<24} {detail}");
    }
    Ok(())
}

fn schema(msg: &str) -> aiueos::AiueosError {
    aiueos::AiueosError::Schema(msg.to_string())
}

#[allow(dead_code)] // only used by the feature-disabled command stubs
fn run_err(msg: &str) -> aiueos::AiueosError {
    aiueos::AiueosError::Run(msg.to_string())
}
