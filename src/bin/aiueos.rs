//! `aiueos` — the Phase-0 aiueos command line.
//!
//!   aiueos verify  <manifest|system>.edn [--policy p.edn]   capability + policy check
//!   aiueos inspect <system>.edn          [--policy p.edn]   print the capability graph
//!   aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn]
//!   aiueos compile <source.clj|manifest> [-o out.wasm]      CLJ/Kotoba → wasm
//!   aiueos check   <source.clj>                             safe-kotoba subset gate
//!   aiueos audit   [--log <audit.edn>]                      replay the audit log

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::{CapabilityGraph, System};
use aiueos::manifest::Manifest;
use aiueos::policy::{self, Policy};
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
            eprintln!("aiueos: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "aiueos — capability-secure wasm component OS (Phase-0)\n\n\
         USAGE:\n  \
         aiueos verify  <manifest|system>.edn [--policy p.edn]\n  \
         aiueos inspect <system>.edn          [--policy p.edn]\n  \
         aiueos up      <system>.edn          [--policy p.edn]   boot the whole system\n  \
         aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn]\n  \
         aiueos compile <source.clj|manifest> [-o out.wasm]\n  \
         aiueos check   <source.clj>\n  \
         aiueos audit   [--log <audit.edn>]"
    );
}

/// Tiny flag reader: pull `--name <value>` (or `-o <value>`) out of args.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn positional(args: &[String]) -> Option<&String> {
    args.iter().find(|a| !a.starts_with('-'))
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
    let target = positional(args).ok_or_else(|| schema("verify needs a file"))?;
    let path = PathBuf::from(target);
    let policy = load_policy(args)?;
    let broker = Broker::new(policy, audit_for(&path)?);

    if is_system(&path) {
        let sys = System::load(&path)?;
        let grants = broker.verify_system(&sys)?;
        println!(
            "✓ system `{}` verified — {} component(s):",
            sys.name,
            grants.len()
        );
        for g in &grants {
            println!(
                "  ✓ {}  caps: {}",
                g.component,
                g.capabilities.iter().cloned().collect::<Vec<_>>().join(" ")
            );
        }
    } else {
        let m = Manifest::load(&path)?;
        let graph = CapabilityGraph::build(std::slice::from_ref(&m));
        let g = broker.verify_one(&m, &graph)?;
        println!(
            "✓ component `{}` ({}) verified — caps: {}",
            g.component,
            m.kind.label(),
            g.capabilities.iter().cloned().collect::<Vec<_>>().join(" ")
        );
    }
    Ok(())
}

fn cmd_inspect(args: &[String]) -> aiueos::Result<()> {
    let target = positional(args).ok_or_else(|| schema("inspect needs a system file"))?;
    let path = PathBuf::from(target);
    let sys = System::load(&path)?;
    let graph = sys.graph();
    let policy = load_policy(args)?;

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
        println!("✓ {} :: {}({:?}) = {}", m.id, m.entry, m.args, result);
        println!("  audit: {}", broker.audit.path().display());
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

        // Stages 3–4: verify + launch in order (audited inside the broker).
        let report = broker.boot(&sys, &base)?;
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
