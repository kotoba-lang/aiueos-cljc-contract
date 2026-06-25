//! The audit log. Every capability decision (grant/deny) and every component
//! lifecycle event (compile/run) is appended as one EDN map per line, so the log
//! is itself "kotoba" — queryable with the same reader as everything else.

use crate::error::Result;
use kotoba_edn::EdnValue;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Grant,
    Deny,
    Compile,
    Run,
    Reject, // safe-subset rejection
}

impl Event {
    fn keyword(self) -> &'static str {
        match self {
            Event::Grant => "grant",
            Event::Deny => "deny",
            Event::Compile => "compile",
            Event::Run => "run",
            Event::Reject => "reject",
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> AuditLog {
        AuditLog { path: path.into() }
    }

    /// Default location: `.aiueos/audit.edn` under `dir`.
    pub fn under(dir: &Path) -> Result<AuditLog> {
        let d = dir.join(".aiueos");
        std::fs::create_dir_all(&d)?;
        Ok(AuditLog::new(d.join("audit.edn")))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Append one audited event.
    pub fn append(&self, event: Event, component: &str, detail: &str) -> Result<()> {
        let entry = EdnValue::map([
            (
                EdnValue::kw("aiueos", "ts"),
                EdnValue::int(Self::now_secs()),
            ),
            (
                EdnValue::kw("aiueos", "event"),
                EdnValue::kw_bare(event.keyword()),
            ),
            (
                EdnValue::kw("aiueos", "component"),
                EdnValue::string(component),
            ),
            (EdnValue::kw("aiueos", "detail"), EdnValue::string(detail)),
        ]);
        let line = kotoba_edn::to_string(&entry);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    /// Read the raw log back (one EDN map per line). Missing file → empty.
    pub fn read(&self) -> Result<Vec<EdnValue>> {
        let src = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in src.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(kotoba_edn::parse(line)?);
        }
        Ok(out)
    }
}
