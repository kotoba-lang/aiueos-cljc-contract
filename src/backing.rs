//! The `computer-virtual` backing bridge (ADR-0007, increment 4) — feature
//! `computer-backing`. The in-process providers in [`crate::host`] gate and audit
//! every computer-use action; this bridge forwards each *already-gated* action to an
//! external host-side daemon (see `examples/computer/backing/`) over a newline-JSON
//! ABI, so the synthetic input drives a REAL virtual screen (headless Chromium / an
//! Xvfb container) while the operator's keyboard/mouse/display never go active.
//!
//! The daemon is **TCB** — it is the host-side code behind the providers, audited
//! like the Phase-7 device adapters. It is spawned only when the operator opts in via
//! `AIUEOS_COMPUTER_BACKING` (a command line, e.g. `node examples/computer/backing/
//! surface.mjs`), and lazily — on the first forwarded action — so non-computer runs
//! never start a browser. There is no `pointer-host`/`keyboard-host` provider, so the
//! bridge can only ever reach the *virtual* surface, never the host HID.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A live connection to a backing daemon: its child process and stdio pipes.
pub struct Backing {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// Minimal JSON string escaping for the one place we embed free text (`type`).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Pull the integer after `"id":` out of a reply line (the frame handle). 0 if absent.
fn parse_id(reply: &str) -> i64 {
    let Some(i) = reply.find("\"id\":") else {
        return 0;
    };
    reply[i + 5..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

impl Backing {
    /// Spawn the daemon named by `AIUEOS_COMPUTER_BACKING`, or `None` if unset/unspawnable.
    /// If `AIUEOS_COMPUTER_URL` is set, navigate there first (session setup).
    pub fn from_env() -> Option<Backing> {
        let cmdline = std::env::var("AIUEOS_COMPUTER_BACKING").ok()?;
        let mut b = Backing::spawn(&cmdline).ok()?;
        if let Ok(url) = std::env::var("AIUEOS_COMPUTER_URL") {
            let _ = b.request(&format!("{{\"op\":\"goto\",\"url\":{}}}", json_str(&url)));
        }
        Some(b)
    }

    /// Spawn `cmdline` (whitespace-split: `prog arg arg …`) with piped stdio.
    pub fn spawn(cmdline: &str) -> std::io::Result<Backing> {
        let mut parts = cmdline.split_whitespace();
        let prog = parts.next().unwrap_or_default();
        let args: Vec<&str> = parts.collect();
        let mut child = Command::new(prog)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Ok(Backing {
            child,
            stdin,
            stdout,
        })
    }

    /// Write one JSON command line and read one JSON reply line.
    fn request(&mut self, line: &str) -> std::io::Result<String> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        let mut reply = String::new();
        self.stdout.read_line(&mut reply)?;
        Ok(reply)
    }

    pub fn pointer_move(&mut self, x: i32, y: i32) {
        let _ = self.request(&format!("{{\"op\":\"pointer-move\",\"x\":{x},\"y\":{y}}}"));
    }
    pub fn pointer_click(&mut self, button: i32) {
        let _ = self.request(&format!("{{\"op\":\"pointer-click\",\"button\":{button}}}"));
    }
    pub fn key(&mut self, code: i32) {
        let _ = self.request(&format!("{{\"op\":\"key\",\"code\":{code}}}"));
    }
    pub fn type_text(&mut self, text: &str) {
        let _ = self.request(&format!("{{\"op\":\"type\",\"text\":{}}}", json_str(text)));
    }
    /// Capture a frame; returns the daemon's frame id (0 if it didn't report one).
    pub fn frame(&mut self) -> i64 {
        parse_id(&self.request("{\"op\":\"frame\"}").unwrap_or_default())
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        let _ = self.request("{\"op\":\"close\"}");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A mock daemon (echoes a frame-id reply per line) proves the bridge protocol —
    // spawn → request → parse — with no browser, so it runs under the feature in CI.
    #[test]
    fn bridge_speaks_the_abi_to_a_mock_daemon() {
        let mock = "/bin/sh ".to_string(); // placeholder; replaced below
        let _ = mock;
        // Write a tiny mock script to a temp file (no spaces in path).
        let dir = std::env::temp_dir();
        let path = dir.join("aiueos-mock-backing.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\nwhile IFS= read -r line; do echo '{\"ok\":true,\"id\":7}'; done\n",
        )
        .unwrap();
        let mut b = Backing::spawn(&format!("/bin/sh {}", path.display())).expect("spawn mock");
        b.pointer_move(10, 20);
        b.type_text("hi \"there\"\nx");
        assert_eq!(b.frame(), 7, "frame id parsed from the mock reply");
    }

    #[test]
    fn json_escape_and_id_parse() {
        assert_eq!(json_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        assert_eq!(parse_id("{\"ok\":true,\"id\":42,\"path\":\"x\"}"), 42);
        assert_eq!(parse_id("{\"ok\":true}"), 0);
    }
}
