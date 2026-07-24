use std::process::Command;

fn main() {
    // Allow override via GIT_VERSION env var (used for Docker builds).
    // When present, skip git commands entirely — no .git needed in build context.
    if let Ok(v) = std::env::var("GIT_VERSION") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            println!("cargo:rustc-env=GIT_VERSION={}", v);
            return;
        }
    }

    let hash = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    let version = if dirty {
        format!("{}-dirty", hash)
    } else {
        hash
    };

    println!("cargo:rustc-env=GIT_VERSION={}", version);
}
