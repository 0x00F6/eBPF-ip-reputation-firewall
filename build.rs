use std::path::Path;
use std::process::Command;

/// Attempt to obtain the latest Git tag
fn get_git_tag() -> Option<String> {
    // 1. Check environment variable override (e.g. from CI/CD or Docker build args)
    if let Ok(val) = std::env::var("GIT_TAG") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // 2. Try exact tag match on HEAD: git describe --tags --exact-match
    if let Ok(output) = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .output()
    {
        if output.status.success() {
            let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !tag.is_empty() {
                return Some(tag);
            }
        }
    }

    // 3. Try most recent reachable tag: git describe --tags --abbrev=0
    if let Ok(output) = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0"])
        .output()
    {
        if output.status.success() {
            let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !tag.is_empty() {
                return Some(tag);
            }
        }
    }

    // 4. Filesystem inspection fallback from .git/refs/tags
    if let Ok(entries) = std::fs::read_dir(".git/refs/tags") {
        let mut tags: Vec<String> = entries
            .filter_map(|e| {
                e.ok()
                    .map(|entry| entry.file_name().to_string_lossy().to_string())
            })
            .collect();
        tags.sort();
        if let Some(last_tag) = tags.pop() {
            if !last_tag.trim().is_empty() {
                return Some(last_tag);
            }
        }
    }

    None
}

/// Pure filesystem commit extraction from .git/HEAD and .git/refs
fn get_git_commit_from_fs() -> Option<String> {
    let head_content = std::fs::read_to_string(".git/HEAD").ok()?;
    let head = head_content.trim();
    if let Some(ref_path) = head.strip_prefix("ref: ") {
        let full_ref_path = format!(".git/{}", ref_path.trim());
        if let Ok(hash) = std::fs::read_to_string(&full_ref_path) {
            let h = hash.trim();
            if h.len() >= 7 {
                return Some(h[..7].to_string());
            }
        }
        // Fallback to packed-refs
        if let Ok(packed) = std::fs::read_to_string(".git/packed-refs") {
            for line in packed.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 && parts[1] == ref_path.trim() {
                    let h = parts[0];
                    if h.len() >= 7 {
                        return Some(h[..7].to_string());
                    }
                }
            }
        }
    } else if head.len() >= 7 {
        return Some(head[..7].to_string());
    }
    None
}

/// Attempt to obtain the short commit hash
fn get_git_commit() -> Option<String> {
    // 1. Check environment variable override
    if let Ok(val) = std::env::var("GIT_COMMIT") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // 2. Try git rev-parse --short HEAD
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !commit.is_empty() {
                return Some(commit);
            }
        }
    }

    // 3. Try git log -1 --format=%h
    if let Ok(output) = Command::new("git")
        .args(["log", "-1", "--format=%h"])
        .output()
    {
        if output.status.success() {
            let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !commit.is_empty() {
                return Some(commit);
            }
        }
    }

    // 4. Pure filesystem fallback (safe across Docker container boundaries)
    if let Some(fs_commit) = get_git_commit_from_fs() {
        return Some(fs_commit);
    }

    None
}

fn main() {
    // Rerun build.rs if git references or env changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-env-changed=GIT_TAG");
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=GIT_REF");

    // Check direct GIT_REF override first
    let git_ref = if let Ok(val) = std::env::var("GIT_REF") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            Some(trimmed.to_string())
        } else {
            None
        }
    } else {
        None
    };

    let resolved_ref = git_ref
        .or_else(get_git_tag)
        .or_else(get_git_commit)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=FIREWALL_GIT_REF={}", resolved_ref);

    if Path::new(".git/HEAD").exists() {
        println!("cargo:rustc-rerun-if-changed=.git/HEAD");
    }
}
