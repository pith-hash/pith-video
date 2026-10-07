//! End-to-end checks of the `gen-reference` CLI: `verify` accepts the
//! committed `reference.json`, and `gen` reproduces those exact bytes into
//! a caller-supplied path.

use std::process::Command;

const COMMITTED: &str = include_str!("../reference.json");

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gen-reference"))
}

#[test]
fn verify_accepts_the_committed_reference() {
    let out = bin().arg("verify").output().expect("spawn gen-reference");
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn gen_reproduces_the_committed_bytes() {
    let dir = std::env::temp_dir().join(format!("pith-video-cli-gen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("reference.json");
    let out = bin()
        .arg("gen")
        .arg(&path)
        .output()
        .expect("spawn gen-reference");
    assert!(
        out.status.success(),
        "gen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read(&path).expect("generated file");
    assert_eq!(
        written,
        COMMITTED.as_bytes(),
        "gen must reproduce committed bytes"
    );
    std::fs::remove_file(&path).expect("cleanup");
    std::fs::remove_dir(&dir).expect("cleanup");
}

#[test]
fn verify_rejects_a_stale_reference() {
    let dir = std::env::temp_dir().join(format!("pith-video-cli-stale-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("reference.json");
    std::fs::write(&path, "{\n  \"format\": 0\n}\n").expect("stale file");
    let out = bin()
        .arg("verify")
        .arg(&path)
        .output()
        .expect("spawn gen-reference");
    assert!(!out.status.success(), "verify must fail on a stale file");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("stale"),
        "stderr must name the drift: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_file(&path).expect("cleanup");
    std::fs::remove_dir(&dir).expect("cleanup");
}

#[test]
fn verify_reports_an_unreadable_path() {
    let out = bin()
        .arg("verify")
        .arg("definitely-missing-reference.json")
        .output()
        .expect("spawn gen-reference");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot read"),
        "stderr must name the read failure: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_mode_prints_usage() {
    let out = bin().arg("generate").output().expect("spawn gen-reference");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usage:"),
        "stderr must carry the usage line: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
