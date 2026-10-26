//! Fail closed at the CLI boundary: re-enrollment must always be explicit.
use std::process::Command;

#[test]
fn checkpoint_requires_explicit_enrollment_or_retained_evidence() {
    let args = [
        "audit-checkpoint",
        "--database",
        "/nonexistent/keyd/state.sqlite",
        "--instance-id",
        "12345678-1234-4234-8234-123456789abc",
    ];
    let missing = Command::new(env!("CARGO_BIN_EXE_anpio-key"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    let conflict = Command::new(env!("CARGO_BIN_EXE_anpio-key"))
        .args(args)
        .args(["--enroll", "--previous", "/nonexistent/retained.json"])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    let absent = Command::new(env!("CARGO_BIN_EXE_anpio-key"))
        .args(args)
        .args(["--previous", "/nonexistent/retained.json"])
        .output()
        .unwrap();
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
}
