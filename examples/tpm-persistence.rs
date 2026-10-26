//! Test-only cross-process TPM persistence probe.
//!
//! This is not a release command. It exists so the U3 acceptance can make the
//! claim that actually matters with two separate processes:
//!
//! ```text
//! tpm-persistence create STATE acceptance-<uuid>   # process A
//! tpm-persistence open STATE                       # process B
//! tpm-persistence delete STATE                     # process C
//! tpm-persistence probe                            # JSON RootProbe
//! ```
//!
//! `create` writes the envelope-side locator (the persistent handle) and a
//! SHA-256 of the derived HS. No key material is written: the HS digest is
//! one-way and exists only so `open` can prove it re-derived the same value
//! from the same TPM object in another process.
//!
//! Names are constrained to `acceptance-*` and the handle must be the one
//! derived from that name, so this probe cannot touch a real envelope's object
//! even if its state file is tampered with.

#[cfg(not(all(
    target_os = "linux",
    feature = "hardware-tpm",
    feature = "tpm-acceptance"
)))]
fn main() {
    eprintln!("tpm-persistence requires Linux with --features hardware-tpm,tpm-acceptance");
    std::process::exit(2);
}

#[cfg(all(
    target_os = "linux",
    feature = "hardware-tpm",
    feature = "tpm-acceptance"
))]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("tpm-persistence: {error}");
        std::process::exit(1);
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "hardware-tpm",
    feature = "tpm-acceptance"
))]
mod linux {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use anpio_key::keystore::hardware::tpm::{
        acceptance_create, acceptance_delete, acceptance_open, probe as probe_tpm,
    };
    use anpio_key::keystore::record::HardwareRoot;
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const MAX_STATE: u64 = 64 * 1024;
    const STATE_SCHEMA: u8 = 1;

    #[derive(Debug, Serialize, Deserialize)]
    struct State {
        schema: u8,
        tag_hint: String,
        root: HardwareRoot,
        ciphertext_b64: String,
        hs_sha256: String,
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            Some("create") => {
                let state = path(args.next(), "STATE")?;
                let tag = args.next().ok_or("create requires TAG")?;
                no_more(args)?;
                create(&state, &tag)
            }
            Some("open") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                open(&state)
            }
            Some("delete") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                delete(&state)
            }
            Some("label") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                let state = read_state(&state)?;
                println!("{}", state.tag_hint);
                Ok(())
            }
            Some("probe") => {
                no_more(args)?;
                let probe = probe_tpm();
                println!(
                    "{}",
                    serde_json::json!({
                        "kind": probe.kind,
                        "compiled": probe.compiled,
                        "usable": probe.usable,
                        "detail": probe.detail,
                        "remedy": probe.remedy,
                    })
                );
                Ok(())
            }
            other => Err(format!(
                "expected create STATE TAG, open STATE, delete STATE, label STATE or probe; got \
                 {other:?}"
            )),
        }
    }

    fn path(value: Option<String>, name: &str) -> Result<PathBuf, String> {
        value
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing {name}"))
    }

    fn no_more(mut args: impl Iterator<Item = String>) -> Result<(), String> {
        match args.next() {
            Some(extra) => Err(format!("unexpected argument {extra:?}")),
            None => Ok(()),
        }
    }

    fn create(path: &Path, tag: &str) -> Result<(), String> {
        let sealed = acceptance_create(tag).map_err(|error| error.to_string())?;
        // A TPM sealed object stays on the chip, so the envelope carries no
        // ciphertext; the digest is still what `open` checks.
        let digest = sealed.hs.expose(|bytes| hex(&Sha256::digest(bytes)));
        let state = State {
            schema: STATE_SCHEMA,
            tag_hint: tag.to_string(),
            root: sealed.root,
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&sealed.ciphertext),
            hs_sha256: digest,
        };
        if let Err(error) = write_state(path, &state) {
            // The object is already on the TPM. Do not leave an orphan behind
            // just because the public state file could not be written.
            let _ = acceptance_delete(tag);
            return Err(error);
        }
        println!("CREATED {tag}");
        Ok(())
    }

    fn open(path: &Path) -> Result<(), String> {
        let state = read_state(path)?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&state.ciphertext_b64)
            .map_err(|error| format!("state ciphertext is not base64: {error}"))?;
        let hs = acceptance_open(&state.tag_hint, &state.root, &ciphertext)
            .map_err(|error| error.to_string())?;
        let actual = hs.expose(|bytes| hex(&Sha256::digest(bytes)));
        if actual != state.hs_sha256 {
            return Err(format!(
                "the TPM reopened handle {:?}, but the derived HS differs from the one created \
                 by the other process",
                state.tag_hint
            ));
        }
        println!("PASS {}", state.tag_hint);
        Ok(())
    }

    fn delete(path: &Path) -> Result<(), String> {
        let state = read_state(path)?;
        acceptance_delete(&state.tag_hint).map_err(|error| error.to_string())?;
        println!("DELETED {}", state.tag_hint);
        Ok(())
    }

    fn write_state(path: &Path, state: &State) -> Result<(), String> {
        let body = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        file.write_all(&body)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write {}: {error}", path.display()))
    }

    fn read_state(path: &Path) -> Result<State, String> {
        let file =
            File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        let mut body = Vec::new();
        file.take(MAX_STATE + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if body.len() as u64 > MAX_STATE {
            return Err(format!("{} is too large", path.display()));
        }
        let state: State = serde_json::from_slice(&body)
            .map_err(|error| format!("{} is not a state file: {error}", path.display()))?;
        if state.schema != STATE_SCHEMA {
            return Err(format!(
                "{} has schema {}, expected {STATE_SCHEMA}",
                path.display(),
                state.schema
            ));
        }
        if !state.tag_hint.starts_with("acceptance-") {
            return Err("acceptance state does not name an acceptance tag".into());
        }
        let HardwareRoot::Tpm { handle } = &state.root else {
            return Err("acceptance state does not name a TPM object".into());
        };
        if !(0x8100_0000..=0x817F_FFFF).contains(handle) {
            return Err(format!(
                "{handle:#010x} is outside the owner persistent range"
            ));
        }
        Ok(state)
    }

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}
