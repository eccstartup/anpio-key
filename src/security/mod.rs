//! UID-separated signing boundary.
pub mod client;
pub mod config;
mod coordinator;
pub mod ecdh;
pub(crate) mod executor;
pub mod http;
pub mod json;
pub mod limits;
pub mod management_ui;
pub mod migration;
pub mod origin;
pub mod paths;
pub mod protocol;
pub mod proofs;
pub mod purpose;
pub(crate) mod se_session;
pub mod server;

use crate::error::{KeydError, Result};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// Build capability; a running service additionally requires explicit protected mode.
pub const fn protected_build_supported() -> bool {
    cfg!(target_os = "linux")
        && !cfg!(debug_assertions)
        && !cfg!(feature = "hardware-software")
        && !cfg!(feature = "seed-export")
}

pub fn require_boundary_platform() -> Result<()> {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        Ok(())
    } else {
        Err(KeydError::Misuse(
            "UID boundary is unsupported on this platform; development mode remains available"
                .into(),
        ))
    }
}

/// A whole-frame deadline, rather than a timeout restarted by each arriving byte.
pub struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
    nonblocking: bool,
}
impl DeadlineStream {
    pub(crate) fn clone_socket(&self) -> Result<UnixStream> {
        Ok(self.stream.try_clone()?)
    }
    pub fn new(stream: UnixStream, budget: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + budget,
            nonblocking: false,
        }
    }
    pub fn reset(&mut self, budget: Duration) {
        self.deadline = Instant::now() + budget;
    }
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "frame deadline expired")
            })
    }

    fn ready(&mut self, events: nix::libc::c_short) -> std::io::Result<()> {
        if !self.nonblocking {
            // poll readiness alone cannot bound a large send on Darwin AF_UNIX.
            // Configure the owned connection once; lease clones only peek and
            // never change these shared flags. Failure is propagated, not ignored.
            self.stream.set_nonblocking(true)?;
            self.nonblocking = true;
        }
        loop {
            let remaining = self.remaining()?;
            // Round up only the poll granularity, never reset the frame deadline.
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
            let timeout = millis.min(i32::MAX as u128) as i32;
            let mut fd = nix::libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            // Valid single pollfd for this owned socket; no data is consumed.
            let result = unsafe { nix::libc::poll(&mut fd, 1, timeout) };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            if fd.revents & nix::libc::POLLNVAL != 0 {
                return Err(std::io::Error::from_raw_os_error(nix::libc::EBADF));
            }
            self.remaining()?;
            // HUP/ERR must reach recv/send: a closed peer may have queued a full
            // response, or a partial frame that must produce EOF, not a retry.
            return Ok(());
        }
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(nix::libc::POLLIN)?;
            // Unlike SO_RCVTIMEO, recv can drain a closed peer. MSG_DONTWAIT is
            // additional to the owned connection's nonblocking mode.
            let count = unsafe {
                nix::libc::recv(
                    self.stream.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    nix::libc::MSG_DONTWAIT,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(std::io::Error::new(
                error.kind(),
                format!("socket read failed: {error}"),
            ));
        }
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            self.ready(nix::libc::POLLOUT)?;
            let count = unsafe {
                nix::libc::send(
                    self.stream.as_raw_fd(),
                    buffer.as_ptr().cast(),
                    buffer.len(),
                    nix::libc::MSG_DONTWAIT | nix::libc::MSG_NOSIGNAL,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(std::io::Error::new(
                error.kind(),
                format!("socket write failed: {error}"),
            ));
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush().map_err(|error| {
            std::io::Error::new(error.kind(), format!("socket flush failed: {error}"))
        })
    }
}

pub fn probe(path: &Path) -> Result<()> {
    println!("anpio-key security boundary probe");
    require_boundary_platform()?;
    let config = config::ServiceConfig::load(path)?;
    println!("config: root-owned, symlink-free, immutable to service and Agents");
    println!("service_uid: {}", config.service_uid);
    println!("admin_uids: {:?}", config.admin_uids);
    for principal in &config.principals {
        println!(
            "bootstrap principal (not live DB state): {} uid={} generation={} enabled={}",
            principal.principal_id, principal.uid, principal.generation, principal.enabled
        );
    }
    paths::state_directory(&config.state_dir, config.service_uid)?;
    println!("state: service-owned 0700");
    let admin = config.admin_uids.contains(&crate::daemon::self_uid());
    let (endpoint, group) = if admin {
        (&config.admin_socket, config.admin_gid)
    } else {
        (&config.sign_socket, config.agent_gid)
    };
    paths::socket(endpoint, config.service_uid, group)?;
    println!("caller socket: trusted group and 0750 directory, 0660 endpoint");
    let reply = client::Client::connect(path, admin)?.capabilities()?;
    println!(
        "server_identity: kernel UID verified; instance={}",
        reply.instance_id.unwrap_or_default()
    );
    println!("signing_available: {}", reply.signing_available);
    println!("protected_supported: {}", reply.protected_supported);
    if reply.protected_supported && config.protected_supported() {
        Ok(())
    } else {
        Err(KeydError::Misuse(
            "boundary checks passed; build or deployment is in preview/development mode".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_response_is_read_after_the_one_shot_server_closes() {
        for _ in 0..32 {
            let (client, mut server) = UnixStream::pair().unwrap();
            let reply = protocol::Reply::code("PUBLIC_TEST_REPLY");
            protocol::write(&mut server, &reply).unwrap();
            drop(server);
            let mut reader = DeadlineStream::new(client, Duration::from_secs(1));
            let received: protocol::Reply = protocol::read(&mut reader).unwrap();
            assert_eq!(received.code, "PUBLIC_TEST_REPLY");
        }
    }

    #[test]
    fn closed_peer_partial_frame_is_eof_and_never_retried() {
        let (client, mut server) = UnixStream::pair().unwrap();
        server.write_all(&[1, 2, 3]).unwrap();
        drop(server);
        let mut reader = DeadlineStream::new(client, Duration::from_secs(1));
        assert_eq!(
            reader.read_exact(&mut [0; 8]).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn blocked_writer_keeps_the_original_frame_deadline() {
        let (client, _server) = UnixStream::pair().unwrap();
        let mut writer = DeadlineStream::new(client, Duration::from_millis(30));
        let error = writer.write_all(&vec![1; 1024 * 1024]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn expired_deadline_rejects_even_queued_bytes_and_closed_peer_write_is_bounded() {
        let (client, mut server) = UnixStream::pair().unwrap();
        server.write_all(&[1]).unwrap();
        let mut reader = DeadlineStream::new(client, Duration::ZERO);
        assert_eq!(
            reader.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        let (client, server) = UnixStream::pair().unwrap();
        drop(server);
        let error = DeadlineStream::new(client, Duration::from_secs(1))
            .write_all(&[1])
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
    }

    #[test]
    fn trickling_bytes_cannot_extend_the_whole_frame_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..100 {
                if server.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let mut reader = DeadlineStream::new(client, Duration::from_millis(25));
        assert_eq!(
            reader.read_exact(&mut [0; 100]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(reader);
        sender.join().unwrap();
    }
}
