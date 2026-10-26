//! One exact-key, non-renewable login lease. No listener, persistent secret, or
//! automatic grant recovery. Runtime support remains macOS preview only.
use crate::error::{KeydError, Result};
use crate::persistence::clock::{Clock, SystemClock, Time};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

pub(crate) const HEARTBEAT_SECONDS: u64 = 5;
pub(crate) const MAX_SECONDS: i64 = 900;

pub(crate) fn require_local_login() -> Result<()> {
    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    {
        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            fn SessionGetInfo(session: u32, actual: *mut u32, attributes: *mut u32) -> i32;
        }
        let mut session = 0;
        let mut attributes = 0;
        // callerSecuritySession (-1) requests this process's actual audit session.
        if unsafe { SessionGetInfo(u32::MAX, &mut session, &mut attributes) } == 0
            && login_active(crate::daemon::peer::self_uid(), session)
        {
            return Ok(());
        }
    }
    Err(KeydError::Misuse("SE_LOGIN_SESSION_REQUIRED".into()))
}

pub(crate) struct Lease {
    pub id: String,
    pub actor: u32,
    pub audit_session: u32,
    pub socket: UnixStream,
    pub deadline: Time,
    pub last: Time,
    pub sequence: u64,
    pub console_epoch: u64,
}

pub(crate) fn now() -> Result<Time> {
    let time = SystemClock.now()?;
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        unsafe extern "C" {
            fn mach_timebase_info(info: *mut Timebase) -> i32;
            fn mach_continuous_time() -> u64;
        }
        let mut base = Timebase { numer: 0, denom: 0 };
        // Continuous time includes suspend, unlike std::time::Instant on Darwin.
        if unsafe { mach_timebase_info(&mut base) } != 0 || base.denom == 0 {
            return Err(KeydError::Locked);
        }
        let millis = u128::from(unsafe { mach_continuous_time() }) * u128::from(base.numer)
            / u128::from(base.denom)
            / 1_000_000;
        Ok(Time {
            wall: time.wall,
            monotonic_ms: i64::try_from(millis).map_err(|_| KeydError::Locked)?,
        })
    }
    #[cfg(not(target_os = "macos"))]
    Ok(time)
}

impl Lease {
    pub fn new(
        id: String,
        actor: u32,
        audit_session: u32,
        socket: UnixStream,
        now: Time,
    ) -> Result<Self> {
        Ok(Self {
            id,
            actor,
            audit_session,
            socket,
            last: now,
            sequence: 0,
            console_epoch: console_epoch(),
            deadline: Time {
                wall: now.wall.checked_add(MAX_SECONDS).ok_or(KeydError::Locked)?,
                monotonic_ms: now
                    .monotonic_ms
                    .checked_add(MAX_SECONDS * 1000)
                    .ok_or(KeydError::Locked)?,
            },
        })
    }

    pub fn fresh(&self, now: Time) -> bool {
        now.wall >= self.last.wall
            && now.monotonic_ms >= self.last.monotonic_ms
            && now.wall < self.deadline.wall
            && now.monotonic_ms < self.deadline.monotonic_ms
            && now.wall - self.last.wall < HEARTBEAT_SECONDS as i64
            && now.monotonic_ms - self.last.monotonic_ms < HEARTBEAT_SECONDS as i64 * 1000
    }

    pub fn heartbeat(&mut self, id: &str, sequence: u64, now: Time) -> Result<()> {
        if !self.fresh(now) || id != self.id || self.sequence.checked_add(1) != Some(sequence) {
            return Err(KeydError::Locked);
        }
        self.last = now;
        self.sequence = sequence;
        Ok(())
    }

    pub fn live(&self) -> bool {
        self.live_at(
            now().ok(),
            login_active(self.actor, self.audit_session),
            console_epoch(),
            observer_healthy(),
        )
    }

    fn live_at(&self, now: Option<Time>, login: bool, epoch: u64, healthy: bool) -> bool {
        if !now.map(|now| self.fresh(now)).unwrap_or(false)
            || self.console_epoch != epoch
            || !healthy
            || !login
        {
            return false;
        }
        let mut byte = 0u8;
        // Peek never consumes a heartbeat or changes the shared socket flags.
        let result = unsafe {
            nix::libc::recv(
                self.socket.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                nix::libc::MSG_PEEK | nix::libc::MSG_DONTWAIT,
            )
        };
        result > 0
            || (result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock)
    }
}

pub(crate) fn peer_session(stream: &UnixStream, actor: u32) -> Result<u32> {
    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    {
        if !console_observer::ensure() {
            return Err(KeydError::Locked);
        }
        #[link(name = "bsm")]
        unsafe extern "C" {
            fn audit_token_to_asid(token: nix::sys::socket::audit_token_t) -> u32;
        }
        let token = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerToken)
            .map_err(|_| KeydError::Locked)?;
        let session = unsafe { audit_token_to_asid(token) };
        if login_active(actor, session) {
            return Ok(session);
        }
    }
    let _ = (stream, actor);
    Err(KeydError::Misuse("SE_LOGIN_SESSION_REQUIRED".into()))
}

pub(crate) fn console_epoch() -> u64 {
    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    {
        console_observer::EPOCH.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(all(target_os = "macos", feature = "hardware-se")))]
    {
        0
    }
}

fn observer_healthy() -> bool {
    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    {
        console_observer::healthy()
    }
    #[cfg(not(all(target_os = "macos", feature = "hardware-se")))]
    {
        false
    }
}

#[cfg(all(target_os = "macos", feature = "hardware-se"))]
mod console_observer {
    use super::*;
    use core_foundation::{array::CFArray, base::TCFType, string::CFString};
    use core_foundation_sys::{
        array::CFArrayRef,
        base::{CFAllocatorRef, CFRelease},
        runloop::{
            kCFRunLoopDefaultMode, CFRunLoopAddSource, CFRunLoopGetCurrent, CFRunLoopRunInMode,
            CFRunLoopSourceRef,
        },
        string::CFStringRef,
    };
    use std::ffi::c_void;
    use std::sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        OnceLock,
    };
    pub(super) static EPOCH: AtomicU64 = AtomicU64::new(1);
    static HEALTHY: AtomicBool = AtomicBool::new(false);
    static TICK: AtomicI64 = AtomicI64::new(0);
    type Store = *const c_void;
    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCreate(
            allocator: CFAllocatorRef,
            name: CFStringRef,
            callback: unsafe extern "C" fn(Store, CFArrayRef, *mut c_void),
            context: *mut c_void,
        ) -> Store;
        fn SCDynamicStoreKeyCreateConsoleUser(allocator: CFAllocatorRef) -> CFStringRef;
        fn SCDynamicStoreSetNotificationKeys(
            store: Store,
            keys: CFArrayRef,
            patterns: CFArrayRef,
        ) -> u8;
        fn SCDynamicStoreCreateRunLoopSource(
            allocator: CFAllocatorRef,
            store: Store,
            order: isize,
        ) -> CFRunLoopSourceRef;
    }
    unsafe extern "C" fn changed(_: Store, _: CFArrayRef, _: *mut c_void) {
        if EPOCH
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |epoch| {
                epoch.checked_add(1)
            })
            .is_err()
        {
            HEALTHY.store(false, Ordering::SeqCst);
        }
    }
    pub(super) fn healthy() -> bool {
        let elapsed = now()
            .map(|now| now.monotonic_ms - TICK.load(Ordering::SeqCst))
            .unwrap_or(i64::MAX);
        HEALTHY.load(Ordering::SeqCst) && (0..2000).contains(&elapsed)
    }
    pub(super) fn ensure() -> bool {
        static STARTED: OnceLock<bool> = OnceLock::new();
        *STARTED.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            if std::thread::Builder::new()
                .name("se-console-watch".into())
                .spawn(move || {
                    let name = CFString::new("org.anpio-key.se-console-watch");
                    // No context pointer escapes; the callback touches only atomics.
                    let store = unsafe {
                        SCDynamicStoreCreate(
                            std::ptr::null(),
                            name.as_concrete_TypeRef(),
                            changed,
                            std::ptr::null_mut(),
                        )
                    };
                    if store.is_null() {
                        let _ = tx.send(false);
                        return;
                    }
                    let key = unsafe { SCDynamicStoreKeyCreateConsoleUser(std::ptr::null()) };
                    if key.is_null() {
                        unsafe { CFRelease(store) };
                        let _ = tx.send(false);
                        return;
                    }
                    let key = unsafe { CFString::wrap_under_create_rule(key) };
                    let keys = CFArray::from_CFTypes(&[key]);
                    if unsafe {
                        SCDynamicStoreSetNotificationKeys(
                            store,
                            keys.as_concrete_TypeRef(),
                            std::ptr::null(),
                        )
                    } == 0
                    {
                        unsafe { CFRelease(store) };
                        let _ = tx.send(false);
                        return;
                    }
                    let source =
                        unsafe { SCDynamicStoreCreateRunLoopSource(std::ptr::null(), store, 0) };
                    if source.is_null() {
                        unsafe { CFRelease(store) };
                        let _ = tx.send(false);
                        return;
                    }
                    unsafe {
                        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode)
                    };
                    TICK.store(
                        now().map(|now| now.monotonic_ms).unwrap_or(0),
                        Ordering::SeqCst,
                    );
                    HEALTHY.store(true, Ordering::SeqCst);
                    let _ = tx.send(true);
                    loop {
                        let result =
                            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, false as u8) };
                        if result == 1 || result == 2 {
                            break;
                        }
                        match now() {
                            Ok(now) => {
                                TICK.store(now.monotonic_ms, Ordering::SeqCst);
                            }
                            Err(_) => break,
                        }
                    }
                    HEALTHY.store(false, Ordering::SeqCst);
                    unsafe {
                        CFRelease(source.cast());
                        CFRelease(store);
                    }
                })
                .is_err()
            {
                return false;
            }
            rx.recv_timeout(std::time::Duration::from_secs(3))
                .unwrap_or(false)
        }) && healthy()
    }
}

pub(crate) fn login_active(actor: u32, session: u32) -> bool {
    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    {
        use core_foundation_sys::base::CFRelease;
        use core_foundation_sys::string::CFStringRef;
        #[link(name = "SystemConfiguration", kind = "framework")]
        unsafe extern "C" {
            fn SCDynamicStoreCopyConsoleUser(
                store: *const std::ffi::c_void,
                uid: *mut u32,
                gid: *mut u32,
            ) -> CFStringRef;
        }
        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            fn SessionGetInfo(session: u32, actual: *mut u32, attributes: *mut u32) -> i32;
        }
        let mut uid = u32::MAX;
        let mut gid = u32::MAX;
        let name = unsafe { SCDynamicStoreCopyConsoleUser(std::ptr::null(), &mut uid, &mut gid) };
        if name.is_null() {
            return false;
        }
        unsafe { CFRelease(name.cast()) };
        let mut actual = 0;
        let mut attributes = 0;
        // Only a non-root, local graphical audit session belonging to the
        // currently active console UID is eligible. UID is kernel-authenticated.
        actor != 0
            && uid == actor
            && session != 0
            && session != u32::MAX
            && unsafe { SessionGetInfo(session, &mut actual, &mut attributes) } == 0
            && actual == session
            && attributes & 0x0010 != 0
            && attributes & 0x1001 == 0
    }
    #[cfg(not(all(target_os = "macos", feature = "hardware-se")))]
    {
        let _ = (actor, session);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Lease, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (
            Lease::new(
                "exact-session".into(),
                501,
                123,
                a,
                Time {
                    wall: 100,
                    monotonic_ms: 1000,
                },
            )
            .unwrap(),
            b,
        )
    }
    #[test]
    fn lease_cannot_extend_deadline_or_resume_after_gap_rollback_or_expiry() {
        let (mut lease, _peer) = fixture();
        let original = lease.deadline;
        for second in 1..MAX_SECONDS {
            lease
                .heartbeat(
                    "exact-session",
                    second as u64,
                    Time {
                        wall: 100 + second,
                        monotonic_ms: 1000 + second * 1000,
                    },
                )
                .unwrap();
        }
        assert_eq!(lease.deadline.wall, original.wall);
        assert!(!lease.fresh(Time {
            wall: original.wall,
            monotonic_ms: original.monotonic_ms
        }));
        let (lease, _peer) = fixture();
        for now in [
            Time {
                wall: 99,
                monotonic_ms: 1001,
            },
            Time {
                wall: 101,
                monotonic_ms: 999,
            },
            Time {
                wall: 105,
                monotonic_ms: 2000,
            },
            Time {
                wall: 101,
                monotonic_ms: 6000,
            },
        ] {
            assert!(!lease.fresh(now));
        }
    }
    #[test]
    fn heartbeat_is_session_bound_and_strictly_ordered() {
        let (mut lease, _peer) = fixture();
        let now = Time {
            wall: 101,
            monotonic_ms: 2000,
        };
        assert!(lease.heartbeat("other-session", 1, now).is_err());
        assert!(lease.heartbeat("exact-session", 2, now).is_err());
        lease.heartbeat("exact-session", 1, now).unwrap();
        assert!(lease.heartbeat("exact-session", 1, now).is_err());
    }

    #[test]
    fn disconnect_logout_relogin_and_observer_failure_end_the_old_lease() {
        let (lease, peer) = fixture();
        let time = Some(Time {
            wall: 101,
            monotonic_ms: 2000,
        });
        assert!(lease.live_at(time, true, lease.console_epoch, true));
        assert!(!lease.live_at(time, false, lease.console_epoch, true));
        assert!(!lease.live_at(time, true, lease.console_epoch + 1, true));
        assert!(!lease.live_at(time, true, lease.console_epoch, false));
        assert!(!lease.live_at(None, true, lease.console_epoch, true));
        drop(peer);
        assert!(!lease.live_at(time, true, lease.console_epoch, true));
    }

    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    #[test]
    #[ignore = "explicit real local-console check; not for headless CI"]
    fn local_console_observer_and_kernel_audit_session_are_available() {
        assert!(
            console_observer::ensure(),
            "console observation must initialize without fallback"
        );
        let (socket, _peer) = UnixStream::pair().unwrap();
        let actor = crate::daemon::peer::self_uid();
        let session = peer_session(&socket, actor)
            .expect("current primary console user's graphical audit session");
        let lease = Lease::new(
            "explicit-console-test".into(),
            actor,
            session,
            socket,
            now().unwrap(),
        )
        .unwrap();
        assert!(
            lease.live(),
            "OS observation and kernel session must actually be usable"
        );
    }
}
