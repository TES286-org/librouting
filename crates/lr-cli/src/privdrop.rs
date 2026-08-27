//! Privilege drop for `lr-daemon` (Unix).
//!
//! Production daemons bind their privileged sockets (BGP's port 179,
//! authenticated listeners) and then discard root. The reference order:
//!
//! 1. bind + arm auth (needs privilege)
//! 2. [`drop_privileges`] — clear supplementary groups, `setgid`, `setuid`
//! 3. run the I/O loop unprivileged
//!
//! Everything is declared with direct `extern "C"` symbols, matching the
//! project's no-libc-dependency convention (see `lr-osroute`).
//!
//! User/group arguments accept either names (resolved via `getpwnam` /
//! `getgrnam`) or numeric IDs. On non-Unix platforms the call fails with
//! a clear message instead of silently succeeding.

#[cfg(unix)]
mod imp {
    use std::ffi::CString;

    // POSIX `struct passwd` / `struct group` field layouts are stable on
    // every supported Unix target: pointer, pointer, uid, gid, then more
    // pointers (passwd) / pointer, pointer, gid, pointer (group).
    #[repr(C)]
    struct Passwd {
        pw_name: *const std::ffi::c_char,
        pw_passwd: *const std::ffi::c_char,
        pw_uid: u32,
        pw_gid: u32,
        pw_gecos: *const std::ffi::c_char,
        pw_dir: *const std::ffi::c_char,
        pw_shell: *const std::ffi::c_char,
    }

    #[repr(C)]
    struct Group {
        gr_name: *const std::ffi::c_char,
        gr_passwd: *const std::ffi::c_char,
        gr_gid: u32,
        gr_mem: *const *const std::ffi::c_char,
    }

    extern "C" {
        fn getuid() -> u32;
        fn geteuid() -> u32;
        fn getgid() -> u32;
        fn getegid() -> u32;
        fn getpwnam(name: *const std::ffi::c_char) -> *const Passwd;
        fn getpwuid(uid: u32) -> *const Passwd;
        fn getgrnam(name: *const std::ffi::c_char) -> *const Group;
        fn setgroups(ngroups: i32, groups: *const u32) -> i32;
        fn setgid(gid: u32) -> i32;
        fn setuid(uid: u32) -> i32;
    }

    /// Resolve a `--user` argument (name or numeric ID) to a uid.
    fn resolve_uid(spec: &str) -> Result<u32, String> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        let c = CString::new(spec).map_err(|_| format!("bad user name '{spec}'"))?;
        let pw = unsafe { getpwnam(c.as_ptr()) };
        if pw.is_null() {
            return Err(format!("unknown user '{spec}'"));
        }
        Ok(unsafe { (*pw).pw_uid })
    }

    /// Primary (login) group of `uid`, when the user database knows it.
    fn primary_gid(uid: u32) -> Option<u32> {
        let pw = unsafe { getpwuid(uid) };
        if pw.is_null() {
            return None;
        }
        Some(unsafe { (*pw).pw_gid })
    }

    /// Resolve a `--group` argument (name or numeric ID) to a gid.
    fn resolve_gid(spec: &str) -> Result<u32, String> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        let c = CString::new(spec).map_err(|_| format!("bad group name '{spec}'"))?;
        let gr = unsafe { getgrnam(c.as_ptr()) };
        if gr.is_null() {
            return Err(format!("unknown group '{spec}'"));
        }
        Ok(unsafe { (*gr).gr_gid })
    }

    /// Current identity, for the startup banner.
    pub fn identity() -> String {
        let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };
        if uid == euid && gid == egid {
            format!("uid={uid} gid={gid}")
        } else {
            format!("uid={uid} gid={gid} euid={euid} egid={egid}")
        }
    }

    /// Drop root privileges down to `user`/`group`.
    ///
    /// * When already unprivileged, the request is validated against the
    ///   current identity (dropping to yourself is a no-op; anything else
    ///   fails cleanly instead of pretending).
    /// * When privileged, supplementary groups are cleared and the
    ///   setgid/setuid pair is applied in that order, then verified —
    ///   a failed drop is fatal, never a warning.
    pub fn drop_privileges(user: &str, group: Option<&str>) -> Result<(), String> {
        let target_uid = resolve_uid(user)?;
        let target_gid = match group {
            Some(g) => resolve_gid(g)?,
            // Default: the target user's login group, like FRR/BIRD.
            None => primary_gid(target_uid).ok_or_else(|| {
                format!("cannot determine login group for uid {target_uid}; pass --group")
            })?,
        };

        let (uid, euid) = unsafe { (getuid(), geteuid()) };
        if euid != 0 {
            // Already unprivileged: only a self-no-op is legitimate.
            if target_uid == uid {
                return Ok(());
            }
            return Err(format!(
                "cannot switch to uid {target_uid} without root (running as uid {uid})"
            ));
        }

        // Root: supplementary groups first, then gid, then uid — each
        // irreversible, so a partial failure leaves the process strictly
        // less privileged than before.
        unsafe {
            if setgroups(0, std::ptr::null()) != 0 {
                return Err("setgroups failed".to_string());
            }
            if setgid(target_gid) != 0 {
                return Err(format!("setgid({target_gid}) failed"));
            }
            if setuid(target_uid) != 0 {
                return Err(format!("setuid({target_uid}) failed"));
            }
            // Verify the drop took effect (defence-in-depth: some
            // environments make setuid silently fail).
            if getuid() != target_uid || geteuid() != target_uid {
                return Err("privilege drop did not take effect".to_string());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn identity_reports_something() {
            assert!(identity().starts_with("uid="));
        }

        #[test]
        fn numeric_specs_resolve_without_lookup() {
            assert_eq!(resolve_uid("1234").unwrap(), 1234);
            assert_eq!(resolve_gid("5678").unwrap(), 5678);
        }

        #[test]
        fn unknown_names_fail_cleanly() {
            // A user name that cannot exist (invalid chars for names but
            // fine as a string) must fail, not panic.
            assert!(resolve_uid("no-such-user\x07").is_err());
        }

        #[test]
        fn drop_to_self_succeeds_unprivileged_or_root() {
            // Either we are root (real drop to the same uid works) or we
            // are already that user (validated no-op).
            let me = unsafe { getuid() }.to_string();
            drop_privileges(&me, None).expect("drop-to-self works");
        }

        #[test]
        fn drop_to_other_user_fails_when_unprivileged() {
            let (_uid, euid) = unsafe { (getuid(), geteuid()) };
            if euid == 0 {
                return; // running as root: switching users is legal
            }
            // uid 0 exists on every system; we are not allowed to become it.
            assert!(drop_privileges("0", None).is_err());
        }
    }
}

#[cfg(not(unix))]
mod imp {
    /// Windows and friends have no uid/gid model: refuse with a clear
    /// message rather than pretending the daemon dropped privileges.
    pub fn drop_privileges(_user: &str, _group: Option<&str>) -> Result<(), String> {
        Err("privilege drop is not supported on this platform".to_string())
    }

    pub fn identity() -> String {
        "no-uid-model".to_string()
    }
}

pub use imp::{drop_privileges, identity};
