//! TCP session authentication for routing protocols — RFC 2385 (TCP MD5)
//! and RFC 5925 (TCP Authentication Option).
//!
//! BGP sessions ride directly on TCP, so per-packet authentication is a
//! *transport* concern, not a protocol one: the kernel signs and verifies
//! every segment (including SYN) and the library only has to install the
//! right keys on the right sockets. That is why this module lives in the
//! system-integration crate instead of `lr-bgp` — the protocol engine stays
//! OS-independent and simply never sees unauthenticated traffic.
//!
//! ## Model
//!
//! - [`TcpAuth::Md5`] — a single shared secret (RFC 2385). The kernel MACs
//!   every segment with HMAC-MD5 over the pseudo-header. Universally
//!   supported by BIRD, FRR and every Linux since 2.6.20 (wildcard listener
//!   keys need `TCP_MD5SIG_EXT`, i.e. kernel >= 4.14).
//! - [`TcpAuth::Ao`] — a set of Master Key Tuples (RFC 5925 §3.1): SendID,
//!   RecvID, key bytes, MAC algorithm and MAC length. The kernel performs
//!   traffic-key derivation (RFC 5926 KDFs), SNE maintenance and RNext key
//!   negotiation. Requires Linux >= 6.7 (`CONFIG_TCP_AO`).
//!
//! ## Sockets and roles
//!
//! - **Listener** ([`arm_listener`]): keys are installed with a wildcard
//!   peer address (`prefix = 0`), so every inbound connection must
//!   authenticate. The kernel copies the key set onto accepted sockets.
//! - **Connector** ([`connect_auth`]): the socket is created by hand so the
//!   keys can be installed *before* `connect(2)` — the SYN itself carries
//!   the MAC. A non-blocking connect plus `poll(2)` preserves the
//!   connect-with-timeout behaviour embedders expect.
//!
//! ## Platform support
//!
//! | Platform | MD5 | TCP-AO |
//! |----------|-----|--------|
//! | Linux    | yes | yes (>= 6.7) |
//! | BSD/macOS/Windows | no ([`TcpAuthError::Unsupported`]) |
//!
//! The BSDs do ship a `TCP_MD5SIG` option, but with a struct layout that
//! differs from Linux (and no TCP-AO); supporting it means per-OS key
//! structures, which is left as documented future work. Embedders on those
//! systems implement their own socket arming and keep using [`TcpAuth`]
//! as the configuration model.
//!
//! ## Example
//!
//! ```no_run
//! use std::net::TcpListener;
//! use lr_osroute::tcp_auth::{TcpAuth, arm_listener, connect_auth};
//! use std::time::Duration;
//!
//! let auth = TcpAuth::md5("shared-secret").unwrap();
//! let listener = TcpListener::bind("127.0.0.1:1179").unwrap();
//! arm_listener(&listener, &auth).unwrap();
//! let stream = connect_auth("127.0.0.1:1179".parse().unwrap(), &auth,
//!                          Duration::from_secs(5)).unwrap();
//! # let _ = stream;
//! ```

use std::fmt;

/// Maximum key length accepted by both `TCP_MD5SIG` and `TCP_AO_ADD_KEY`.
pub const MAX_KEY_LEN: usize = 80;

// ---------------------------------------------------------------------------
// Configuration model (platform-independent)
// ---------------------------------------------------------------------------

/// MAC algorithm for a TCP-AO Master Key Tuple (RFC 5925 §2 / RFC 5926).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpAoAlgorithm {
    /// HMAC-SHA1-96 — the mandatory-to-implement algorithm (default).
    #[default]
    HmacSha1,
    /// AES-128-CMAC — the second standard algorithm.
    CmacAes128,
}

impl TcpAoAlgorithm {
    /// Kernel crypto-API name for `struct tcp_ao_add.alg_name`.
    pub fn kernel_name(self) -> &'static str {
        match self {
            TcpAoAlgorithm::HmacSha1 => "hmac(sha1)",
            TcpAoAlgorithm::CmacAes128 => "cmac(aes)",
        }
    }

    /// Maximum MAC length (digest size) the algorithm can produce.
    pub fn digest_size(self) -> u8 {
        match self {
            TcpAoAlgorithm::HmacSha1 => 20,
            TcpAoAlgorithm::CmacAes128 => 16,
        }
    }

    /// Default MAC length (RFC 5925 §5.1 truncated MAC conventions).
    pub fn default_mac_len(self) -> u8 {
        12
    }

    /// Parses a user-facing algorithm name (daemon CLI / TOML).
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "hmac-sha1" | "hmac(sha1)" | "hmac_sha1" => Some(TcpAoAlgorithm::HmacSha1),
            "cmac-aes" | "cmac(aes)" | "aes-128-cmac" | "cmac_aes" => {
                Some(TcpAoAlgorithm::CmacAes128)
            }
            _ => None,
        }
    }
}

/// One TCP-AO Master Key Tuple (RFC 5925 §3.1) reduced to the fields the
/// kernel socket API consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAoKey {
    /// KeyID placed in the TCP-AO option of outgoing segments (`sndid`).
    pub send_id: u8,
    /// KeyID that must appear in the peer's segments to select this MKT
    /// (`rcvid`).
    pub recv_id: u8,
    /// Raw key bytes (1..=[`MAX_KEY_LEN`]).
    pub key: Vec<u8>,
}

impl TcpAoKey {
    /// Creates a symmetric MKT (`send_id == recv_id`, the common case).
    pub fn symmetric(id: u8, key: impl Into<Vec<u8>>) -> Result<Self, TcpAuthError> {
        Self::new(id, id, key)
    }

    /// Creates an MKT with distinct send/receive KeyIDs.
    pub fn new(send_id: u8, recv_id: u8, key: impl Into<Vec<u8>>) -> Result<Self, TcpAuthError> {
        let key = key.into();
        if key.is_empty() {
            return Err(TcpAuthError::EmptyKey);
        }
        if key.len() > MAX_KEY_LEN {
            return Err(TcpAuthError::KeyTooLong(key.len()));
        }
        Ok(Self {
            send_id,
            recv_id,
            key,
        })
    }
}

/// Transport authentication configuration for one BGP session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TcpAuth {
    /// No authentication (plain TCP).
    #[default]
    None,
    /// RFC 2385 TCP MD5 with one shared secret.
    Md5 { key: Vec<u8> },
    /// RFC 5925 TCP-AO with a set of Master Key Tuples.
    Ao {
        /// Master Key Tuples; the first entry is the Current/RNext key.
        keys: Vec<TcpAoKey>,
        algorithm: TcpAoAlgorithm,
        /// MAC length in bytes; RFC 5925 truncated MAC (0 = algorithm
        /// default, 12 for hmac(sha1)).
        mac_len: u8,
        /// Reject inbound connections that carry no TCP-AO option
        /// (`TCP_AO_INFO.ao_required`).
        ao_required: bool,
    },
}

impl TcpAuth {
    /// RFC 2385 configuration with one shared secret.
    pub fn md5(key: impl Into<Vec<u8>>) -> Result<Self, TcpAuthError> {
        let key = key.into();
        if key.is_empty() {
            return Err(TcpAuthError::EmptyKey);
        }
        if key.len() > MAX_KEY_LEN {
            return Err(TcpAuthError::KeyTooLong(key.len()));
        }
        Ok(TcpAuth::Md5 { key })
    }

    /// RFC 5925 configuration. `mac_len == 0` selects the algorithm
    /// default. The first key becomes Current/RNext on the socket.
    pub fn tcp_ao(
        keys: Vec<TcpAoKey>,
        algorithm: TcpAoAlgorithm,
        mac_len: u8,
    ) -> Result<Self, TcpAuthError> {
        if keys.is_empty() {
            return Err(TcpAuthError::NoAoKeys);
        }
        let mac_len = if mac_len == 0 {
            algorithm.default_mac_len()
        } else {
            if mac_len > algorithm.digest_size() {
                return Err(TcpAuthError::BadMacLen {
                    requested: mac_len,
                    max: algorithm.digest_size(),
                });
            }
            mac_len
        };
        Ok(TcpAuth::Ao {
            keys,
            algorithm,
            mac_len,
            ao_required: true,
        })
    }

    /// True when no authentication is configured.
    pub fn is_none(&self) -> bool {
        matches!(self, TcpAuth::None)
    }

    /// One-line description for logs and banners. Never contains key
    /// material — only lengths and identifiers.
    pub fn describe(&self) -> String {
        match self {
            TcpAuth::None => "none".to_string(),
            TcpAuth::Md5 { key } => format!("md5 ({}-byte key)", key.len()),
            TcpAuth::Ao {
                keys,
                algorithm,
                mac_len,
                ..
            } => format!(
                "tcp-ao {} ({} key(s), maclen {})",
                algorithm.kernel_name(),
                keys.len(),
                mac_len
            ),
        }
    }
}

/// Errors from configuring or applying TCP authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpAuthError {
    /// Key material is empty.
    EmptyKey,
    /// Key material exceeds [`MAX_KEY_LEN`] bytes.
    KeyTooLong(usize),
    /// TCP-AO configured without any Master Key Tuple.
    NoAoKeys,
    /// Requested MAC length exceeds the algorithm digest size.
    BadMacLen { requested: u8, max: u8 },
    /// The platform has no TCP auth socket-option support.
    Unsupported(&'static str),
    /// The connect did not complete within the timeout.
    ConnectTimeout,
    /// A socket operation failed; `errno` is the OS error code.
    Os { context: &'static str, errno: i32 },
}

impl TcpAuthError {
    /// True when the running kernel lacks the requested socket option —
    /// e.g. TCP-AO on kernels older than Linux 6.7 (`ENOPROTOOPT`).
    /// Callers may degrade gracefully (skip) instead of failing hard.
    pub fn is_kernel_unsupported(&self) -> bool {
        matches!(self, TcpAuthError::Os { errno, .. } if *errno == ENOPROTOOPT)
    }
}

impl fmt::Display for TcpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpAuthError::EmptyKey => write!(f, "authentication key is empty"),
            TcpAuthError::KeyTooLong(n) => {
                write!(f, "authentication key is {n} bytes (max {MAX_KEY_LEN})")
            }
            TcpAuthError::NoAoKeys => write!(f, "tcp-ao needs at least one key"),
            TcpAuthError::BadMacLen { requested, max } => {
                write!(f, "mac length {requested} exceeds digest size {max}")
            }
            TcpAuthError::Unsupported(why) => write!(f, "unsupported on this platform: {why}"),
            TcpAuthError::ConnectTimeout => write!(f, "connect timed out"),
            TcpAuthError::Os { context, errno } => {
                let e = std::io::Error::from_raw_os_error(*errno);
                write!(f, "{context}: {e}")
            }
        }
    }
}

impl std::error::Error for TcpAuthError {}

/// Linux `ENOPROTOOPT` (the errno returned for unknown TCP options).
const ENOPROTOOPT: i32 = 92;

// ---------------------------------------------------------------------------
// Public API — Linux implementation
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", target_os = "linux"))]
mod imp {
    use super::{TcpAoAlgorithm, TcpAuth, TcpAuthError, MAX_KEY_LEN};
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::time::{Duration, Instant};

    // Socket-option constants (uapi/linux/tcp.h, asm-generic/socket.h).
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const SOL_SOCKET: i32 = 1;
    const SO_ERROR: i32 = 4;
    const SOL_TCP: i32 = 6; // IPPROTO_TCP
    const TCP_MD5SIG: i32 = 14;
    const TCP_MD5SIG_EXT: i32 = 32;
    const TCP_MD5SIG_FLAG_PREFIX: u8 = 0x1;
    const TCP_AO_ADD_KEY: i32 = 38;
    const TCP_AO_INFO: i32 = 40;

    // Socket / fcntl / poll constants.
    const SOCK_STREAM: i32 = 1;
    const SOCK_NONBLOCK: i32 = 0o4000;
    const O_NONBLOCK: i32 = 0o4000;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const POLL_OUT: i16 = 0x4;
    const POLL_ERR: i16 = 0x8;
    const POLL_HUP: i16 = 0x10;
    const EINPROGRESS: i32 = 115;
    const EINTR: i32 = 4;

    /// `struct sockaddr_storage` (128 bytes).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrStorage {
        ss_family: u16,
        __pad: [u8; 126],
    }

    /// `struct tcp_md5sig` — uapi/linux/tcp.h.
    #[repr(C)]
    struct TcpMd5sig {
        tcpm_addr: SockaddrStorage,  // address associated with the key
        tcpm_flags: u8,              // extension flags
        tcpm_prefixlen: u8,          // address prefix
        tcpm_keylen: u16,            // key length
        tcpm_ifindex: i32,           // device index for scope
        tcpm_key: [u8; MAX_KEY_LEN], // key (binary)
    }

    /// `struct tcp_ao_add` — setsockopt(TCP_AO_ADD_KEY).
    ///
    /// The `set_current`/`set_rnext` bitfield occupies a `u32` with
    /// `set_current` at bit 0 and `set_rnext` at bit 1; this manual layout
    /// matches the GCC ABI on the little-endian targets librouting ships
    /// for (x86_64, aarch64).
    #[repr(C, align(8))]
    struct TcpAoAdd {
        addr: SockaddrStorage, // peer's address for the key
        alg_name: [u8; 64],    // crypto hash algorithm to use
        ifindex: i32,          // L3 dev index for VRF
        flags: u32,            // bit0 set_current, bit1 set_rnext
        reserved2: u16,        // must be 0
        prefix: u8,            // peer's address prefix
        sndid: u8,             // SendID for outgoing segments
        rcvid: u8,             // RecvID to match for incoming segments
        maclen: u8,            // length of authentication code (hash)
        keyflags: u8,          // TCP_AO_KEYF_*
        keylen: u8,            // length of ::key
        key: [u8; MAX_KEY_LEN],
    }

    /// `struct tcp_ao_info_opt` — setsockopt(TCP_AO_INFO).
    ///
    /// Bitfield in `flags`: bit0 set_current, bit1 set_rnext, bit2
    /// ao_required, bit3 set_counters, bit4 accept_icmps (little-endian
    /// ABI as for [`TcpAoAdd`]).
    #[repr(C, align(8))]
    struct TcpAoInfoOpt {
        flags: u32,
        reserved2: u16,
        current_key: u8,
        rnext: u8,
        pkt_good: u64,
        pkt_bad: u64,
        pkt_key_not_found: u64,
        pkt_ao_required: u64,
        pkt_dropped_icmp: u64,
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn setsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: u32,
        ) -> i32;
        fn getsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
        fn connect(fd: i32, addr: *const SockaddrStorage, addrlen: u32) -> i32;
        fn poll(fds: *mut PollFd, nfds: u64, timeout_ms: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn os_error(context: &'static str) -> TcpAuthError {
        TcpAuthError::Os {
            context,
            errno: errno(),
        }
    }

    /// Encodes an IP address (and optional port) as the
    /// `sockaddr_storage` payload of a key structure. Port is zeroed:
    /// both `TCP_MD5SIG` and `TCP_AO_ADD_KEY` match on address only.
    fn key_addr(ip: IpAddr) -> SockaddrStorage {
        let mut s: SockaddrStorage = unsafe { zeroed() };
        match ip {
            IpAddr::V4(v4) => {
                s.ss_family = AF_INET;
                s.__pad[2..6].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                s.ss_family = AF_INET6;
                s.__pad[6..22].copy_from_slice(&v6.octets());
            }
        }
        s
    }

    /// Wildcard address in the family of a listener (for arming keys that
    /// authenticate *any* inbound peer).
    fn any_addr(family: u16) -> SockaddrStorage {
        let mut s: SockaddrStorage = unsafe { zeroed() };
        s.ss_family = family;
        s
    }

    /// Full sockaddr (with port) for connect(2). Field offsets inside
    /// `__pad` (which starts at absolute offset 2):
    /// `sockaddr_in`  — port `0..2`, address `2..6`.
    /// `sockaddr_in6` — port `0..2`, flowinfo `2..6`, address `6..22`,
    /// scope-id `22..26`.
    fn sock_addr(addr: SocketAddr) -> (SockaddrStorage, u32) {
        let mut s: SockaddrStorage = unsafe { zeroed() };
        let port = addr.port().to_be_bytes();
        match addr {
            SocketAddr::V4(v4) => {
                s.ss_family = AF_INET;
                s.__pad[0..2].copy_from_slice(&port);
                s.__pad[2..6].copy_from_slice(&v4.ip().octets());
                (s, 16)
            }
            SocketAddr::V6(v6) => {
                s.ss_family = AF_INET6;
                s.__pad[0..2].copy_from_slice(&port);
                // __pad[2..6] is sin6_flowinfo, left zeroed.
                s.__pad[6..22].copy_from_slice(&v6.ip().octets());
                s.__pad[22..26].copy_from_slice(&v6.scope_id().to_be_bytes());
                (s, 28)
            }
        }
    }

    // -- key installation ---------------------------------------------------

    /// Installs an RFC 2385 key for a specific peer address (exact match).
    fn add_md5_key(fd: i32, peer: IpAddr, key: &[u8]) -> Result<(), TcpAuthError> {
        let mut md5: TcpMd5sig = unsafe { zeroed() };
        md5.tcpm_addr = key_addr(peer);
        md5.tcpm_keylen = key.len() as u16;
        md5.tcpm_key[..key.len()].copy_from_slice(key);
        // SAFETY: `md5` is a valid, fully-initialized repr(C) struct and
        // `setsockopt` only reads `size_of::<TcpMd5sig>()` bytes from it.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TCP,
                TCP_MD5SIG,
                (&raw const md5) as *const core::ffi::c_void,
                size_of::<TcpMd5sig>() as u32,
            )
        };
        if rc < 0 {
            return Err(os_error("setsockopt(TCP_MD5SIG)"));
        }
        Ok(())
    }

    /// Installs an RFC 2385 wildcard key (prefix 0 — any peer). Requires
    /// `TCP_MD5SIG_EXT` (kernel >= 4.14).
    fn add_md5_wildcard_key(fd: i32, family: u16, key: &[u8]) -> Result<(), TcpAuthError> {
        let mut md5: TcpMd5sig = unsafe { zeroed() };
        md5.tcpm_addr = any_addr(family);
        md5.tcpm_flags = TCP_MD5SIG_FLAG_PREFIX;
        md5.tcpm_prefixlen = 0;
        md5.tcpm_keylen = key.len() as u16;
        md5.tcpm_key[..key.len()].copy_from_slice(key);
        // SAFETY: as above.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TCP,
                TCP_MD5SIG_EXT,
                (&raw const md5) as *const core::ffi::c_void,
                size_of::<TcpMd5sig>() as u32,
            )
        };
        if rc < 0 {
            return Err(os_error("setsockopt(TCP_MD5SIG_EXT)"));
        }
        Ok(())
    }

    /// Parameters of one TCP-AO Master Key Tuple installation. `prefix == 0`
    /// with a wildcard address installs a listener key; a full prefix
    /// installs an exact peer key for connectors.
    struct AoKeyInstall<'a> {
        addr: SockaddrStorage,
        prefix: u8,
        send_id: u8,
        recv_id: u8,
        mac_len: u8,
        algorithm: TcpAoAlgorithm,
        key: &'a [u8],
        set_current: bool,
        set_rnext: bool,
    }

    /// Adds one TCP-AO Master Key Tuple to the socket.
    fn add_ao_key(fd: i32, p: AoKeyInstall<'_>) -> Result<(), TcpAuthError> {
        let mut ao: TcpAoAdd = unsafe { zeroed() };
        ao.addr = p.addr;
        let name = p.algorithm.kernel_name();
        ao.alg_name[..name.len()].copy_from_slice(name.as_bytes());
        ao.prefix = p.prefix;
        ao.sndid = p.send_id;
        ao.rcvid = p.recv_id;
        ao.maclen = p.mac_len;
        ao.keylen = p.key.len() as u8;
        ao.key[..p.key.len()].copy_from_slice(p.key);
        ao.flags = (p.set_current as u32) | ((p.set_rnext as u32) << 1);
        // SAFETY: `ao` is a valid, fully-initialized repr(C) struct.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TCP,
                TCP_AO_ADD_KEY,
                (&raw const ao) as *const core::ffi::c_void,
                size_of::<TcpAoAdd>() as u32,
            )
        };
        if rc < 0 {
            return Err(os_error("setsockopt(TCP_AO_ADD_KEY)"));
        }
        Ok(())
    }

    /// Sets per-socket TCP-AO options; used for `ao_required` on listeners.
    fn set_ao_required(fd: i32) -> Result<(), TcpAuthError> {
        let mut info: TcpAoInfoOpt = unsafe { zeroed() };
        info.flags = 1 << 2; // ao_required
                             // SAFETY: `info` is a valid, fully-initialized repr(C) struct.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TCP,
                TCP_AO_INFO,
                (&raw const info) as *const core::ffi::c_void,
                size_of::<TcpAoInfoOpt>() as u32,
            )
        };
        if rc < 0 {
            return Err(os_error("setsockopt(TCP_AO_INFO)"));
        }
        Ok(())
    }

    /// Applies authentication keys to a socket that will *connect* to
    /// `peer`. Must run before connect(2) so the SYN carries the MAC.
    fn arm_outgoing(fd: i32, peer: IpAddr, auth: &TcpAuth) -> Result<(), TcpAuthError> {
        match auth {
            TcpAuth::None => Ok(()),
            TcpAuth::Md5 { key } => add_md5_key(fd, peer, key),
            TcpAuth::Ao {
                keys,
                algorithm,
                mac_len,
                ..
            } => {
                let prefix = if peer.is_ipv4() { 32 } else { 128 };
                for (i, mkt) in keys.iter().enumerate() {
                    // First key becomes Current/RNext: the kernel signs the
                    // SYN with it and requests it from the peer.
                    add_ao_key(
                        fd,
                        AoKeyInstall {
                            addr: key_addr(peer),
                            prefix,
                            send_id: mkt.send_id,
                            recv_id: mkt.recv_id,
                            mac_len: *mac_len,
                            algorithm: *algorithm,
                            key: &mkt.key,
                            set_current: i == 0,
                            set_rnext: i == 0,
                        },
                    )?;
                }
                Ok(())
            }
        }
    }

    // -- public entry points ------------------------------------------------

    pub fn arm_listener_impl(listener: &TcpListener, auth: &TcpAuth) -> Result<(), TcpAuthError> {
        let fd = listener.as_raw_fd();
        match auth {
            TcpAuth::None => Ok(()),
            TcpAuth::Md5 { key } => {
                let family = listener_family(listener);
                add_md5_wildcard_key(fd, family, key)
            }
            TcpAuth::Ao {
                keys,
                algorithm,
                mac_len,
                ao_required,
            } => {
                let family = listener_family(listener);
                for mkt in keys {
                    add_ao_key(
                        fd,
                        AoKeyInstall {
                            addr: any_addr(family),
                            prefix: 0, // wildcard: authenticate any inbound peer
                            send_id: mkt.send_id,
                            recv_id: mkt.recv_id,
                            mac_len: *mac_len,
                            algorithm: *algorithm,
                            key: &mkt.key,
                            set_current: false,
                            set_rnext: false,
                        },
                    )?;
                }
                if *ao_required {
                    set_ao_required(fd)?;
                }
                Ok(())
            }
        }
    }

    /// Address family of a bound listener (used for wildcard key arming).
    fn listener_family(listener: &TcpListener) -> u16 {
        match listener.local_addr() {
            Ok(SocketAddr::V4(_)) => AF_INET,
            _ => AF_INET6,
        }
    }

    pub fn connect_auth_impl(
        addr: SocketAddr,
        auth: &TcpAuth,
        timeout: Duration,
    ) -> Result<TcpStream, TcpAuthError> {
        if auth.is_none() {
            return TcpStream::connect_timeout(&addr, timeout).map_err(|e| TcpAuthError::Os {
                context: "connect",
                errno: e.raw_os_error().unwrap_or(0),
            });
        }
        // SAFETY: raw socket helpers below check every return value; the fd
        // is closed on every error path and handed to TcpStream (which then
        // owns it) on success.
        unsafe {
            let ty = SOCK_STREAM | SOCK_NONBLOCK;
            let fd = socket(family_of(&addr) as i32, ty, 0);
            if fd < 0 {
                return Err(os_error("socket"));
            }
            // Keys first: the SYN must already carry the MAC.
            if let Err(e) = arm_outgoing(fd, addr.ip(), auth) {
                close(fd);
                return Err(e);
            }
            let (sa, len) = sock_addr(addr);
            let rc = connect(fd, &sa, len);
            if rc < 0 && errno() != EINPROGRESS {
                let e = os_error("connect");
                close(fd);
                return Err(e);
            }
            if !wait_writable(fd, timeout) {
                close(fd);
                return Err(TcpAuthError::ConnectTimeout);
            }
            let mut so_err: i32 = 0;
            let mut so_len = size_of::<i32>() as u32;
            let rc = getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                (&raw mut so_err) as *mut core::ffi::c_void,
                &mut so_len,
            );
            if rc < 0 {
                let e = os_error("getsockopt(SO_ERROR)");
                close(fd);
                return Err(e);
            }
            if so_err != 0 {
                let e = TcpAuthError::Os {
                    context: "connect",
                    errno: so_err,
                };
                close(fd);
                return Err(e);
            }
            // Back to blocking mode for the TcpStream consumer.
            let flags = fcntl(fd, F_GETFL);
            if flags >= 0 {
                fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
            }
            Ok(TcpStream::from_raw_fd(fd))
        }
    }

    /// Polls until the socket is writable (connected) or the timeout hits.
    fn wait_writable(fd: i32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let mut pfd = PollFd {
                fd,
                events: POLL_OUT,
                revents: 0,
            };
            let remaining = deadline - now;
            let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            // SAFETY: `pfd` is a valid single-element pollfd array.
            let rc = unsafe { poll(&mut pfd, 1, ms.max(0)) };
            if rc < 0 {
                // EINTR → retry, anything else → give up.
                if errno() == EINTR {
                    continue;
                }
                return false;
            }
            if pfd.revents & (POLL_ERR | POLL_HUP) != 0 {
                // Connect failed; the caller reads SO_ERROR for details.
                return true;
            }
            if pfd.revents & POLL_OUT != 0 {
                return true;
            }
        }
    }

    fn family_of(addr: &SocketAddr) -> u16 {
        match addr {
            SocketAddr::V4(_) => AF_INET,
            SocketAddr::V6(_) => AF_INET6,
        }
    }

    /// Layout pins against the C uapi structs. If any of these fail, the
    /// hand-rolled repr(C) definitions have drifted from the kernel ABI.
    #[cfg(test)]
    mod layout_tests {
        use super::*;
        use std::mem::{offset_of, size_of};

        #[test]
        fn struct_sizes_match_uapi() {
            // struct tcp_md5sig: 128 + 1 + 1 + 2 + 4 + 80 = 216
            assert_eq!(size_of::<TcpMd5sig>(), 216);
            // struct tcp_ao_add: 128 + 64 + 4 + 4 + 2 + 6 + 80 = 288 (align 8)
            assert_eq!(size_of::<TcpAoAdd>(), 288);
            // struct tcp_ao_info_opt: 4 + 2 + 2 + 5*8 = 48 (align 8)
            assert_eq!(size_of::<TcpAoInfoOpt>(), 48);
            // sockaddr_storage is 128 bytes.
            assert_eq!(size_of::<SockaddrStorage>(), 128);
        }

        #[test]
        fn struct_offsets_match_uapi() {
            assert_eq!(offset_of!(TcpMd5sig, tcpm_flags), 128);
            assert_eq!(offset_of!(TcpMd5sig, tcpm_prefixlen), 129);
            assert_eq!(offset_of!(TcpMd5sig, tcpm_keylen), 130);
            assert_eq!(offset_of!(TcpMd5sig, tcpm_ifindex), 132);
            assert_eq!(offset_of!(TcpMd5sig, tcpm_key), 136);

            assert_eq!(offset_of!(TcpAoAdd, alg_name), 128);
            assert_eq!(offset_of!(TcpAoAdd, ifindex), 192);
            assert_eq!(offset_of!(TcpAoAdd, flags), 196);
            assert_eq!(offset_of!(TcpAoAdd, reserved2), 200);
            assert_eq!(offset_of!(TcpAoAdd, prefix), 202);
            assert_eq!(offset_of!(TcpAoAdd, sndid), 203);
            assert_eq!(offset_of!(TcpAoAdd, rcvid), 204);
            assert_eq!(offset_of!(TcpAoAdd, maclen), 205);
            assert_eq!(offset_of!(TcpAoAdd, keyflags), 206);
            assert_eq!(offset_of!(TcpAoAdd, keylen), 207);
            assert_eq!(offset_of!(TcpAoAdd, key), 208);

            assert_eq!(offset_of!(TcpAoInfoOpt, reserved2), 4);
            assert_eq!(offset_of!(TcpAoInfoOpt, current_key), 6);
            assert_eq!(offset_of!(TcpAoInfoOpt, rnext), 7);
            assert_eq!(offset_of!(TcpAoInfoOpt, pkt_good), 8);
            assert_eq!(offset_of!(TcpAoInfoOpt, pkt_dropped_icmp), 40);
        }
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub use imp::{arm_listener_impl as arm_listener, connect_auth_impl as connect_auth};

// ---------------------------------------------------------------------------
// Public API — platforms without kernel support
// ---------------------------------------------------------------------------

#[cfg(all(feature = "std", not(target_os = "linux"),))]
mod stub {
    use super::{TcpAuth, TcpAuthError};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    pub fn arm_listener_impl(_listener: &TcpListener, auth: &TcpAuth) -> Result<(), TcpAuthError> {
        match auth {
            TcpAuth::None => Ok(()),
            _ => Err(TcpAuthError::Unsupported(
                "TCP MD5 / TCP-AO socket options exist only on Linux in librouting",
            )),
        }
    }

    pub fn connect_auth_impl(
        addr: SocketAddr,
        auth: &TcpAuth,
        timeout: Duration,
    ) -> Result<TcpStream, TcpAuthError> {
        match auth {
            TcpAuth::None => {
                TcpStream::connect_timeout(&addr, timeout).map_err(|e| TcpAuthError::Os {
                    context: "connect",
                    errno: e.raw_os_error().unwrap_or(0),
                })
            }
            _ => Err(TcpAuthError::Unsupported(
                "TCP MD5 / TCP-AO socket options exist only on Linux in librouting",
            )),
        }
    }
}

#[cfg(all(feature = "std", not(target_os = "linux")))]
pub use stub::{arm_listener_impl as arm_listener, connect_auth_impl as connect_auth};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_config_validation() {
        assert!(matches!(
            TcpAuth::md5("".as_bytes().to_vec()),
            Err(TcpAuthError::EmptyKey)
        ));
        let long = vec![b'k'; MAX_KEY_LEN + 1];
        assert!(matches!(
            TcpAuth::md5(long),
            Err(TcpAuthError::KeyTooLong(n)) if n == MAX_KEY_LEN + 1
        ));
        let ok = TcpAuth::md5(b"secret".as_slice()).unwrap();
        assert_eq!(
            ok,
            TcpAuth::Md5 {
                key: b"secret".to_vec()
            }
        );
        assert!(!ok.is_none());
    }

    #[test]
    fn ao_config_validation() {
        assert!(matches!(
            TcpAuth::tcp_ao(vec![], TcpAoAlgorithm::HmacSha1, 0),
            Err(TcpAuthError::NoAoKeys)
        ));
        assert!(matches!(
            TcpAoKey::symmetric(1, ""),
            Err(TcpAuthError::EmptyKey)
        ));
        // MAC length over digest size rejected.
        assert!(matches!(
            TcpAuth::tcp_ao(
                vec![TcpAoKey::symmetric(1, "k").unwrap()],
                TcpAoAlgorithm::HmacSha1,
                21
            ),
            Err(TcpAuthError::BadMacLen {
                requested: 21,
                max: 20
            })
        ));
        // mac_len 0 → algorithm default.
        let auth = TcpAuth::tcp_ao(
            vec![TcpAoKey::symmetric(1, "k").unwrap()],
            TcpAoAlgorithm::HmacSha1,
            0,
        )
        .unwrap();
        assert!(matches!(
            &auth,
            TcpAuth::Ao {
                mac_len: 12,
                ao_required: true,
                ..
            }
        ));
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(TcpAoAlgorithm::HmacSha1.kernel_name(), "hmac(sha1)");
        assert_eq!(TcpAoAlgorithm::CmacAes128.kernel_name(), "cmac(aes)");
        assert_eq!(
            TcpAoAlgorithm::parse("HMAC-SHA1"),
            Some(TcpAoAlgorithm::HmacSha1)
        );
        assert_eq!(
            TcpAoAlgorithm::parse("cmac(aes)"),
            Some(TcpAoAlgorithm::CmacAes128)
        );
        assert_eq!(TcpAoAlgorithm::parse("nope"), None);
    }

    #[test]
    fn describe_never_leaks_key_material() {
        let md5 = TcpAuth::md5("topsecret").unwrap();
        assert_eq!(md5.describe(), "md5 (9-byte key)");
        assert!(!md5.describe().contains("topsecret"));

        let ao = TcpAuth::tcp_ao(
            vec![TcpAoKey::symmetric(7, "topsecret").unwrap()],
            TcpAoAlgorithm::HmacSha1,
            0,
        )
        .unwrap();
        assert_eq!(ao.describe(), "tcp-ao hmac(sha1) (1 key(s), maclen 12)");
        assert!(!ao.describe().contains("topsecret"));
    }

    #[test]
    fn error_display() {
        let e = TcpAuthError::Os {
            context: "setsockopt(TCP_AO_ADD_KEY)",
            errno: ENOPROTOOPT,
        };
        assert!(e.is_kernel_unsupported());
        assert!(e.to_string().contains("Protocol not available"));
        assert!(!TcpAuthError::ConnectTimeout.is_kernel_unsupported());
    }

    // -- Linux wire-structure layout pins: see `imp::layout_tests`. --------

    // -- Live loopback handshakes (graceful skip on kernels lacking the
    //    needed options) ----------------------------------------------------

    #[cfg(target_os = "linux")]
    mod live {
        use super::super::*;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        fn skip(e: &TcpAuthError) -> bool {
            e.is_kernel_unsupported()
        }

        #[test]
        fn md5_loopback_authenticated_handshake() {
            let auth = TcpAuth::md5(b"interop-secret".as_slice()).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Err(e) = arm_listener(&listener, &auth) {
                if skip(&e) {
                    eprintln!("skipped (kernel): {e}");
                    return;
                }
                panic!("arm_listener: {e}");
            }
            let addr = listener.local_addr().unwrap();
            let mut client = match connect_auth(addr, &auth, Duration::from_secs(5)) {
                Ok(s) => s,
                Err(e) if skip(&e) => {
                    eprintln!("skipped (kernel): {e}");
                    return;
                }
                Err(e) => panic!("connect_auth: {e}"),
            };
            let (mut server, _) = listener.accept().expect("authenticated accept");
            client.write_all(b"ping").unwrap();
            server.write_all(b"pong").unwrap();
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            client.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"pong");
        }

        #[test]
        fn md5_loopback_wrong_key_rejected() {
            let server_auth = TcpAuth::md5(b"alpha").unwrap();
            let client_auth = TcpAuth::md5(b"beta").unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Err(e) = arm_listener(&listener, &server_auth) {
                if skip(&e) {
                    eprintln!("skipped (kernel): {e}");
                    return;
                }
                panic!("arm_listener: {e}");
            }
            let addr = listener.local_addr().unwrap();
            // The listener drops SYNs signed with the wrong key: connect
            // must fail (timeout or reset), never succeed.
            let r = connect_auth(addr, &client_auth, Duration::from_secs(1));
            match r {
                Ok(_) => panic!("connection with wrong MD5 key was accepted"),
                Err(e) if skip(&e) => {
                    eprintln!("skipped (kernel): {e}");
                }
                Err(_) => {} // rejected as required
            }
            listener.set_nonblocking(true).unwrap();
            assert!(
                listener.accept().is_err(),
                "listener accepted an unauthenticated/wrongly-keyed connection"
            );
        }

        #[test]
        fn tcp_ao_loopback_authenticated_handshake() {
            let auth = TcpAuth::tcp_ao(
                vec![TcpAoKey::symmetric(1, b"ao-secret".as_slice()).unwrap()],
                TcpAoAlgorithm::HmacSha1,
                0,
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Err(e) = arm_listener(&listener, &auth) {
                if skip(&e) {
                    eprintln!("skipped (kernel): {e}");
                    return;
                }
                panic!("arm_listener: {e}");
            }
            let addr = listener.local_addr().unwrap();
            let mut client = match connect_auth(addr, &auth, Duration::from_secs(5)) {
                Ok(s) => s,
                Err(e) if skip(&e) => {
                    eprintln!("skipped (kernel): {e}");
                    return;
                }
                Err(e) => panic!("connect_auth: {e}"),
            };
            let (mut server, _) = listener.accept().expect("authenticated accept");
            client.write_all(b"ping").unwrap();
            server.write_all(b"pong").unwrap();
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            client.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"pong");
        }

        #[test]
        fn tcp_ao_loopback_wrong_key_rejected() {
            let server_auth = TcpAuth::tcp_ao(
                vec![TcpAoKey::symmetric(1, b"alpha").unwrap()],
                TcpAoAlgorithm::HmacSha1,
                0,
            )
            .unwrap();
            // Same KeyID, different key bytes: the MAC check must fail.
            let client_auth = TcpAuth::tcp_ao(
                vec![TcpAoKey::symmetric(1, b"beta").unwrap()],
                TcpAoAlgorithm::HmacSha1,
                0,
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Err(e) = arm_listener(&listener, &server_auth) {
                if skip(&e) {
                    eprintln!("skipped (kernel): {e}");
                    return;
                }
                panic!("arm_listener: {e}");
            }
            let addr = listener.local_addr().unwrap();
            let r = connect_auth(addr, &client_auth, Duration::from_secs(1));
            match r {
                Ok(_) => panic!("connection with wrong TCP-AO key was accepted"),
                Err(e) if skip(&e) => {
                    eprintln!("skipped (kernel): {e}");
                }
                Err(_) => {} // rejected as required
            }
            listener.set_nonblocking(true).unwrap();
            assert!(
                listener.accept().is_err(),
                "listener accepted a connection failing TCP-AO verification"
            );
        }

        #[test]
        fn connect_auth_none_is_plain_connect() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let mut s = connect_auth(addr, &TcpAuth::None, Duration::from_secs(5)).unwrap();
            let (_c, _) = listener.accept().unwrap();
            s.write_all(b"x").unwrap();
        }
    }
}
