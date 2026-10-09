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
    // The OS detail text is platform-specific (the Linux strerror
    // differs from the Win32 message table), so only the context
    // prefix and the raw-code suffix are pinned everywhere; the
    // exact strerror text is stable on Linux alone.
    let msg = e.to_string();
    assert!(msg.starts_with("setsockopt(TCP_AO_ADD_KEY): "));
    assert!(msg.contains(&format!("(os error {ENOPROTOOPT})")));
    #[cfg(target_os = "linux")]
    assert!(msg.contains("Protocol not available"));
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
