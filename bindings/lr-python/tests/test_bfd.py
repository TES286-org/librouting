"""BFD Control packet wire codec tests (RFC 5880 §4.1).

Mirrors the C ABI tests in crates/lr-ffi/src/bfd.rs and the Go tests
in bindings/lr-go/bfd_test.go.
"""

import librouting


def test_packet_new_defaults():
    with librouting.BfdPacket.new() as p:
        assert p.version == 1
        assert p.diag == librouting.DIAG_NONE
        assert p.state == librouting.STATE_DOWN
        assert p.detect_mult == 3
        assert p.my_discriminator == 0
        assert p.your_discriminator == 0
        assert p.desired_min_tx_interval == 1_000_000
        assert p.required_min_rx_interval == 1_000_000
        assert p.required_min_echo_interval == 0
        assert p.length == 24


def test_heartbeat():
    with librouting.BfdPacket.heartbeat(0x1234, 0x5678) as p:
        assert p.state == librouting.STATE_UP
        assert p.my_discriminator == 0x1234
        assert p.your_discriminator == 0x5678


def test_setters_mutate_in_place():
    with librouting.BfdPacket.new() as p:
        p.set_diag(librouting.DIAG_CTRL_EXPIRED)
        p.set_state(librouting.STATE_UP)
        p.set_flags(0b0010_0000)  # Poll bit
        p.set_detect_mult(5)
        p.set_my_discriminator(0xAABBCCDD)
        p.set_your_discriminator(0x11223344)
        p.set_desired_min_tx_interval(500_000)
        p.set_required_min_rx_interval(750_000)
        p.set_required_min_echo_interval(100_000)

        assert p.diag == librouting.DIAG_CTRL_EXPIRED
        assert p.state == librouting.STATE_UP
        assert p.flags == 0b0010_0000
        assert p.detect_mult == 5
        assert p.my_discriminator == 0xAABBCCDD
        assert p.your_discriminator == 0x11223344
        assert p.desired_min_tx_interval == 500_000
        assert p.required_min_rx_interval == 750_000
        assert p.required_min_echo_interval == 100_000


def test_set_state_clamps_invalid_to_admin_down():
    with librouting.BfdPacket.new() as p:
        p.set_state(99)
        assert p.state == librouting.STATE_ADMIN_DOWN


def test_set_flags_masks_reserved_bits():
    with librouting.BfdPacket.new() as p:
        p.set_flags(0xFF)
        assert p.flags == 0b0011_1111


def test_encode_decode_roundtrip():
    with librouting.BfdPacket.heartbeat(0xDEADBEEF, 0xCAFEBABE) as p:
        enc = p.encode()
        assert len(enc) == 24

    dec = librouting.decode_bfd_packet(enc)
    try:
        assert dec.state == librouting.STATE_UP
        assert dec.my_discriminator == 0xDEADBEEF
        assert dec.your_discriminator == 0xCAFEBABE
        assert dec.desired_min_tx_interval == 1_000_000
    finally:
        dec.close()


def test_decode_rejects_too_short():
    try:
        librouting.decode_bfd_packet(bytes([0, 1, 2]))
    except librouting.LrError:
        pass
    else:
        raise AssertionError("expected LrError on too-short input")


def test_decode_rejects_empty():
    try:
        librouting.decode_bfd_packet(b"")
    except librouting.LrError:
        pass
    else:
        raise AssertionError("expected LrError on empty input")


# ---- BFD AuthType readers (RFC 5880 §8 IANA codes) ----

def test_auth_type_readers_match_rust():
    assert librouting.auth_type_expected_digest_len(librouting.AUTH_TYPE_KEYED_MD5) == 16
    assert librouting.auth_type_expected_digest_len(librouting.AUTH_TYPE_KEYED_SHA1) == 20
    assert (
        librouting.auth_type_expected_digest_len(librouting.AUTH_TYPE_METICULOUS_KEYED_MD5)
        == 16
    )
    assert (
        librouting.auth_type_expected_digest_len(librouting.AUTH_TYPE_METICULOUS_KEYED_SHA1)
        == 20
    )
    assert librouting.auth_type_expected_digest_len(librouting.AUTH_TYPE_SIMPLE_PASSWORD) == -1
    assert librouting.auth_type_expected_digest_len(99) == -1
    assert librouting.auth_type_is_keyed_hash(librouting.AUTH_TYPE_KEYED_MD5)
    assert not librouting.auth_type_is_keyed_hash(librouting.AUTH_TYPE_SIMPLE_PASSWORD)
    assert librouting.auth_type_is_meticulous(librouting.AUTH_TYPE_METICULOUS_KEYED_MD5)
    assert not librouting.auth_type_is_meticulous(librouting.AUTH_TYPE_KEYED_MD5)


# ---- BFD AuthKey lifecycle ----

def test_auth_key_round_trip():
    secret = b"0123456789abcdef"
    with librouting.BfdAuthKey.new(7, secret) as k:
        assert k.key_id == 7
        assert k.data_len == 16
        assert k.data == secret


def test_auth_key_simple_password():
    pw = b"hunter2"
    with librouting.BfdAuthKey.simple_password(3, pw) as k:
        assert k.key_id == 3
        assert k.data_len == 7
        assert k.data == pw


# ---- BFD AuthSection lifecycle ----

def test_auth_section_simple_password():
    pw = b"hunter2"
    with librouting.BfdAuthSection.simple_password(pw, 7) as s:
        assert s.auth_type == librouting.AUTH_TYPE_SIMPLE_PASSWORD
        assert s.key_id == 7
        assert s.sequence is None
        assert s.data_len == 7
        assert s.wire_len == 3 + 7
        assert s.data == pw


def test_auth_section_keyed_md5():
    digest = bytes(16)
    with librouting.BfdAuthSection.keyed_md5(2, 0xDEADBEEF, digest) as s:
        assert s.auth_type == librouting.AUTH_TYPE_KEYED_MD5
        assert s.key_id == 2
        assert s.sequence == 0xDEADBEEF
        assert s.data_len == 16
        assert s.wire_len == 24


def test_auth_section_keyed_sha1():
    digest = bytes(20)
    with librouting.BfdAuthSection.keyed_sha1(4, 0xFEEDFACE, digest) as s:
        assert s.auth_type == librouting.AUTH_TYPE_KEYED_SHA1
        assert s.wire_len == 28


def test_auth_section_meticulous_variants():
    digest16 = bytes(16)
    with librouting.BfdAuthSection.meticulous_keyed_md5(3, 42, digest16) as s:
        assert s.auth_type == librouting.AUTH_TYPE_METICULOUS_KEYED_MD5

    digest20 = bytes(20)
    with librouting.BfdAuthSection.meticulous_keyed_sha1(5, 42, digest20) as s:
        assert s.auth_type == librouting.AUTH_TYPE_METICULOUS_KEYED_SHA1


# ---- BfdPacket auth integration ----

def test_packet_auth_absent_by_default():
    with librouting.BfdPacket.new() as p:
        assert not p.auth_present
        assert p.auth() is None


def test_packet_set_auth_simple_password_round_trip():
    with librouting.BfdPacket.new() as p:
        pw = b"hunter2"
        s = librouting.BfdAuthSection.simple_password(pw, 7)
        p.set_auth(s)
        assert p.auth_present

        # set_auth consumed `s` — its close() / __del__ must be a no-op.
        s.close()

        sec = p.auth()
        try:
            assert sec is not None
            assert sec.auth_type == librouting.AUTH_TYPE_SIMPLE_PASSWORD
            assert sec.key_id == 7
            assert sec.data_len == 7
            assert sec.data == pw
        finally:
            if sec is not None:
                sec.close()

        # Clear via None.
        p.set_auth(None)
        assert not p.auth_present


# ---- BfdKeyedAuth auth_section_for_tx ----

def test_keyed_auth_auth_section_for_tx():
    secret = b"0123456789abcdef"
    with librouting.BfdKeyedAuth.new(
        librouting.AUTH_ALGO_KEYED_MD5, 7, secret
    ) as a:
        assert a.xmit_seq == 0
        assert a.key_id == 7
        assert a.digest_len == 16
        assert not a.is_meticulous

        sec = a.auth_section_for_tx()
        try:
            assert sec.auth_type == librouting.AUTH_TYPE_KEYED_MD5
            assert sec.key_id == 7
            assert sec.sequence == 0  # xmit_seq before any advance
            assert sec.data_len == 16
            assert sec.data == secret
        finally:
            sec.close()

        # advance_xmit_seq bumps the counter.
        a.advance_xmit_seq()
        assert a.xmit_seq == 1

        sec2 = a.auth_section_for_tx()
        try:
            assert sec2.sequence == 1
        finally:
            sec2.close()


def test_keyed_auth_end_to_end_sign_and_verify_md5():
    """End-to-end: build a packet + auth section, encode, sign, decode,
    verify — mirrors the Rust-side `sign_and_verify_round_trip_md5`
    test in `keyed_auth.rs`."""
    secret = b"0123456789abcdef"
    auth = librouting.BfdKeyedAuth.new(librouting.AUTH_ALGO_KEYED_MD5, 7, secret)
    try:
        p = librouting.BfdPacket.heartbeat(0x11112222, 0x33334444)
        try:
            # Set the A flag bit + install the auth section.
            p.set_flags(0b0000_0100)
            sec = auth.auth_section_for_tx()
            p.set_auth(sec)  # consumes `sec`
            # Encode — the auth section's digest field carries the
            # shared key at this stage.
            wire = p.encode()
        finally:
            p.close()

        # Sign the encoded packet in place — the last 16 bytes
        # (MD5 digest) are replaced with the computed hash.
        buf = bytearray(wire)
        auth.sign_packet(buf)

        # Decode the signed packet — the auth section's `data` field
        # now carries the received digest.
        dec = librouting.decode_bfd_packet(bytes(buf))
        try:
            sec_out = dec.auth()
            assert sec_out is not None
            try:
                # Verify the inbound packet — should authenticate
                # (first packet, AuthSeqKnown=0 → accept any sequence).
                assert auth.verify_inbound(bytes(buf), sec_out, 3)
                assert auth.rcv_auth_seq_known
            finally:
                sec_out.close()
        finally:
            dec.close()
    finally:
        auth.close()
