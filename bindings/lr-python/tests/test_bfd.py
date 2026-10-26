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
