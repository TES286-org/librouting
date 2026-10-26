"""MPLS Label / LabelStack tests (RFC 3032 §2.1, RFC 8277 §2.2/§2.3).

These tests exercise the Python binding through the public
``librouting.Label`` / ``librouting.LabelStack`` API and the
``librouting.LabelSpec`` dataclass. They mirror the C ABI tests in
``crates/lr-ffi/src/mpls.rs`` and the Go tests in
``bindings/lr-go/mpls_test.go``.
"""

import librouting


def test_label_new_and_readers():
    with librouting.Label(100) as l:
        assert l.value == 100
        assert l.tc == 0
        assert l.ttl == 64
        assert not l.is_reserved


def test_label_reserved():
    with librouting.Label(0) as l:
        assert l.is_reserved


def test_label_new_checked_rejects_oversize():
    # 0x100000 = 1 << 20 = MAX_VALUE + 1.
    try:
        librouting.Label(0x100000, checked=True)
    except librouting.LrError:
        pass
    else:
        raise AssertionError("expected LrError on oversize label value")


def test_label_with_tc_and_ttl():
    l = librouting.Label(0xFFFFF)
    l = l.with_tc(7).with_ttl(255)
    try:
        assert l.tc == 7
        assert l.ttl == 255
    finally:
        l.close()


def test_label_with_tc_masks_high_bits():
    l = librouting.Label(16)
    l = l.with_tc(0xFF)
    try:
        assert l.tc == 0x07
    finally:
        l.close()


def test_label_encode_3octet_and_4octet():
    l = librouting.Label(100).with_tc(0).with_ttl(64)
    try:
        assert l.encode_3octet(bottom=True) == bytes([0x00, 0x06, 0x41])
        assert l.encode_4octet(bottom=True) == bytes([0x00, 0x06, 0x41, 0x40])
    finally:
        l.close()


def test_stack_from_values_roundtrip_4octet():
    s = librouting.LabelStack.from_values([16, 240, 1048575])
    try:
        assert len(s) == 3
        assert not s.is_empty()
        # Read middle entry.
        assert s.at(1).value == 240
        # Encode as 4-octet wire form (12 bytes) and decode back.
        enc = s.encode_4octet()
        assert len(enc) == 12
        dec = librouting.LabelStack.decode_4octet(enc)
        try:
            assert len(dec) == 3
            # Last entry preserved.
            assert dec.at(2).value == 1048575
        finally:
            dec.close()
    finally:
        s.close()


def test_stack_from_labels_roundtrip_3octet():
    specs = [
        librouting.LabelSpec(value=16),
        librouting.LabelSpec(value=240),
    ]
    s = librouting.LabelStack.from_labels(specs)
    try:
        enc = s.encode_3octet()
        assert len(enc) == 6
        dec = librouting.LabelStack.decode_3octet(enc)
        try:
            assert len(dec) == 2
        finally:
            dec.close()
    finally:
        s.close()


def test_stack_push_pop():
    s = librouting.LabelStack()
    try:
        s.push(librouting.Label(100))
        s.push_bottom(librouting.Label(200))
        assert len(s) == 2
        # Top is at index 0.
        assert s.at(0).value == 100
        # Pop the top — pops 100.
        assert s.pop() is True
        assert len(s) == 1
        # The bottom label (200) is now at index 0.
        assert s.at(0).value == 200
        # Pop again — pops 200.
        assert s.pop() is True
        assert s.is_empty()
        # Pop on an empty stack returns False (no label was popped).
        assert s.pop() is False
    finally:
        s.close()


def test_stack_at_returns_error_on_oob():
    s = librouting.LabelStack()
    try:
        try:
            s.at(0)
        except librouting.LrError:
            pass
        else:
            raise AssertionError("expected LrError on out-of-bounds At")
    finally:
        s.close()


def test_stack_decode_4octet_rejects_uneven_length():
    try:
        librouting.LabelStack.decode_4octet(bytes([0, 1, 2]))
    except librouting.LrError:
        pass
    else:
        raise AssertionError("expected LrError on uneven-length decode")


def test_stack_labels_returns_all_specs():
    specs = [
        librouting.LabelSpec(value=16),
        librouting.LabelSpec(value=240),
        librouting.LabelSpec(value=1048575),
    ]
    s = librouting.LabelStack.from_labels(specs)
    try:
        out = s.labels()
        assert len(out) == 3
        assert out[2].value == 1048575
    finally:
        s.close()
