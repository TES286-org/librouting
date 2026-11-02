// Package librouting — additional foundational types that complement
// the existing core.go: BoxedIpAddr (RFC 4291 §2.5.5.2 IPv4-mapped
// IPv6 surface), NlriFamily (RFC 4760 AFI/SAFI), RawRouteKey
// (lr_route_key_new / lr_route_key_with_source), Preference
// (admin_distance + metric), ReadBuf / WriteBuf owned buffer
// handles, TimerQueue + TimerSpec, MemoryConn paired transport,
// CRC / Fletcher / OSPF LSA checksum utilities, and the Instant /
// Duration helpers.
//
// The IpAddr, CorePrefix, Asn, RouterID, ProtocolBirdName,
// ProtocolDefaultAdminDistance already live in core.go; this file
// adds the missing surfaces so the Go binding mirrors the C ABI in
// full. Mirrors:
//   lr_core::addr::{IpAddr (boxed form), ...}
//   lr_core::nlri::NlriFamily
//   lr_core::rib::{RouteKey, Preference}
//   lr_core::buf::{ReadBuf, WriteBuf}
//   lr_core::timer::{TimerQueue, TimerSpec}
//   lr_core::checksum::{crc16_arc, crc32c, fletcher32, ospf_lsa_checksum}
//   lr_core::time::{Instant, Duration}
//   lr_ffi::memory_conn::MemoryConn

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// ---- ProtoOther constant (the only LR_PROTOCOL_* not in core.go) ----

// ProtoOther is LR_PROTOCOL_OTHER (6).
const ProtoOther Protocol = 6

// ---- Asn extras (AsU16, AsU32, IsAS23456) ----
//
// The existing Asn type lives in core.go. These methods read the
// 16-bit / 32-bit forms of the value through the C ABI.

// AsU32 returns the 32-bit AS value.
func (a Asn) AsU32() uint32 { return uint32(C.lr_asn_as_u32(C.uint32_t(a.Value))) }

// AsU16 returns the 16-bit AS value, or 0 when the value does not
// fit (RFC 4893 AS_TRANS upgrade path).
func (a Asn) AsU16() uint16 { return uint16(C.lr_asn_as_u16(C.uint32_t(a.Value))) }

// IsAS23456 reports whether the ASN is AS_TRANS (23456). Alias for
// IsASTrans.
func (a Asn) IsAS23456() bool {
	var c C.struct_lr_asn_t
	c.value = C.uint32_t(a.Value)
	return C.lr_asn_is_as23456(c) != 0
}

// ---- BoxedIpAddr (RFC 4291 §2.5.5.2 IPv4-mapped IPv6) ----
//
// The C ABI has a second IpAddr surface — boxed `IpAddr *` returned
// by `lr_ip_addr_from_v4_bytes` / `lr_ip_addr_from_v6_bytes` /
// `lr_ip_addr_from_bytes`, freed via `lr_ip_addr_free`. This is the
// surface that supports `lr_ip_addr_to_ipv4_mapped` and the
// `lr_nlri_family_from_addr` derivation.

// BoxedIpAddr is an owned `IpAddr *` handle.
type BoxedIpAddr struct {
	ptr *C.IpAddr
}

// NewBoxedIPv4 constructs a boxed IpAddr from 4 octets.
func NewBoxedIPv4(octets [4]byte) (*BoxedIpAddr, error) {
	p := C.lr_ip_addr_from_v4_bytes((*C.uint8_t)(unsafe.Pointer(&octets[0])))
	if p == nil {
		return nil, errors.New("lr_ip_addr_from_v4_bytes returned null")
	}
	return adoptBoxedIpAddr(p), nil
}

// NewBoxedIPv6 constructs a boxed IpAddr from 16 octets.
func NewBoxedIPv6(octets [16]byte) (*BoxedIpAddr, error) {
	p := C.lr_ip_addr_from_v6_bytes((*C.uint8_t)(unsafe.Pointer(&octets[0])))
	if p == nil {
		return nil, errors.New("lr_ip_addr_from_v6_bytes returned null")
	}
	return adoptBoxedIpAddr(p), nil
}

// NewBoxedIPFromBytes dispatches on length.
func NewBoxedIPFromBytes(b []byte) (*BoxedIpAddr, error) {
	switch len(b) {
	case 4:
		var a [4]byte
		copy(a[:], b)
		return NewBoxedIPv4(a)
	case 16:
		var a [16]byte
		copy(a[:], b)
		return NewBoxedIPv6(a)
	default:
		return nil, fmt.Errorf("NewBoxedIPFromBytes: bad length %d (want 4 or 16)", len(b))
	}
}

func adoptBoxedIpAddr(p *C.IpAddr) *BoxedIpAddr {
	o := &BoxedIpAddr{ptr: p}
	runtime.SetFinalizer(o, func(x *BoxedIpAddr) { x.Close() })
	return o
}

// Close releases the boxed handle. Idempotent; the finalizer also
// calls Close but explicit Close keeps lifetime churn out of the GC.
func (a *BoxedIpAddr) Close() {
	runtime.SetFinalizer(a, nil)
	if a.ptr != nil {
		C.lr_ip_addr_free(a.ptr)
		a.ptr = nil
	}
}

// IsIPv4MappedIPv6 reports the ::ffff:a.b.c.d form (RFC 4291 §2.5.5.2).
func (a *BoxedIpAddr) IsIPv4MappedIPv6() bool {
	if a.ptr == nil {
		return false
	}
	return C.lr_ip_addr_is_ipv4_mapped_ipv6(a.ptr) != 0
}

// ToIPv4Mapped converts IPv4 to its IPv4-mapped IPv6 form. Returns
// nil when the input is already IPv6 (no fresh allocation needed).
func (a *BoxedIpAddr) ToIPv4Mapped() *BoxedIpAddr {
	if a.ptr == nil {
		return nil
	}
	p := C.lr_ip_addr_to_ipv4_mapped(a.ptr)
	if p == nil {
		return nil
	}
	return adoptBoxedIpAddr(p)
}

// ---- NlriFamily (RFC 4760) ----

// NlriFamily is an AFI + SAFI pair (RFC 4760).
type NlriFamily struct {
	c C.struct_lr_afi_safi_t
}

// Afi returns the 16-bit AFI.
func (f NlriFamily) Afi() uint16 { return uint16(f.c.afi) }

// Safi returns the 8-bit SAFI.
func (f NlriFamily) Safi() uint8 { return uint8(f.c.safi) }

// IsIPv4 reports whether the family is IPv4 (AFI=1).
func (f NlriFamily) IsIPv4() bool { return C.lr_nlri_family_is_ipv4(f.c) != 0 }

// IsIPv6 reports whether the family is IPv6 (AFI=2).
func (f NlriFamily) IsIPv6() bool { return C.lr_nlri_family_is_ipv6(f.c) != 0 }

// IsLabeledUnicast reports whether the family is RFC 8277 labeled-unicast.
func (f NlriFamily) IsLabeledUnicast() bool { return C.lr_nlri_family_is_labeled_unicast(f.c) != 0 }

// IsBgpLs reports whether the family is RFC 7752 BGP-LS.
func (f NlriFamily) IsBgpLs() bool { return C.lr_nlri_family_is_bgp_ls(f.c) != 0 }

// IsBgpLsVpn reports whether the family is RFC 7752 §3 BGP-LS VPN.
func (f NlriFamily) IsBgpLsVpn() bool { return C.lr_nlri_family_is_bgp_ls_vpn(f.c) != 0 }

// NlriFamilyIPv4Unicast returns NlriFamily{AFI=1, SAFI=1}.
func NlriFamilyIPv4Unicast() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv4_unicast()} }

// NlriFamilyIPv6Unicast returns NlriFamily{AFI=2, SAFI=1}.
func NlriFamilyIPv6Unicast() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv6_unicast()} }

// NlriFamilyIPv4Multicast returns NlriFamily{AFI=1, SAFI=2}.
func NlriFamilyIPv4Multicast() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv4_multicast()} }

// NlriFamilyIPv4MplsVpn returns NlriFamily{AFI=1, SAFI=128}.
func NlriFamilyIPv4MplsVpn() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv4_mpls_vpn()} }

// NlriFamilyIPv6MplsVpn returns NlriFamily{AFI=2, SAFI=128}.
func NlriFamilyIPv6MplsVpn() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv6_mpls_vpn()} }

// NlriFamilyIPv4LabeledUnicast returns NlriFamily{AFI=1, SAFI=4} (RFC 8277).
func NlriFamilyIPv4LabeledUnicast() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv4_labeled_unicast()} }

// NlriFamilyIPv6LabeledUnicast returns NlriFamily{AFI=2, SAFI=4} (RFC 8277).
func NlriFamilyIPv6LabeledUnicast() NlriFamily { return NlriFamily{c: C.lr_nlri_family_ipv6_labeled_unicast()} }

// NlriFamilyBgpLs returns NlriFamily{AFI=16388, SAFI=71} (RFC 7752).
func NlriFamilyBgpLs() NlriFamily { return NlriFamily{c: C.lr_nlri_family_bgp_ls()} }

// NlriFamilyBgpLsVpn returns NlriFamily{AFI=16388, SAFI=72} (RFC 7752 §3).
func NlriFamilyBgpLsVpn() NlriFamily { return NlriFamily{c: C.lr_nlri_family_bgp_ls_vpn()} }

// NlriFamilyFromAddr derives the family for a BoxedIpAddr
// (V4 -> {1, 1}, V6 -> {2, 1}).
func NlriFamilyFromAddr(addr *BoxedIpAddr) (NlriFamily, error) {
	if addr == nil || addr.ptr == nil {
		return NlriFamily{}, errors.New("NlriFamilyFromAddr: nil addr")
	}
	var out C.struct_lr_afi_safi_t
	rc := C.lr_nlri_family_from_addr(addr.ptr, &out)
	if rc != 0 {
		return NlriFamily{}, fmt.Errorf("lr_nlri_family_from_addr: %s (rc=%d)", LastError(), int(rc))
	}
	return NlriFamily{c: out}, nil
}

// ---- RawRouteKey ----
//
// The user-friendly RouteKey used elsewhere in this package
// (librouting.go) is the canonical Go form; this RawRouteKey is the
// low-level direct wrapper around the C ABI's lr_route_key_new /
// lr_route_key_with_source constructors.

// RawRouteKey is a direct wrapper around lr_route_key_t.
type RawRouteKey struct {
	c C.struct_lr_route_key_t
}

// NewRawRouteKey constructs a RawRouteKey from a prefix + afi_safi
// (AFI/SAFI packed as afi<<8 | safi).
func NewRawRouteKey(prefix CorePrefix, afiSafi uint16) (RawRouteKey, error) {
	var cP C.struct_lr_core_prefix_t
	cP.addr = ipAddrToC(prefix.Addr)
	cP.prefix_len = C.uint8_t(prefix.PrefixLen)
	var out C.struct_lr_route_key_t
	rc := C.lr_route_key_new(cP, C.uint16_t(afiSafi), &out)
	if rc != 0 {
		return RawRouteKey{}, fmt.Errorf("lr_route_key_new: %s (rc=%d)", LastError(), int(rc))
	}
	return RawRouteKey{c: out}, nil
}

// NewRawRouteKeyWithSource constructs a RawRouteKey with an explicit
// source prefix (RFC 8966 §3.1 source-specific routing).
func NewRawRouteKeyWithSource(prefix CorePrefix, afiSafi uint16, source CorePrefix) (RawRouteKey, error) {
	var cP, cS C.struct_lr_core_prefix_t
	cP.addr = ipAddrToC(prefix.Addr)
	cP.prefix_len = C.uint8_t(prefix.PrefixLen)
	cS.addr = ipAddrToC(source.Addr)
	cS.prefix_len = C.uint8_t(source.PrefixLen)
	var out C.struct_lr_route_key_t
	rc := C.lr_route_key_with_source(cP, C.uint16_t(afiSafi), cS, &out)
	if rc != 0 {
		return RawRouteKey{}, fmt.Errorf("lr_route_key_with_source: %s (rc=%d)", LastError(), int(rc))
	}
	return RawRouteKey{c: out}, nil
}

// Prefix returns the prefix part.
func (k RawRouteKey) Prefix() CorePrefix {
	return CorePrefix{Addr: ipAddrFromC(k.c.prefix.addr), PrefixLen: uint8(k.c.prefix.prefix_len)}
}

// AfiSafi returns the packed AFI/SAFI.
func (k RawRouteKey) AfiSafi() uint16 { return uint16(k.c.afi_safi) }

// HasSource reports whether a source prefix is set.
func (k RawRouteKey) HasSource() bool { return k.c.has_source != 0 }

// SourcePrefix returns the source prefix, or the zero CorePrefix
// when HasSource() is false.
func (k RawRouteKey) SourcePrefix() CorePrefix {
	return CorePrefix{Addr: ipAddrFromC(k.c.source_prefix.addr), PrefixLen: uint8(k.c.source_prefix.prefix_len)}
}

// ---- Preference ----

// Preference is the admin_distance + metric pair (RFC 4271 §9).
type Preference struct {
	AdminDistance uint32
	Metric        uint32
}

// NewPreference constructs a Preference.
func NewPreference(adminDistance, metric uint32) Preference {
	c := C.lr_preference_new(C.uint32_t(adminDistance), C.uint32_t(metric))
	return Preference{AdminDistance: uint32(c.admin_distance), Metric: uint32(c.metric)}
}

// ---- Instant / Duration ----
//
// The C ABI represents Instant and Duration as plain u64
// milliseconds. The helpers below mirror the Rust methods without
// wrapping them in a struct — the u64 is the wire form.

// InstantFromMillis constructs an Instant from a u64 milliseconds value.
func InstantFromMillis(millis uint64) uint64 { return uint64(C.lr_instant_from_millis(C.uint64_t(millis))) }

// InstantFromSecs constructs an Instant from a u64 seconds value.
func InstantFromSecs(secs uint64) uint64 { return uint64(C.lr_instant_from_secs(C.uint64_t(secs))) }

// InstantAsMillis reads an Instant as milliseconds.
func InstantAsMillis(instant uint64) uint64 { return uint64(C.lr_instant_as_millis(C.uint64_t(instant))) }

// InstantAsSecs reads an Instant as seconds.
func InstantAsSecs(instant uint64) uint64 { return uint64(C.lr_instant_as_secs(C.uint64_t(instant))) }

// InstantSaturatingSub returns max(0, later - earlier) in milliseconds.
func InstantSaturatingSub(earlier, later uint64) uint64 {
	return uint64(C.lr_instant_saturating_sub(C.uint64_t(earlier), C.uint64_t(later)))
}

// InstantCheckedAdd adds instant + duration_ms with overflow check.
func InstantCheckedAdd(instant, durationMs uint64) uint64 {
	return uint64(C.lr_instant_checked_add(C.uint64_t(instant), C.uint64_t(durationMs)))
}

// InstantCheckedSub subtracts instant - other with underflow check.
// Returns the result and ok=true on success, or (0, false) on
// underflow.
func InstantCheckedSub(instant, other uint64) (uint64, bool) {
	var out C.uint64_t
	rc := C.lr_instant_checked_sub(C.uint64_t(instant), C.uint64_t(other), &out)
	if rc == -2 { // LR_ERR_INVALID_HANDLE = underflow
		return 0, false
	}
	if rc != 0 {
		return 0, false
	}
	return uint64(out), true
}

// DurationFromMillis constructs a Duration from a u64 milliseconds value.
func DurationFromMillis(millis uint64) uint64 { return uint64(C.lr_duration_from_millis(C.uint64_t(millis))) }

// DurationFromSecs constructs a Duration from a u64 seconds value.
func DurationFromSecs(secs uint64) uint64 { return uint64(C.lr_duration_from_secs(C.uint64_t(secs))) }

// DurationAsMillis reads a Duration as milliseconds.
func DurationAsMillis(durationMs uint64) uint64 { return uint64(C.lr_duration_as_millis(C.uint64_t(durationMs))) }

// DurationAsSecs reads a Duration as seconds.
func DurationAsSecs(durationMs uint64) uint64 { return uint64(C.lr_duration_as_secs(C.uint64_t(durationMs))) }

// DurationCheckedAdd adds two Durations with overflow check.
func DurationCheckedAdd(a, b uint64) uint64 { return uint64(C.lr_duration_checked_add(C.uint64_t(a), C.uint64_t(b))) }

// ---- CRC / Fletcher / OSPF LSA checksum ----

// CRC16ARC computes RFC 1952 CRC-16/ARC over data.
func CRC16ARC(data []byte) uint16 {
	if len(data) == 0 {
		return uint16(C.lr_crc16_arc(nil, 0))
	}
	return uint16(C.lr_crc16_arc((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// CRC32C computes RFC 3748 CRC-32C/Castagnoli over data.
func CRC32C(data []byte) uint32 {
	if len(data) == 0 {
		return uint32(C.lr_crc32c(nil, 0))
	}
	return uint32(C.lr_crc32c((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// Fletcher32 computes generic Fletcher-32 (RFC 2328 §C.4 / RFC 905 §A.3).
func Fletcher32(data []byte) uint32 {
	if len(data) == 0 {
		return uint32(C.lr_fletcher32(nil, 0))
	}
	return uint32(C.lr_fletcher32((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// OspfLsaChecksum computes the RFC 2328 §C.4 LSA checksum (Fletcher-16
// over the LSA body). Returns 0 when len(lsa) < 20.
func OspfLsaChecksum(lsa []byte) uint16 {
	if len(lsa) < 20 {
		return 0
	}
	return uint16(C.lr_ospf_lsa_checksum((*C.uint8_t)(unsafe.Pointer(&lsa[0])), C.size_t(len(lsa))))
}

// OspfLsaChecksumOk reports whether the LSA's embedded checksum
// (offset 16-17) matches the computed Fletcher-16 over the body.
func OspfLsaChecksumOk(lsa []byte) bool {
	if len(lsa) < 20 {
		return false
	}
	return C.lr_ospf_lsa_checksum_ok((*C.uint8_t)(unsafe.Pointer(&lsa[0])), C.size_t(len(lsa))) != 0
}

// ---- ReadBuf ----

// ReadBuf is an owned readable byte buffer with a position cursor.
type ReadBuf struct {
	ptr C.lr_read_buf_t
}

// NewReadBuf constructs a ReadBuf from data (the C side copies).
func NewReadBuf(data []byte) (*ReadBuf, error) {
	var p C.lr_read_buf_t
	if len(data) == 0 {
		p = C.lr_read_buf_new(nil, 0)
	} else {
		p = C.lr_read_buf_new((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
	if p == nil {
		return nil, errors.New("lr_read_buf_new returned null")
	}
	rb := &ReadBuf{ptr: p}
	runtime.SetFinalizer(rb, func(x *ReadBuf) { x.Close() })
	return rb, nil
}

// Close releases the buffer.
func (r *ReadBuf) Close() {
	runtime.SetFinalizer(r, nil)
	if r.ptr != nil {
		C.lr_read_buf_free(r.ptr)
		r.ptr = nil
	}
}

// Remaining returns the bytes left at the current position.
func (r *ReadBuf) Remaining() int { return int(C.lr_read_buf_remaining(r.ptr)) }

// Position returns the current read position.
func (r *ReadBuf) Position() int { return int(C.lr_read_buf_position(r.ptr)) }

// Advance advances the position by n bytes.
func (r *ReadBuf) Advance(n int) error {
	rc := C.lr_read_buf_advance(r.ptr, C.size_t(n))
	if rc != 0 {
		return fmt.Errorf("lr_read_buf_advance: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PeekU8 peeks the next byte without advancing. Returns the byte
// and ok=true, or (0, false) when the buffer is empty.
func (r *ReadBuf) PeekU8() (byte, bool) {
	var out C.uint8_t
	rc := C.lr_read_buf_peek_u8(r.ptr, &out)
	if rc == 1 {
		return 0, false
	}
	if rc != 0 {
		return 0, false
	}
	return byte(out), true
}

// GetU8 reads the next byte and advances.
func (r *ReadBuf) GetU8() (byte, bool) {
	var out C.uint8_t
	rc := C.lr_read_buf_get_u8(r.ptr, &out)
	if rc == 1 {
		return 0, false
	}
	if rc != 0 {
		return 0, false
	}
	return byte(out), true
}

// GetU16BE reads the next 2 bytes big-endian and advances by 2.
func (r *ReadBuf) GetU16BE() (uint16, bool) {
	var out C.uint16_t
	rc := C.lr_read_buf_get_u16_be(r.ptr, &out)
	if rc == 1 {
		return 0, false
	}
	if rc != 0 {
		return 0, false
	}
	return uint16(out), true
}

// GetU32BE reads the next 4 bytes big-endian and advances by 4.
func (r *ReadBuf) GetU32BE() (uint32, bool) {
	var out C.uint32_t
	rc := C.lr_read_buf_get_u32_be(r.ptr, &out)
	if rc == 1 {
		return 0, false
	}
	if rc != 0 {
		return 0, false
	}
	return uint32(out), true
}

// GetU64BE reads the next 8 bytes big-endian and advances by 8.
func (r *ReadBuf) GetU64BE() (uint64, bool) {
	var out C.uint64_t
	rc := C.lr_read_buf_get_u64_be(r.ptr, &out)
	if rc == 1 {
		return 0, false
	}
	if rc != 0 {
		return 0, false
	}
	return uint64(out), true
}

// GetBytes reads n bytes. Returns the slice and ok=true, or
// (nil, false) when the buffer is too short.
func (r *ReadBuf) GetBytes(n int) ([]byte, bool) {
	var b C.struct_lr_bytes_t
	rc := C.lr_read_buf_get_bytes(r.ptr, C.size_t(n), &b)
	if rc == 1 {
		return nil, false
	}
	if rc != 0 {
		return nil, false
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), true
}

// Chunk borrows the remaining bytes as a snapshot (does not
// advance the position).
func (r *ReadBuf) Chunk() ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_read_buf_chunk(r.ptr, &b)
	if rc != 0 {
		return nil, fmt.Errorf("lr_read_buf_chunk: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// ---- WriteBuf ----

// WriteBuf is an owned writable byte buffer.
type WriteBuf struct {
	ptr C.lr_write_buf_t
}

// NewWriteBuf constructs an empty WriteBuf with capacity cap.
func NewWriteBuf(cap int) (*WriteBuf, error) {
	p := C.lr_write_buf_new(C.size_t(cap))
	if p == nil {
		return nil, errors.New("lr_write_buf_new returned null")
	}
	wb := &WriteBuf{ptr: p}
	runtime.SetFinalizer(wb, func(x *WriteBuf) { x.Close() })
	return wb, nil
}

// Close releases the buffer.
func (w *WriteBuf) Close() {
	runtime.SetFinalizer(w, nil)
	if w.ptr != nil {
		C.lr_write_buf_free(w.ptr)
		w.ptr = nil
	}
}

// Position returns the number of bytes written so far.
func (w *WriteBuf) Position() int { return int(C.lr_write_buf_position(w.ptr)) }

// RemainingMut returns the remaining capacity.
func (w *WriteBuf) RemainingMut() int { return int(C.lr_write_buf_remaining_mut(w.ptr)) }

// Capacity returns the total allocated capacity.
func (w *WriteBuf) Capacity() int { return int(C.lr_write_buf_capacity(w.ptr)) }

// PutU8 pushes one byte.
func (w *WriteBuf) PutU8(v byte) error {
	rc := C.lr_write_buf_put_u8(w.ptr, C.uint8_t(v))
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_put_u8: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PutBytes pushes the byte slice.
func (w *WriteBuf) PutBytes(b []byte) error {
	var rc C.int32_t
	if len(b) == 0 {
		rc = C.lr_write_buf_put_bytes(w.ptr, nil, 0)
	} else {
		rc = C.lr_write_buf_put_bytes(w.ptr, (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	}
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_put_bytes: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PutU16BE pushes a 2-byte big-endian value.
func (w *WriteBuf) PutU16BE(v uint16) error {
	rc := C.lr_write_buf_put_u16_be(w.ptr, C.uint16_t(v))
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_put_u16_be: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PutU32BE pushes a 4-byte big-endian value.
func (w *WriteBuf) PutU32BE(v uint32) error {
	rc := C.lr_write_buf_put_u32_be(w.ptr, C.uint32_t(v))
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_put_u32_be: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PutU64BE pushes an 8-byte big-endian value.
func (w *WriteBuf) PutU64BE(v uint64) error {
	rc := C.lr_write_buf_put_u64_be(w.ptr, C.uint64_t(v))
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_put_u64_be: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Patch back-fills len(data) bytes at offset at.
func (w *WriteBuf) Patch(at int, data []byte) error {
	var rc C.int32_t
	if len(data) == 0 {
		rc = C.lr_write_buf_patch(w.ptr, C.size_t(at), nil, 0)
	} else {
		rc = C.lr_write_buf_patch(w.ptr, C.size_t(at), (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_patch: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Reserve at least `additional` more bytes of capacity.
func (w *WriteBuf) Reserve(additional int) error {
	rc := C.lr_write_buf_reserve(w.ptr, C.size_t(additional))
	if rc != 0 {
		return fmt.Errorf("lr_write_buf_reserve: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Written returns the bytes written so far without resetting the buffer.
func (w *WriteBuf) Written() ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_write_buf_written(w.ptr, &b)
	if rc != 0 {
		return nil, fmt.Errorf("lr_write_buf_written: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// TakeBytes takes the written bytes and resets the buffer to empty.
func (w *WriteBuf) TakeBytes() ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_write_buf_take_bytes(w.ptr, &b)
	if rc != 0 {
		return nil, fmt.Errorf("lr_write_buf_take_bytes: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// ---- TimerQueue / TimerSpec ----

// TimerSpec is one timer arm — fire-once or periodic.
type TimerSpec struct {
	AfterMs    uint64
	PeriodicMs uint64
}

// TimerSpecOnce constructs a fire-once TimerSpec.
func TimerSpecOnce(afterMs uint64) TimerSpec {
	c := C.lr_timer_spec_once(C.uint64_t(afterMs))
	return TimerSpec{AfterMs: uint64(c.after_ms), PeriodicMs: uint64(c.periodic_ms)}
}

// TimerSpecPeriodic constructs a periodic TimerSpec.
func TimerSpecPeriodic(afterMs, periodicMs uint64) TimerSpec {
	c := C.lr_timer_spec_periodic(C.uint64_t(afterMs), C.uint64_t(periodicMs))
	return TimerSpec{AfterMs: uint64(c.after_ms), PeriodicMs: uint64(c.periodic_ms)}
}

func (s TimerSpec) toC() C.struct_lr_timer_spec_t {
	var c C.struct_lr_timer_spec_t
	c.after_ms = C.uint64_t(s.AfterMs)
	c.periodic_ms = C.uint64_t(s.PeriodicMs)
	return c
}

// TimerQueue is an ordered timer queue with arm / cancel / tick.
type TimerQueue struct {
	ptr C.lr_timer_queue_t
}

// NewTimerQueue constructs an empty TimerQueue.
func NewTimerQueue() (*TimerQueue, error) {
	p := C.lr_timer_queue_new()
	if p == nil {
		return nil, errors.New("lr_timer_queue_new returned null")
	}
	tq := &TimerQueue{ptr: p}
	runtime.SetFinalizer(tq, func(x *TimerQueue) { x.Close() })
	return tq, nil
}

// Close releases the queue.
func (q *TimerQueue) Close() {
	runtime.SetFinalizer(q, nil)
	if q.ptr != nil {
		C.lr_timer_queue_free(q.ptr)
		q.ptr = nil
	}
}

// Arm schedules a timer with the given id and spec at time nowMs.
func (q *TimerQueue) Arm(nowMs uint64, id uint32, spec TimerSpec) error {
	rc := C.lr_timer_queue_arm(q.ptr, C.uint64_t(nowMs), C.lr_timer_id_t(id), spec.toC())
	if rc != 0 {
		return fmt.Errorf("lr_timer_queue_arm: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Cancel cancels the timer with the given id.
func (q *TimerQueue) Cancel(id uint32) error {
	rc := C.lr_timer_queue_cancel(q.ptr, C.lr_timer_id_t(id))
	if rc != 0 {
		return fmt.Errorf("lr_timer_queue_cancel: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// CancelAll cancels every timer in the queue.
func (q *TimerQueue) CancelAll() error {
	rc := C.lr_timer_queue_cancel_all(q.ptr)
	if rc != 0 {
		return fmt.Errorf("lr_timer_queue_cancel_all: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Tick advances the queue to nowMs and returns the list of timer IDs
// that fired.
func (q *TimerQueue) Tick(nowMs uint64) ([]uint32, error) {
	var arr *C.lr_timer_id_t
	var count C.size_t
	rc := C.lr_timer_queue_tick(q.ptr, C.uint64_t(nowMs), &arr, &count)
	if rc != 0 {
		return nil, fmt.Errorf("lr_timer_queue_tick: %s (rc=%d)", LastError(), int(rc))
	}
	n := int(count)
	if n == 0 {
		return nil, nil
	}
	defer C.lr_timer_queue_drain_free(arr, count)
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = uint32(*(*C.lr_timer_id_t)(unsafe.Pointer(uintptr(unsafe.Pointer(arr)) + uintptr(i)*unsafe.Sizeof(*arr))))
	}
	return out, nil
}

// IsEmpty reports whether the queue is empty.
func (q *TimerQueue) IsEmpty() bool { return C.lr_timer_queue_is_empty(q.ptr) != 0 }

// Len returns the number of armed timers.
func (q *TimerQueue) Len() int { return int(C.lr_timer_queue_len(q.ptr)) }

// NextFireMs returns the next scheduled fire time in milliseconds,
// or 0 when the queue is empty.
func (q *TimerQueue) NextFireMs() uint64 { return uint64(C.lr_timer_queue_next_fire_ms(q.ptr)) }

// ---- MemoryConn ----

// MemoryConn is a paired in-process byte transport.
type MemoryConn struct {
	ptr C.lr_memory_conn_t
}

// NewMemoryConn constructs an empty MemoryConn.
func NewMemoryConn() (*MemoryConn, error) {
	p := C.lr_memory_conn_new()
	if p == nil {
		return nil, errors.New("lr_memory_conn_new returned null")
	}
	c := &MemoryConn{ptr: p}
	runtime.SetFinalizer(c, func(x *MemoryConn) { x.Close() })
	return c, nil
}

// NewMemoryConnPair returns two independent MemoryConns (loopback
// wiring is the embedder's job).
func NewMemoryConnPair() (*MemoryConn, *MemoryConn, error) {
	var a, b C.lr_memory_conn_t
	rc := C.lr_memory_conn_pair(&a, &b)
	if rc != 0 {
		return nil, nil, fmt.Errorf("lr_memory_conn_pair: %s (rc=%d)", LastError(), int(rc))
	}
	ca := &MemoryConn{ptr: a}
	cb := &MemoryConn{ptr: b}
	runtime.SetFinalizer(ca, func(x *MemoryConn) { x.Close() })
	runtime.SetFinalizer(cb, func(x *MemoryConn) { x.Close() })
	return ca, cb, nil
}

// Close releases the conn.
func (c *MemoryConn) Close() {
	runtime.SetFinalizer(c, nil)
	if c.ptr != nil {
		C.lr_memory_conn_free(c.ptr)
		c.ptr = nil
	}
}

// PushInput appends bytes to the inbound queue (the bytes the peer
// sent to us).
func (c *MemoryConn) PushInput(data []byte) error {
	var rc C.int32_t
	if len(data) == 0 {
		rc = C.lr_memory_conn_push_input(c.ptr, nil, 0)
	} else {
		rc = C.lr_memory_conn_push_input(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
	if rc != 0 {
		return fmt.Errorf("lr_memory_conn_push_input: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// TakeInput drains the inbound queue.
func (c *MemoryConn) TakeInput() ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_memory_conn_take_input(c.ptr, &b)
	if rc != 0 {
		return nil, fmt.Errorf("lr_memory_conn_take_input: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}

// PutOutput appends bytes to the outbound queue (the bytes we
// prepared for the peer).
func (c *MemoryConn) PutOutput(data []byte) error {
	var rc C.int32_t
	if len(data) == 0 {
		rc = C.lr_memory_conn_put_output(c.ptr, nil, 0)
	} else {
		rc = C.lr_memory_conn_put_output(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
	if rc != 0 {
		return fmt.Errorf("lr_memory_conn_put_output: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// DrainOutput drains the outbound queue.
func (c *MemoryConn) DrainOutput() ([]byte, error) {
	var b C.struct_lr_bytes_t
	rc := C.lr_memory_conn_drain_output(c.ptr, &b)
	if rc != 0 {
		return nil, fmt.Errorf("lr_memory_conn_drain_output: %s (rc=%d)", LastError(), int(rc))
	}
	defer C.lr_bytes_free(&b)
	return copyBytes(&b), nil
}
