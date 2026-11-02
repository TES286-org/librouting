// BGP Path Attributes — mirrors `lr_bgp::path::PathAttributes`.
//
// This file mirrors the public Rust API of `lr_bgp::path::PathAttributes`
// and the C ABI surface in `lr_ffi.h` (`lr_bgp_path_attrs_*`).
//
// # API hierarchy
//
// The Go surface mirrors the Rust module split:
//   - BgpPathAttrs       — lr_bgp::path::PathAttributes (RFC 4271 §5.1 container)
//   - BgpLargeCommunity  — lr_bgp::path::LargeCommunity (RFC 8097 — three u32 fields)
//   - BgpAsPath          — minimal RAII wrapper for the opaque handle returned
//     by AsPath / AsPathWire / As4Path. The full BgpAsPath surface (decode /
//     encode / prepend / segment iteration) is a separate follow-up.
//   - BgpNextHop         — value type for `lr_bgp_next_hop_t`
//   - PathAttr           — value type for the (flags, type, value) triple
//
// Each owned handle is garbage-collected via runtime.SetFinalizer,
// matching the rest of this package. Use Free() for explicit teardown.
//
// # Constants
//
// The IANA BGP path attribute type codes (RFC 4271 §5.1 + extensions)
// are exported as `BGPAttr*` constants, mirroring `lr_bgp::path::AttrType`
// so a Go caller can drive Get / Remove / At with the same constants the
// C ABI and the Rust crate use. The librouting-private tags (OSPF / Babel
// / IGP metric / peer-source-address / LrMplsLabelStack) are included.

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
	"net/netip"
	"runtime"
	"unsafe"
)

// ----------------------------------------------------------------------
// Constants — mirror lr_bgp::path::AttrType and lr_bgp_next_hop_t::kind.
// ----------------------------------------------------------------------

// ORIGIN attribute values (RFC 4271 §5.1.1).
const (
	OriginIGP        = 0
	OriginEGP        = 1
	OriginIncomplete = 2
)

// NEXT_HOP kind values (lr_bgp_next_hop_t::kind).
const (
	NextHopV4       = 0
	NextHopV6       = 1
	NextHopV4OverV6 = 2 // RFC 5549 IPv4-over-IPv6.
)

// IANA BGP path attribute type codes (RFC 4271 §5.1 + extensions).
// Mirror `lr_bgp::path::AttrType`.
const (
	BGPAttrOrigin           uint8 = 1
	BGPAttrAsPath           uint8 = 2
	BGPAttrNextHop          uint8 = 3
	BGPAttrMed              uint8 = 4
	BGPAttrLocalPref        uint8 = 5
	BGPAttrAtomicAggregate  uint8 = 6
	BGPAttrAggregator       uint8 = 7
	BGPAttrCommunities      uint8 = 8
	BGPAttrOriginatorID     uint8 = 9
	BGPAttrClusterList      uint8 = 10
	BGPAttrMpReachNlri      uint8 = 14
	BGPAttrMpUnreachNlri    uint8 = 15
	BGPAttrExtCommunities   uint8 = 16
	BGPAttrAs4Path          uint8 = 17
	BGPAttrPmsiTunnel       uint8 = 22
	BGPAttrAigp             uint8 = 26
	BGPAttrLargeCommunities uint8 = 32
	BGPAttrOtc              uint8 = 35
)

// librouting-private attribute tags — never transmitted on the wire;
// used by the Loc-RIB / policy DSL to carry metadata the best-path
// selector reads.
const (
	BGPAttrOspfMetric2       uint8 = 253
	BGPAttrOspfRouterID      uint8 = 252
	BGPAttrBabelRouterID     uint8 = 250
	BGPAttrBabelSeqno        uint8 = 249
	BGPAttrIgpMetric         uint8 = 246
	BGPAttrPeerSourceAddress uint8 = 245
	BGPAttrLrMplsLabelStack  uint8 = 255
)

// ----------------------------------------------------------------------
// BgpNextHop — value type for the lr_bgp_next_hop_t C struct.
// ----------------------------------------------------------------------

// BgpNextHop is one IPv4/IPv6 next-hop value (RFC 4271 §5.1.3 /
// RFC 4760 §3 / RFC 5549 IPv4-over-IPv6). Addr is always 16 bytes —
// the first 4 bytes are used for kind == NextHopV4. Present is true
// when the attribute is set on the underlying PathAttributes.
type BgpNextHop struct {
	Addr    [16]byte
	Kind    uint8
	Present bool
}

// IPAddress returns the next-hop as a stdlib netip.Addr, or the zero
// netip.Addr when the attribute is absent. IPv4-over-IPv6 returns an
// IPv4 address (the 4-byte IPv4 prefix).
func (n BgpNextHop) IPAddress() (netip.Addr, bool) {
	if !n.Present {
		return netip.Addr{}, false
	}
	switch n.Kind {
	case NextHopV4, NextHopV4OverV6:
		return netip.AddrFrom4([4]byte(n.Addr[:4])), true
	case NextHopV6:
		return netip.AddrFrom16(n.Addr), true
	}
	return netip.Addr{}, false
}

func nextHopFromC(c *C.lr_bgp_next_hop_t) BgpNextHop {
	var out BgpNextHop
	out.Kind = uint8(c.kind)
	out.Present = c.present != 0
	// c.addr is a fixed uint8_t[16]; cgo surfaces it as a [16]uint8
	// of type _Ctype_uint8_t — convert each byte explicitly.
	for i := 0; i < 16; i++ {
		out.Addr[i] = byte(c.addr[i])
	}
	return out
}

// ----------------------------------------------------------------------
// BgpLargeCommunity — RFC 8097. Three 32-bit fields.
// ----------------------------------------------------------------------

// BgpLargeCommunity is a single RFC 8097 Large Community
// (global, local1, local2). Wraps the boxed lr_bgp_large_community_t
// handle. The handle is freed by the runtime finalizer; call Free
// for explicit teardown.
type BgpLargeCommunity struct {
	ptr C.lr_bgp_large_community_t
}

// NewBgpLargeCommunity constructs a Large Community from its three
// 32-bit fields (RFC 8097 — global administrator + two local data
// words).
func NewBgpLargeCommunity(globalAdmin, localData1, localData2 uint32) (*BgpLargeCommunity, error) {
	p := C.lr_bgp_large_community_new(
		C.uint32_t(globalAdmin),
		C.uint32_t(localData1),
		C.uint32_t(localData2),
	)
	if p == nil {
		return nil, fmt.Errorf("lr_bgp_large_community_new: %s", LastError())
	}
	c := &BgpLargeCommunity{ptr: p}
	runtime.SetFinalizer(c, (*BgpLargeCommunity).destroy)
	return c, nil
}

func (c *BgpLargeCommunity) destroy() {
	if c != nil && c.ptr != nil {
		C.lr_bgp_large_community_free(c.ptr)
		c.ptr = nil
	}
}

// Free releases the handle. Safe to call multiple times.
func (c *BgpLargeCommunity) Free() {
	if c == nil {
		return
	}
	runtime.SetFinalizer(c, nil)
	c.destroy()
}

// GlobalAdmin returns the global administrator field.
func (c *BgpLargeCommunity) GlobalAdmin() uint32 {
	if c == nil || c.ptr == nil {
		return 0
	}
	return uint32(C.lr_bgp_large_community_global_admin(c.ptr))
}

// LocalData1 returns the first local data word.
func (c *BgpLargeCommunity) LocalData1() uint32 {
	if c == nil || c.ptr == nil {
		return 0
	}
	return uint32(C.lr_bgp_large_community_local_data1(c.ptr))
}

// LocalData2 returns the second local data word.
func (c *BgpLargeCommunity) LocalData2() uint32 {
	if c == nil || c.ptr == nil {
		return 0
	}
	return uint32(C.lr_bgp_large_community_local_data2(c.ptr))
}

// String formats the Large Community as "global:local1:local2".
func (c *BgpLargeCommunity) String() string {
	if c == nil || c.ptr == nil {
		return "<freed>"
	}
	return fmt.Sprintf("%d:%d:%d", c.GlobalAdmin(), c.LocalData1(), c.LocalData2())
}

// ----------------------------------------------------------------------
// BgpAsPath — minimal RAII wrapper around the opaque lr_bgp_as_path_t.
// ----------------------------------------------------------------------

// BgpAsPath is a minimal RAII wrapper around the opaque
// lr_bgp_as_path_t handle returned by (BgpPathAttrs).AsPath and
// friends. The full AS_PATH surface (decode / encode / segment
// iteration / prepend / loop-check) is a separate follow-up; this
// type only owns the handle's lifetime so a Go embedder does not
// leak it.
type BgpAsPath struct {
	ptr C.lr_bgp_as_path_t
}

func (p *BgpAsPath) destroy() {
	if p != nil && p.ptr != nil {
		C.lr_bgp_as_path_free(p.ptr)
		p.ptr = nil
	}
}

// Free releases the handle. Safe to call multiple times.
func (p *BgpAsPath) Free() {
	if p == nil {
		return
	}
	runtime.SetFinalizer(p, nil)
	p.destroy()
}

// Closed reports whether the handle has been freed.
func (p *BgpAsPath) Closed() bool {
	return p == nil || p.ptr == nil
}

func wrapAsPath(ptr C.lr_bgp_as_path_t) *BgpAsPath {
	if ptr == nil {
		return nil
	}
	p := &BgpAsPath{ptr: ptr}
	runtime.SetFinalizer(p, (*BgpAsPath).destroy)
	return p
}

// ----------------------------------------------------------------------
// BgpPathAttrs — main RAII class.
// ----------------------------------------------------------------------

// BgpPathAttrs is an owned RFC 4271 §5.1 PathAttributes handle. Wraps
// the boxed lr_bgp_path_attrs_t so a Go embedder can build, populate
// and read the full well-known + optional attribute set the daemon
// uses for BGP best-path selection, MPLS labelled unicast, MP-BGP
// and OSPF / Babel redistribution metadata.
//
// The handle is garbage-collected via a finalizer; call Free for
// explicit teardown.
type BgpPathAttrs struct {
	ptr C.lr_bgp_path_attrs_t
}

// NewBgpPathAttrs constructs an empty PathAttributes set.
func NewBgpPathAttrs() (*BgpPathAttrs, error) {
	p := C.lr_bgp_path_attrs_new()
	if p == nil {
		return nil, fmt.Errorf("lr_bgp_path_attrs_new: %s", LastError())
	}
	a := &BgpPathAttrs{ptr: p}
	runtime.SetFinalizer(a, (*BgpPathAttrs).destroy)
	return a, nil
}

func (a *BgpPathAttrs) destroy() {
	if a != nil && a.ptr != nil {
		C.lr_bgp_path_attrs_free(a.ptr)
		a.ptr = nil
	}
}

// Free releases the handle. Safe to call multiple times.
func (a *BgpPathAttrs) Free() {
	if a == nil {
		return
	}
	runtime.SetFinalizer(a, nil)
	a.destroy()
}

// Closed reports whether the handle has been freed.
func (a *BgpPathAttrs) Closed() bool {
	return a == nil || a.ptr == nil
}

// checkHandle returns an error when the handle is nil.
func (a *BgpPathAttrs) checkHandle(op string) error {
	if a == nil || a.ptr == nil {
		return fmt.Errorf("%s: nil handle", op)
	}
	return nil
}

// ---- lifecycle / introspection ----

// Len returns the number of typed attribute readers wired on this
// set (the PathAttributes::len counter — distinct from Count, which
// is the raw attribute count including unknown / unparsed entries).
func (a *BgpPathAttrs) Len() int {
	if a == nil || a.ptr == nil {
		return 0
	}
	return int(C.lr_bgp_path_attrs_len(a.ptr))
}

// IsEmpty reports whether no typed attribute is set. A non-typed-attr
// set may still have a non-zero Count.
func (a *BgpPathAttrs) IsEmpty() bool {
	if a == nil || a.ptr == nil {
		return true
	}
	return C.lr_bgp_path_attrs_is_empty(a.ptr) != 0
}

// Count returns the raw attribute count — the number of entries in
// the underlying ordered map, including unknown / unparsed
// attributes the typed readers do not surface.
func (a *BgpPathAttrs) Count() int {
	if a == nil || a.ptr == nil {
		return 0
	}
	return int(C.lr_bgp_path_attrs_count(a.ptr))
}

// At reads the attribute at index in insertion order. Returns
// (PathAttr, true) when in range, (zero, false) otherwise.
func (a *BgpPathAttrs) At(index int) (PathAttr, bool, error) {
	if err := a.checkHandle("BgpPathAttrs.At"); err != nil {
		return PathAttr{}, false, err
	}
	var flags, ty C.uint8_t
	var b C.struct_lr_bytes_t
	present := C.lr_bgp_path_attrs_at(a.ptr, C.size_t(index), &flags, &ty, &b)
	if present == 0 {
		return PathAttr{}, false, nil
	}
	defer C.lr_bytes_free(&b)
	v := copyBytes(&b)
	return PathAttr{Flags: uint8(flags), AttrType: uint8(ty), Value: v}, true, nil
}

// Get reads the attribute with IANA type code attrType. Returns
// (PathAttr, true) when present, (zero, false) otherwise.
func (a *BgpPathAttrs) Get(attrType uint8) (PathAttr, bool, error) {
	if err := a.checkHandle("BgpPathAttrs.Get"); err != nil {
		return PathAttr{}, false, err
	}
	var flags, ty C.uint8_t
	var b C.struct_lr_bytes_t
	present := C.lr_bgp_path_attrs_get(a.ptr, C.uint8_t(attrType), &flags, &ty, &b)
	if present == 0 {
		return PathAttr{}, false, nil
	}
	defer C.lr_bytes_free(&b)
	v := copyBytes(&b)
	return PathAttr{Flags: uint8(flags), AttrType: uint8(ty), Value: v}, true, nil
}

// Remove removes the attribute with IANA type code attrType.
// Returns true when the attribute was present (and is now gone),
// false when it was absent.
func (a *BgpPathAttrs) Remove(attrType uint8) bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_remove(a.ptr, C.uint8_t(attrType)) != 0
}

// InsertRaw inserts a raw attribute value with the given flags and
// attrType (IANA code).
func (a *BgpPathAttrs) InsertRaw(flags, attrType uint8, value []byte) error {
	if err := a.checkHandle("BgpPathAttrs.InsertRaw"); err != nil {
		return err
	}
	var ptr *C.uint8_t
	if len(value) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&value[0]))
	}
	rc := C.lr_bgp_path_attrs_insert_raw(
		a.ptr, C.uint8_t(flags), C.uint8_t(attrType), ptr, C.size_t(len(value)))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_insert_raw failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// ---- RFC 4271 §5.1 — well-known mandatory + discretionary ----

// Origin reads the ORIGIN attribute (RFC 4271 §5.1.1). Returns
// (value, true) when present, (0, false) otherwise.
func (a *BgpPathAttrs) Origin() (uint8, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint8_t
	if C.lr_bgp_path_attrs_origin(a.ptr, &out) != 0 {
		return uint8(out), true
	}
	return 0, false
}

// Med reads the MULTI_EXIT_DISC attribute (RFC 4271 §5.1.4).
func (a *BgpPathAttrs) Med() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_med(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// LocalPref reads the LOCAL_PREF attribute (RFC 4271 §5.1.5).
func (a *BgpPathAttrs) LocalPref() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_local_pref(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// SetLocalPref sets the LOCAL_PREF attribute (RFC 4271 §5.1.5).
func (a *BgpPathAttrs) SetLocalPref(value uint32) error {
	if err := a.checkHandle("BgpPathAttrs.SetLocalPref"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_set_local_pref(a.ptr, C.uint32_t(value))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_local_pref failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// AtomicAggregate reports whether the ATOMIC_AGGREGATE attribute is
// present (RFC 4271 §5.1.6).
func (a *BgpPathAttrs) AtomicAggregate() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_atomic_aggregate(a.ptr) != 0
}

// Aggregator reads the AGGREGATOR attribute (RFC 4271 §5.1.7).
// Returns (asn, speaker, true) when present, (0, 0, false) otherwise.
func (a *BgpPathAttrs) Aggregator() (asn, speaker uint32, ok bool) {
	if a == nil || a.ptr == nil {
		return 0, 0, false
	}
	var cAsn, cSpk C.uint32_t
	if C.lr_bgp_path_attrs_aggregator(a.ptr, &cAsn, &cSpk) != 0 {
		return uint32(cAsn), uint32(cSpk), true
	}
	return 0, 0, false
}

// NextHop reads the NEXT_HOP attribute (RFC 4271 §5.1.3). The
// returned BgpNextHop carries Present=false when the attribute is
// absent.
func (a *BgpPathAttrs) NextHop() BgpNextHop {
	var out BgpNextHop
	if a == nil || a.ptr == nil {
		return out
	}
	var c C.lr_bgp_next_hop_t
	if C.lr_bgp_path_attrs_next_hop(a.ptr, &c) != 0 {
		return nextHopFromC(&c)
	}
	return out
}

// ---- RFC 4271 §5.1.2 + RFC 6793 — AS_PATH ----

// AsPath reads the AS_PATH attribute (RFC 4271 §5.1.2). Returns a
// *BgpAsPath handle (caller frees) or nil when absent.
func (a *BgpPathAttrs) AsPath() *BgpAsPath {
	if a == nil || a.ptr == nil {
		return nil
	}
	return wrapAsPath(C.lr_bgp_path_attrs_as_path(a.ptr))
}

// AsPathWire reads the AS_PATH attribute in the explicit 2-byte or
// 4-byte AS form (RFC 6793 §4). Returns nil when absent.
func (a *BgpPathAttrs) AsPathWire(asn4 bool) *BgpAsPath {
	if a == nil || a.ptr == nil {
		return nil
	}
	var flag C.uint8_t
	if asn4 {
		flag = 1
	}
	return wrapAsPath(C.lr_bgp_path_attrs_as_path_wire(a.ptr, flag))
}

// As4Path reads the AS4_PATH attribute (RFC 6793 §3). Returns nil
// when absent.
func (a *BgpPathAttrs) As4Path() *BgpAsPath {
	if a == nil || a.ptr == nil {
		return nil
	}
	return wrapAsPath(C.lr_bgp_path_attrs_as4_path(a.ptr))
}

// ---- RFC 4456 — Route Reflection ----

// OriginatorID reads the ORIGINATOR_ID attribute (RFC 4456 §5).
func (a *BgpPathAttrs) OriginatorID() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_originator_id(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// HasClusterList reports whether the CLUSTER_LIST attribute is
// present (RFC 4456 §8).
func (a *BgpPathAttrs) HasClusterList() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_cluster_list(a.ptr) != 0
}

// ClusterList reads the CLUSTER_LIST attribute (RFC 4456 §8) as
// the raw byte stream — one 4-byte cluster-id per entry, in
// network byte order. Returns nil when absent.
func (a *BgpPathAttrs) ClusterList() []byte {
	if a == nil || a.ptr == nil {
		return nil
	}
	var b C.struct_lr_bytes_t
	C.lr_bgp_path_attrs_cluster_list(a.ptr, &b)
	defer C.lr_bytes_free(&b)
	return copyBytes(&b)
}

// ---- RFC 1997 / 4360 / 8097 — Communities ----

// Communities reads the COMMUNITIES attribute (RFC 1997) as a list
// of u32 values — each `asn<<16 | value`. Returns nil when absent.
func (a *BgpPathAttrs) Communities() []uint32 {
	if a == nil || a.ptr == nil {
		return nil
	}
	var b C.struct_lr_bytes_t
	n := C.lr_bgp_path_attrs_communities(a.ptr, &b)
	defer C.lr_bytes_free(&b)
	count := int(n)
	if count == 0 {
		return nil
	}
	raw := copyBytes(&b)
	if len(raw) < count*4 {
		return nil
	}
	out := make([]uint32, count)
	for i := 0; i < count; i++ {
		off := i * 4
		out[i] = uint32(raw[off])<<24 |
			uint32(raw[off+1])<<16 |
			uint32(raw[off+2])<<8 |
			uint32(raw[off+3])
	}
	return out
}

// ExtCommunities reads the EXTENDED COMMUNITIES attribute (RFC 4360)
// as the raw 8-octet-per-entry byte stream. Returns nil when absent.
func (a *BgpPathAttrs) ExtCommunities() []byte {
	if a == nil || a.ptr == nil {
		return nil
	}
	var b C.struct_lr_bytes_t
	C.lr_bgp_path_attrs_ext_communities(a.ptr, &b)
	defer C.lr_bytes_free(&b)
	return copyBytes(&b)
}

// LargeCommunities reads the LARGE COMMUNITIES attribute (RFC 8097)
// as a slice of *BgpLargeCommunity. Returns nil when absent.
func (a *BgpPathAttrs) LargeCommunities() ([]*BgpLargeCommunity, error) {
	if a == nil || a.ptr == nil {
		return nil, nil
	}
	var b C.struct_lr_bytes_t
	n := C.lr_bgp_path_attrs_large_communities(a.ptr, &b)
	defer C.lr_bytes_free(&b)
	count := int(n)
	if count == 0 {
		return nil, nil
	}
	raw := copyBytes(&b)
	if len(raw) < count*12 {
		return nil, nil
	}
	out := make([]*BgpLargeCommunity, count)
	for i := 0; i < count; i++ {
		off := i * 12
		ga := uint32(raw[off])<<24 | uint32(raw[off+1])<<16 |
			uint32(raw[off+2])<<8 | uint32(raw[off+3])
		l1 := uint32(raw[off+4])<<24 | uint32(raw[off+5])<<16 |
			uint32(raw[off+6])<<8 | uint32(raw[off+7])
		l2 := uint32(raw[off+8])<<24 | uint32(raw[off+9])<<16 |
			uint32(raw[off+10])<<8 | uint32(raw[off+11])
		c, err := NewBgpLargeCommunity(ga, l1, l2)
		if err != nil {
			return out[:i], err
		}
		out[i] = c
	}
	return out, nil
}

// HasCommunity reports whether the COMMUNITIES attribute contains
// the given u32 community value (RFC 1997).
func (a *BgpPathAttrs) HasCommunity(community uint32) bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_community(a.ptr, C.uint32_t(community)) != 0
}

// InsertCommunity inserts one u32 community value into the
// COMMUNITIES attribute (RFC 1997).
func (a *BgpPathAttrs) InsertCommunity(community uint32) error {
	if err := a.checkHandle("BgpPathAttrs.InsertCommunity"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_insert_community(a.ptr, C.uint32_t(community))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_insert_community failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// InsertLargeCommunity inserts one *BgpLargeCommunity into the
// LARGE COMMUNITIES attribute (RFC 8097).
func (a *BgpPathAttrs) InsertLargeCommunity(c *BgpLargeCommunity) error {
	if err := a.checkHandle("BgpPathAttrs.InsertLargeCommunity"); err != nil {
		return err
	}
	if c == nil || c.ptr == nil {
		return errors.New("BgpPathAttrs.InsertLargeCommunity: nil community")
	}
	rc := C.lr_bgp_path_attrs_insert_large_community(a.ptr, c.ptr)
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_insert_large_community failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// ---- RFC 7311 / 8124 — AIGP ----

// HasAigp reports whether the AIGP attribute (RFC 7311) is present.
func (a *BgpPathAttrs) HasAigp() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_aigp(a.ptr) != 0
}

// Aigp reads the AIGP attribute (RFC 7311) value as a 64-bit
// unsigned int.
func (a *BgpPathAttrs) Aigp() (uint64, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint64_t
	if C.lr_bgp_path_attrs_aigp(a.ptr, &out) != 0 {
		return uint64(out), true
	}
	return 0, false
}

// ---- RFC 9655 — OTC (Only To Customer) ----

// HasOtc reports whether the OTC attribute (RFC 9655) is present.
func (a *BgpPathAttrs) HasOtc() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_otc(a.ptr) != 0
}

// Otc reads the OTC attribute (RFC 9655) value as a 32-bit unsigned int.
func (a *BgpPathAttrs) Otc() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_otc(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// ---- RFC 6514 — PMSI Tunnel ----

// HasPmsiTunnel reports whether the PMSI_TUNNEL attribute (RFC 6514)
// is present.
func (a *BgpPathAttrs) HasPmsiTunnel() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_pmsi_tunnel(a.ptr) != 0
}

// ---- RFC 8277 — MPLS Label Stack ----

// LabelStack reads the LrMplsLabelStack attribute (RFC 8277 §3).
// Returns a *MPLSLabelStack (owned by the caller) or nil when absent.
func (a *BgpPathAttrs) LabelStack() *MPLSLabelStack {
	if a == nil || a.ptr == nil {
		return nil
	}
	ptr := C.lr_bgp_path_attrs_label_stack(a.ptr)
	if ptr == nil {
		return nil
	}
	s := &MPLSLabelStack{ptr: ptr}
	runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
	return s
}

// SetLabelStack sets the LrMplsLabelStack attribute (RFC 8277 §3).
func (a *BgpPathAttrs) SetLabelStack(stack *MPLSLabelStack) error {
	if err := a.checkHandle("BgpPathAttrs.SetLabelStack"); err != nil {
		return err
	}
	if stack == nil || stack.ptr == nil {
		return errors.New("BgpPathAttrs.SetLabelStack: nil stack")
	}
	rc := C.lr_bgp_path_attrs_set_label_stack(a.ptr, stack.ptr)
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_label_stack failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// ---- MP-BGP (RFC 4760) ----

// MpReachResult carries the MP_REACH_NLRI attribute (RFC 4760 §3).
type MpReachResult struct {
	FamilyAfi  uint16
	FamilySafi uint8
	NextHop    BgpNextHop
	NlriBytes  []byte
}

// MpReach reads the MP_REACH_NLRI attribute (RFC 4760 §3). Returns
// (result, true) when present, (zero, false) otherwise.
func (a *BgpPathAttrs) MpReach() (MpReachResult, bool, error) {
	if a == nil || a.ptr == nil {
		return MpReachResult{}, false, nil
	}
	var afi C.uint16_t
	var safi C.uint8_t
	var nh C.lr_bgp_next_hop_t
	var b C.struct_lr_bytes_t
	present := C.lr_bgp_path_attrs_mp_reach(a.ptr, &afi, &safi, &nh, &b)
	if present == 0 {
		return MpReachResult{}, false, nil
	}
	defer C.lr_bytes_free(&b)
	return MpReachResult{
		FamilyAfi:  uint16(afi),
		FamilySafi: uint8(safi),
		NextHop:    nextHopFromC(&nh),
		NlriBytes:  copyBytes(&b),
	}, true, nil
}

// MpUnreachResult carries the MP_UNREACH_NLRI attribute (RFC 4760 §3).
type MpUnreachResult struct {
	FamilyAfi  uint16
	FamilySafi uint8
	NlriBytes  []byte
}

// MpUnreach reads the MP_UNREACH_NLRI attribute (RFC 4760 §3).
func (a *BgpPathAttrs) MpUnreach() (MpUnreachResult, bool, error) {
	if a == nil || a.ptr == nil {
		return MpUnreachResult{}, false, nil
	}
	var afi C.uint16_t
	var safi C.uint8_t
	var b C.struct_lr_bytes_t
	present := C.lr_bgp_path_attrs_mp_unreach(a.ptr, &afi, &safi, &b)
	if present == 0 {
		return MpUnreachResult{}, false, nil
	}
	defer C.lr_bytes_free(&b)
	return MpUnreachResult{
		FamilyAfi:  uint16(afi),
		FamilySafi: uint8(safi),
		NlriBytes:  copyBytes(&b),
	}, true, nil
}

// ---- OSPF redistrib (RFC 4577 §3) ----

// SetOspfMetric2 sets the OSPF metric2 attribute (RFC 4577 §3).
func (a *BgpPathAttrs) SetOspfMetric2(metric uint32) error {
	if err := a.checkHandle("BgpPathAttrs.SetOspfMetric2"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_set_ospf_metric2(a.ptr, C.uint32_t(metric))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_ospf_metric2 failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// OspfMetric2 reads the OSPF metric2 attribute (RFC 4577 §3).
func (a *BgpPathAttrs) OspfMetric2() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_ospf_metric2(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// HasOspfMetric2 reports whether the OSPF metric2 attribute is present.
func (a *BgpPathAttrs) HasOspfMetric2() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_ospf_metric2(a.ptr) != 0
}

// SetOspfRouterID sets the OSPF router-id attribute (RFC 4577 §3).
func (a *BgpPathAttrs) SetOspfRouterID(routerID uint32) error {
	if err := a.checkHandle("BgpPathAttrs.SetOspfRouterID"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_set_ospf_router_id(a.ptr, C.uint32_t(routerID))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_ospf_router_id failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// OspfRouterID reads the OSPF router-id attribute (RFC 4577 §3).
func (a *BgpPathAttrs) OspfRouterID() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_ospf_router_id(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// HasOspfRouterID reports whether the OSPF router-id attribute is present.
func (a *BgpPathAttrs) HasOspfRouterID() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_ospf_router_id(a.ptr) != 0
}

// ---- Babel redistrib (RFC 7999 + babel-ext) ----

// SetBabelSeqno sets the Babel seqno attribute (RFC 7999 §3 + babel-ext).
func (a *BgpPathAttrs) SetBabelSeqno(seqno uint16) error {
	if err := a.checkHandle("BgpPathAttrs.SetBabelSeqno"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_set_babel_seqno(a.ptr, C.uint16_t(seqno))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_babel_seqno failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// BabelSeqno reads the Babel seqno attribute (RFC 7999 §3 + babel-ext).
func (a *BgpPathAttrs) BabelSeqno() (uint16, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint16_t
	if C.lr_bgp_path_attrs_babel_seqno(a.ptr, &out) != 0 {
		return uint16(out), true
	}
	return 0, false
}

// HasBabelSeqno reports whether the Babel seqno attribute is present.
func (a *BgpPathAttrs) HasBabelSeqno() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_babel_seqno(a.ptr) != 0
}

// SetBabelRouterID sets the Babel router-id attribute (RFC 7999 §3
// + babel-ext — the 64-bit Babel router-id).
func (a *BgpPathAttrs) SetBabelRouterID(routerID uint64) error {
	if err := a.checkHandle("BgpPathAttrs.SetBabelRouterID"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_set_babel_router_id(a.ptr, C.uint64_t(routerID))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_babel_router_id failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// BabelRouterID reads the Babel router-id attribute (RFC 7999 §3
// + babel-ext).
func (a *BgpPathAttrs) BabelRouterID() (uint64, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint64_t
	if C.lr_bgp_path_attrs_babel_router_id(a.ptr, &out) != 0 {
		return uint64(out), true
	}
	return 0, false
}

// HasBabelRouterID reports whether the Babel router-id attribute is present.
func (a *BgpPathAttrs) HasBabelRouterID() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_babel_router_id(a.ptr) != 0
}

// ---- IGP metric (RFC 4271 §9.1.2.2 step 7) ----

// SetIgpMetric sets the IGP metric attribute (RFC 4271 §9.1.2.2 step 7).
func (a *BgpPathAttrs) SetIgpMetric(metric uint32) error {
	if err := a.checkHandle("BgpPathAttrs.SetIgpMetric"); err != nil {
		return err
	}
	rc := C.lr_bgp_path_attrs_set_igp_metric(a.ptr, C.uint32_t(metric))
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_igp_metric failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// IgpMetric reads the IGP metric attribute (RFC 4271 §9.1.2.2 step 7).
func (a *BgpPathAttrs) IgpMetric() (uint32, bool) {
	if a == nil || a.ptr == nil {
		return 0, false
	}
	var out C.uint32_t
	if C.lr_bgp_path_attrs_igp_metric(a.ptr, &out) != 0 {
		return uint32(out), true
	}
	return 0, false
}

// HasIgpMetric reports whether the IGP metric attribute is present.
func (a *BgpPathAttrs) HasIgpMetric() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_igp_metric(a.ptr) != 0
}

// ---- Peer source address (RFC 4271 §6.3) ----

// SetPeerSourceAddress sets the peer-source-address attribute
// (RFC 4271 §6.3 — the IPv4 (4-byte) or IPv6 (16-byte) source
// address of the BGP peer that sent the route).
func (a *BgpPathAttrs) SetPeerSourceAddress(addr []byte, isIPv6 bool) error {
	if err := a.checkHandle("BgpPathAttrs.SetPeerSourceAddress"); err != nil {
		return err
	}
	expected := 4
	if isIPv6 {
		expected = 16
	}
	if len(addr) != expected {
		return fmt.Errorf("addr must be %d bytes for isIPv6=%v", expected, isIPv6)
	}
	var flag C.uint8_t
	if isIPv6 {
		flag = 1
	}
	rc := C.lr_bgp_path_attrs_set_peer_source_address(
		a.ptr,
		(*C.uint8_t)(unsafe.Pointer(&addr[0])),
		flag,
	)
	if rc != 0 {
		return fmt.Errorf("lr_bgp_path_attrs_set_peer_source_address failed (rc=%d): %s",
			int(rc), LastError())
	}
	return nil
}

// PeerSourceAddress reads the peer-source-address attribute
// (RFC 4271 §6.3). Returns (addr, isIPv6, true) when present,
// (nil, false, false) otherwise.
func (a *BgpPathAttrs) PeerSourceAddress() (addr []byte, isIPv6 bool, ok bool) {
	if a == nil || a.ptr == nil {
		return nil, false, false
	}
	var buf [16]C.uint8_t
	var cIsV6 C.uint8_t
	if C.lr_bgp_path_attrs_peer_source_address(a.ptr, &buf[0], &cIsV6) != 0 {
		isV6 := cIsV6 != 0
		n := 4
		if isV6 {
			n = 16
		}
		out := make([]byte, n)
		for i := 0; i < n; i++ {
			out[i] = byte(buf[i])
		}
		return out, isV6, true
	}
	return nil, false, false
}

// HasPeerSourceAddress reports whether the peer-source-address
// attribute is present.
func (a *BgpPathAttrs) HasPeerSourceAddress() bool {
	if a == nil || a.ptr == nil {
		return false
	}
	return C.lr_bgp_path_attrs_has_peer_source_address(a.ptr) != 0
}
