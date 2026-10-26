// Core foundational types + remaining codec surfaces for the new
// C ABI modules landed in issue #92 (bfd is in bfd.go, mpls is in
// mpls.go). This file groups the smaller surfaces together to keep
// the per-file diff readable.

package librouting

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"

import (
        "fmt"
        "runtime"
        "unsafe"
)

// ---------------------------------------------------------------------------
// lr-core foundational types (IpAddr, Prefix, Asn, RouterId, Protocol)
// ---------------------------------------------------------------------------

// IpAddr is a repr-C IP address (v4 or v6).
type IpAddr struct {
        IsV6   bool
        Octets [16]byte
}

func ipAddrFromC(c C.struct_lr_ip_addr_t) IpAddr {
        var o [16]byte
        for i := 0; i < 16; i++ {
                o[i] = byte(c.octets[i])
        }
        return IpAddr{IsV6: c.is_ipv6 != 0, Octets: o}
}

func ipAddrToC(a IpAddr) C.struct_lr_ip_addr_t {
        var c C.struct_lr_ip_addr_t
        c.is_ipv6 = boolToU8(a.IsV6)
        for i := 0; i < 16; i++ {
                c.octets[i] = C.uint8_t(a.Octets[i])
        }
        return c
}

// NewIpAddrV4 constructs an IPv4 address from 4 octets.
func NewIpAddrV4(octets [4]byte) IpAddr {
        var o [16]byte
        copy(o[12:], octets[:])
        return IpAddr{IsV6: false, Octets: o}
}

// NewIpAddrV6 constructs an IPv6 address from 16 octets.
func NewIpAddrV6(octets [16]byte) IpAddr {
        return IpAddr{IsV6: true, Octets: octets}
}

// IsIPv4 returns true when the address is IPv4.
func (a IpAddr) IsIPv4() bool { return !a.IsV6 }

// IsIPv6 returns true when the address is IPv6.
func (a IpAddr) IsIPv6() bool { return a.IsV6 }

// IsUnspecified returns true for 0.0.0.0 or ::.
func (a IpAddr) IsUnspecified() bool {
        return C.lr_ip_addr_is_unspecified(ipAddrToC(a)) != 0
}

// IsMulticast returns true for 224.0.0.0/4 or ff00::/8.
func (a IpAddr) IsMulticast() bool {
        return C.lr_ip_addr_is_multicast(ipAddrToC(a)) != 0
}

// Octets4 returns the 4 IPv4 octets (panics if the address is IPv6).
func (a IpAddr) Octets4() [4]byte {
        if a.IsV6 {
                panic("Octets4 on IPv6 address")
        }
        var o [4]byte
        copy(o[:], a.Octets[12:])
        return o
}

// CorePrefix is an lr-core-form prefix (separate from the policy-form
// PrefixSpec used by lr_prefix_list_*).
type CorePrefix struct {
        Addr      IpAddr
        PrefixLen uint8
}

// NewCorePrefixV4 constructs an IPv4 prefix.
func NewCorePrefixV4(octets [4]byte, prefixLen uint8) CorePrefix {
        return CorePrefix{Addr: NewIpAddrV4(octets), PrefixLen: prefixLen}
}

// NewCorePrefixV6 constructs an IPv6 prefix.
func NewCorePrefixV6(octets [16]byte, prefixLen uint8) CorePrefix {
        return CorePrefix{Addr: NewIpAddrV6(octets), PrefixLen: prefixLen}
}

// Contains returns true when `addr` falls within the prefix.
func (p CorePrefix) Contains(addr IpAddr) bool {
        var cP C.struct_lr_core_prefix_t
        cP.addr = ipAddrToC(p.Addr)
        cP.prefix_len = C.uint8_t(p.PrefixLen)
        cA := ipAddrToC(addr)
        return C.lr_core_prefix_contains(cP, cA) != 0
}

// ContainsPrefix returns true when `inner` falls within `outer`.
func (p CorePrefix) ContainsPrefix(inner CorePrefix) bool {
        var cOuter, cInner C.struct_lr_core_prefix_t
        cOuter.addr = ipAddrToC(p.Addr)
        cOuter.prefix_len = C.uint8_t(p.PrefixLen)
        cInner.addr = ipAddrToC(inner.Addr)
        cInner.prefix_len = C.uint8_t(inner.PrefixLen)
        return C.lr_core_prefix_contains_prefix(cOuter, cInner) != 0
}

// Network returns the network address (host bits zeroed).
func (p CorePrefix) Network() (IpAddr, error) {
        var cP C.struct_lr_core_prefix_t
        cP.addr = ipAddrToC(p.Addr)
        cP.prefix_len = C.uint8_t(p.PrefixLen)
        var out C.struct_lr_ip_addr_t
        rc := C.lr_core_prefix_network(cP, &out)
        if rc != 0 {
                return IpAddr{}, fmt.Errorf("lr_core_prefix_network: %s (rc=%d)", LastError(), int(rc))
        }
        return ipAddrFromC(out), nil
}

// Asn is a 32-bit Autonomous System Number.
type Asn struct{ Value uint32 }

// NewAsn constructs an Asn from a u32 value.
func NewAsn(value uint32) Asn { return Asn{Value: value} }

// IsPrivate returns true for RFC 6996 private range.
func (a Asn) IsPrivate() bool {
        var c C.struct_lr_asn_t
        c.value = C.uint32_t(a.Value)
        return C.lr_asn_is_private(c) != 0
}

// IsASTrans returns true for AS_TRANS (23456).
func (a Asn) IsASTrans() bool {
        var c C.struct_lr_asn_t
        c.value = C.uint32_t(a.Value)
        return C.lr_asn_is_as_trans(c) != 0
}

// RouterID is a 32-bit BGP/OSPF router identifier.
type RouterID struct{ Value uint32 }

// NewRouterIDFromU32 constructs a RouterID from a u32.
func NewRouterIDFromU32(value uint32) RouterID { return RouterID{Value: value} }

// NewRouterIDFromV4 constructs a RouterID from 4 IPv4 octets.
func NewRouterIDFromV4(octets [4]byte) RouterID {
        return RouterID{Value: uint32(C.lr_router_id_from_v4((*C.uint8_t)(unsafe.Pointer(&octets[0]))).value)}
}

// ToV4Bytes writes the RouterID's 4 IPv4 octets.
func (r RouterID) ToV4Bytes() ([4]byte, error) {
        var c C.struct_lr_router_id_t
        c.value = C.uint32_t(r.Value)
        var out [4]byte
        rc := C.lr_router_id_to_v4_bytes(c, (*C.uint8_t)(unsafe.Pointer(&out[0])))
        if rc != 0 {
                return [4]byte{}, fmt.Errorf("lr_router_id_to_v4_bytes: %s (rc=%d)", LastError(), int(rc))
        }
        return out, nil
}

// Protocol constants (mirrors LR_PROTOCOL_*).
const (
        ProtocolBgp       = C.LR_PROTOCOL_BGP
        ProtocolOspfv2   = C.LR_PROTOCOL_OSPFV2
        ProtocolOspfv3    = C.LR_PROTOCOL_OSPFV3
        ProtocolBabel     = C.LR_PROTOCOL_BABEL
        ProtocolStatic    = C.LR_PROTOCOL_STATIC
        ProtocolConnected = C.LR_PROTOCOL_CONNECTED
        ProtocolOther     = C.LR_PROTOCOL_OTHER
)

// ProtocolBirdName returns the BIRD-style name for a protocol constant.
func ProtocolBirdName(proto uint8) (string, error) {
        buf := make([]byte, 32)
        n := C.lr_protocol_bird_name(C.uint8_t(proto), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
        if n == 0 {
                return "", fmt.Errorf("lr_protocol_bird_name returned 0")
        }
        return string(buf[:n]), nil
}

// ProtocolDefaultAdminDistance returns the default admin distance.
func ProtocolDefaultAdminDistance(proto uint8) uint32 {
        return uint32(C.lr_protocol_default_admin_distance(C.uint8_t(proto)))
}

// ---------------------------------------------------------------------------
// BGP best-path (RFC 4271 §9.1.2.2)
// ---------------------------------------------------------------------------

// BestPathConfig mirrors lr_bgp::best_path::BestPathConfig.
type BestPathConfig struct {
        AlwaysCompareMed                bool
        MissingMedAsInfinity            bool
        DeterministicRouterID           bool
        PreferExternals                 bool
        CountConfedInPathLen            bool
        Multipath                       uint32
        MultipathRelax                  bool
        GracefulShutdownLeastPreferred bool
        CompareIgpMetric                bool
        PreferNextHopSelf               bool
}

// DefaultBestPathConfig returns the RFC 4271 §9.1.2.2 defaults.
func DefaultBestPathConfig() BestPathConfig {
        c := C.lr_best_path_config_default()
        return bestPathConfigFromC(c)
}

func bestPathConfigFromC(c C.struct_lr_best_path_config_t) BestPathConfig {
        return BestPathConfig{
                AlwaysCompareMed:                c.always_compare_med != 0,
                MissingMedAsInfinity:            c.missing_med_as_infinity != 0,
                DeterministicRouterID:           c.deterministic_router_id != 0,
                PreferExternals:                 c.prefer_externals != 0,
                CountConfedInPathLen:            c.count_confed_in_path_len != 0,
                Multipath:                       uint32(c.multipath),
                MultipathRelax:                  c.multipath_relax != 0,
                GracefulShutdownLeastPreferred: c.graceful_shutdown_least_preferred != 0,
                CompareIgpMetric:                c.compare_igp_metric != 0,
                PreferNextHopSelf:               c.prefer_next_hop_self != 0,
        }
}

func bestPathConfigToC(b BestPathConfig) C.struct_lr_best_path_config_t {
        return C.struct_lr_best_path_config_t{
                always_compare_med:                 boolToU8(b.AlwaysCompareMed),
                missing_med_as_infinity:           boolToU8(b.MissingMedAsInfinity),
                deterministic_router_id:           boolToU8(b.DeterministicRouterID),
                prefer_externals:                  boolToU8(b.PreferExternals),
                count_confed_in_path_len:          boolToU8(b.CountConfedInPathLen),
                multipath:                         C.uint32_t(b.Multipath),
                multipath_relax:                    boolToU8(b.MultipathRelax),
                graceful_shutdown_least_preferred: boolToU8(b.GracefulShutdownLeastPreferred),
                compare_igp_metric:                boolToU8(b.CompareIgpMetric),
                prefer_next_hop_self:              boolToU8(b.PreferNextHopSelf),
        }
}

// BestPathCompare runs the BGP best-path comparison between two routes.
// Returns -1 when a is preferred, 0 on tie, 1 when b is preferred.
func BestPathCompare(a, b *Route, cfg BestPathConfig) (int, error) {
        if a == nil || b == nil {
                return 0, fmt.Errorf("BestPathCompare: nil route")
        }
        rc := C.lr_best_path_compare(a.ptr, b.ptr, bestPathConfigToC(cfg))
        if rc < 0 && rc != -1 {
                return 0, fmt.Errorf("lr_best_path_compare: %s (rc=%d)", LastError(), int(rc))
        }
        return int(rc), nil
}

// ---------------------------------------------------------------------------
// BGP capabilities (RFC 5492)
// ---------------------------------------------------------------------------

// BGP capability code constants.
const (
        BGPCapMultiprotocolExtensions   = C.LR_BGP_CAP_MULTIPROTOCOL_EXTENSIONS
        BGPCapRouteRefresh             = C.LR_BGP_CAP_ROUTE_REFRESH
        BGPCapExtendedNextHop          = C.LR_BGP_CAP_EXTENDED_NEXT_HOP
        BGPCapExtendedMessage          = C.LR_BGP_CAP_EXTENDED_MESSAGE
        BGPCapGracefulRestart          = C.LR_BGP_CAP_GRACEFUL_RESTART
        BGPCapFourOctetAS              = C.LR_BGP_CAP_FOUR_OCTET_AS
        BGPCapAddPath                  = C.LR_BGP_CAP_ADD_PATH
        BGPCapEnhancedRouteRefresh     = C.LR_BGP_CAP_ENHANCED_ROUTE_REFRESH
        BGPCapLongLivedGracefulRestart = C.LR_BGP_CAP_LONG_LIVED_GRACEFUL_RESTART
)

// BgpCapability is an owned handle to one BGP OPEN capability.
type BgpCapability struct {
        ptr C.lr_bgp_capability_t
}

// NewBgpCapFourOctetAS constructs a Four-Octet-AS capability.
func NewBgpCapFourOctetAS(asn uint32) *BgpCapability {
        c := &BgpCapability{ptr: C.lr_bgp_cap_four_octet_as(C.uint32_t(asn))}
        runtime.SetFinalizer(c, (*BgpCapability).destroy)
        return c
}

func (c *BgpCapability) destroy() {
        if c.ptr != nil {
                C.lr_bgp_cap_free(c.ptr)
                c.ptr = nil
        }
}

// Free releases the handle.
func (c *BgpCapability) Free() {
        runtime.SetFinalizer(c, nil)
        c.destroy()
}

// Code reads the capability's wire code.
func (c *BgpCapability) Code() uint8 {
        return uint8(C.lr_bgp_cap_code(c.ptr))
}

// ValueLen reads the length of the capability's value bytes.
func (c *BgpCapability) ValueLen() int {
        return int(C.lr_bgp_cap_value_len(c.ptr))
}

// Value copies the capability's value bytes.
func (c *BgpCapability) Value() ([]byte, error) {
        n := c.ValueLen()
        if n == 0 {
                return []byte{}, nil
        }
        buf := make([]byte, n)
        got := C.lr_bgp_cap_value(c.ptr, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(n))
        if int(got) != n {
                return nil, fmt.Errorf("lr_bgp_cap_value copied %d, expected %d", int(got), n)
        }
        return buf, nil
}

// AsFourOctet returns the ASN when this is a Four-Octet-AS capability.
func (c *BgpCapability) AsFourOctet() uint32 {
        return uint32(C.lr_bgp_cap_as_four_octet(c.ptr))
}
