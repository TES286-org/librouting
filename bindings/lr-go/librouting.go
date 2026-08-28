// Package librouting provides a Go binding for the librouting C ABI.
//
// It exposes the Layer-3 router lifecycle (NewRouter, AddBGPSession,
// FeedInput, DrainOutput, Tick) and Layer-1 codec helpers (DecodeBGP,
// EncodeKeepalive, DecodeBabel). All resources are garbage-collected via
// runtime.SetFinalizer when the corresponding Go values leave scope.
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

// Router is an owned handle to a librouting router instance.
type Router struct {
        ptr C.lr_router_t
}

// NewRouter creates a new router. The returned *Router is garbage-collected
// via a finalizer that calls lr_router_destroy.
func NewRouter() (*Router, error) {
        r := C.lr_router_new()
        if r == nil {
                return nil, fmt.Errorf("lr_router_new returned null")
        }
        out := &Router{ptr: r}
        runtime.SetFinalizer(out, func(o *Router) {
                if o.ptr != nil {
                        C.lr_router_destroy(o.ptr)
                        o.ptr = nil
                }
        })
        return out, nil
}

// AddBGPSession adds a BGP session. Returns the session handle.
// Graceful restart (RFC 4724) is enabled with a 120 s restart time;
// Long-Lived Graceful Restart (RFC 9494) is disabled.
func (r *Router) AddBGPSession(localAS, peerAS, localBGPID uint32, holdTime, keepalive uint16, asn4 bool) (uint64, error) {
        return r.AddBGPSessionExt(localAS, peerAS, localBGPID, holdTime, keepalive, asn4,
                true, 120, false, 0, 0)
}

// AddBGPSessionExt adds a BGP session with explicit graceful-restart
// configuration (RFC 4724 + RFC 9494). Returns the session handle.
//
// restartTime and llgrStaleTime are seconds. LLGR requires GR: when llgr
// is enabled with gracefulRestart disabled the LLGR capability is not
// advertised (RFC 9494 §4.1). llgrMaxStale caps the stale time received
// from the peer; 0 honours the peer's value.
func (r *Router) AddBGPSessionExt(localAS, peerAS, localBGPID uint32, holdTime, keepalive uint16, asn4 bool,
        gracefulRestart bool, restartTime uint16, llgr bool, llgrStaleTime, llgrMaxStale uint32) (uint64, error) {
        var h C.uint64_t
        rc := C.lr_router_add_bgp_session_ext(
                r.ptr,
                C.uint32_t(localAS),
                C.uint32_t(peerAS),
                C.uint32_t(localBGPID),
                C.uint16_t(holdTime),
                C.uint16_t(keepalive),
                toCBool(asn4),
                toCBool(gracefulRestart),
                C.uint16_t(restartTime),
                toCBool(llgr),
                C.uint32_t(llgrStaleTime),
                C.uint32_t(llgrMaxStale),
                &h,
        )
        if rc != 0 {
                return 0, fmt.Errorf("lr_router_add_bgp_session_ext: %s (rc=%d)", LastError(), int(rc))
        }
        return uint64(h), nil
}

// FeedInput pushes bytes from the peer transport into a session.
func (r *Router) FeedInput(session uint64, data []byte) error {
        if len(data) == 0 {
                return nil
        }
        rc := C.lr_router_feed_input(
                r.ptr,
                C.uint64_t(session),
                (*C.uint8_t)(unsafe.Pointer(&data[0])),
                C.size_t(len(data)),
        )
        if rc != 0 {
                return fmt.Errorf("lr_router_feed_input: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// DrainOutput drains bytes the session prepared for the peer transport.
func (r *Router) DrainOutput(session uint64) ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_router_drain_output(
                r.ptr,
                C.uint64_t(session),
                &b,
        )
        if rc != 0 {
                return nil, fmt.Errorf("lr_router_drain_output: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// RequestRouteRefresh asks an established peer to resend the specified address
// family. It returns false when the session did not negotiate RFC 2918.
func (r *Router) RequestRouteRefresh(session uint64, afi uint16, safi uint8) (bool, error) {
        rc := C.lr_router_request_route_refresh(
                r.ptr,
                C.uint64_t(session),
                C.uint16_t(afi),
                C.uint8_t(safi),
        )
        if rc < 0 {
                return false, fmt.Errorf("lr_router_request_route_refresh: %s (rc=%d)", LastError(), int(rc))
        }
        return rc == 1, nil
}

// SetMRAI configures the per-prefix RFC 4271 UPDATE batching interval.
// Setting zero disables batching and flushes pending updates.
func (r *Router) SetMRAI(session uint64, intervalMs uint64) error {
        rc := C.lr_router_set_mrai(r.ptr, C.uint64_t(session), C.uint64_t(intervalMs))
        if rc != 0 {
                return fmt.Errorf("lr_router_set_mrai: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// SetAddPath enables or disables RFC 7911 Add-Path on one BGP session.
// Call it after AddBGPSession and before StartSession — the capability is
// negotiated in OPEN. The peer must also offer Add-Path for it to take
// effect; see also SetAddPathMaxPaths.
func (r *Router) SetAddPath(session uint64, enabled bool) error {
        rc := C.lr_router_set_add_path(r.ptr, C.uint64_t(session), toCBool(enabled))
        if rc != 0 {
                return fmt.Errorf("lr_router_set_add_path: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// SetAddPathMaxPaths caps how many paths per prefix the RFC 7911 decision
// process keeps in the Loc-RIB and advertises to Add-Path peers
// (router-wide; values below 1 are clamped to 1).
func (r *Router) SetAddPathMaxPaths(maxPaths uint32) error {
        rc := C.lr_router_set_add_path_max_paths(r.ptr, C.uint32_t(maxPaths))
        if rc != 0 {
                return fmt.Errorf("lr_router_set_add_path_max_paths: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// ExtNextHopTuple is a single RFC 5549 Extended Next-Hop tuple: IPv4
// unicast NLRI can be resolved over an IPv6 next-hop when all three
// fields are 1, 1, 2 respectively.
type ExtNextHopTuple struct {
        NlriAfi     uint16
        NlriSafi    uint8
        NexthopAfi  uint16
}

// SetExtendedNextHop configures RFC 5549 Extended Next-Hop on a BGP
// session. Pass an empty slice to clear. Must be called after
// AddBGPSession and before StartSession — the capability is negotiated
// in OPEN.
func (r *Router) SetExtendedNextHop(session uint64, tuples []ExtNextHopTuple) error {
        if len(tuples) == 0 {
                rc := C.lr_router_set_extended_next_hop(r.ptr, C.uint64_t(session), nil, 0)
                if rc != 0 {
                        return fmt.Errorf("lr_router_set_extended_next_hop: %s (rc=%d)", LastError(), int(rc))
                }
                return nil
        }
        buf := make([]byte, 5*len(tuples))
        for i, t := range tuples {
                buf[5*i+0] = byte(t.NlriAfi >> 8)
                buf[5*i+1] = byte(t.NlriAfi)
                buf[5*i+2] = t.NlriSafi
                buf[5*i+3] = byte(t.NexthopAfi >> 8)
                buf[5*i+4] = byte(t.NexthopAfi)
        }
        rc := C.lr_router_set_extended_next_hop(
                r.ptr,
                C.uint64_t(session),
                (*C.uint8_t)(unsafe.Pointer(&buf[0])),
                C.uintptr_t(len(tuples)),
        )
        if rc != 0 {
                return fmt.Errorf("lr_router_set_extended_next_hop: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// MPFamily is a single RFC 4760 multiprotocol family: AFI + SAFI.
type MPFamily struct {
        Afi  uint16
        Safi uint8
}

// SetMPFamilies overrides the MP-BGP address families advertised in OPEN.
// Common values: {AFI=1, SAFI=1} for IPv4 unicast, {AFI=2, SAFI=1} for
// IPv6 unicast. Must be called before StartSession.
func (r *Router) SetMPFamilies(session uint64, families []MPFamily) error {
        if len(families) == 0 {
                rc := C.lr_router_set_mp_families(r.ptr, C.uint64_t(session), nil, 0)
                if rc != 0 {
                        return fmt.Errorf("lr_router_set_mp_families: %s (rc=%d)", LastError(), int(rc))
                }
                return nil
        }
        buf := make([]byte, 4*len(families))
        for i, f := range families {
                buf[4*i+0] = byte(f.Afi >> 8)
                buf[4*i+1] = byte(f.Afi)
                buf[4*i+2] = 0 // reserved
                buf[4*i+3] = f.Safi
        }
        rc := C.lr_router_set_mp_families(
                r.ptr,
                C.uint64_t(session),
                (*C.uint8_t)(unsafe.Pointer(&buf[0])),
                C.uintptr_t(len(families)),
        )
        if rc != 0 {
                return fmt.Errorf("lr_router_set_mp_families: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// SetLocalAddress sets the local source address for next-hop-self egress.
// Accepts 4-byte (IPv4) or 16-byte (IPv6) slices. For RFC 5549 ENH
// egress over IPv6 pass a 16-byte IPv6 address. Must be called before
// StartSession.
func (r *Router) SetLocalAddress(session uint64, addr []byte) error {
        var afi uint16
        switch len(addr) {
        case 4:
                afi = 1
        case 16:
                afi = 2
        default:
                return fmt.Errorf("SetLocalAddress: bad address length %d (want 4 or 16)", len(addr))
        }
        rc := C.lr_router_set_local_address(
                r.ptr,
                C.uint64_t(session),
                C.uint16_t(afi),
                (*C.uint8_t)(unsafe.Pointer(&addr[0])),
                C.uintptr_t(len(addr)),
        )
        if rc != 0 {
                return fmt.Errorf("lr_router_set_local_address: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// Tick advances the router clock by `nowMs` milliseconds.
func (r *Router) Tick(nowMs uint64) error {
        rc := C.lr_router_tick(r.ptr, C.uint64_t(nowMs))
        if rc != 0 {
                return fmt.Errorf("lr_router_tick: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// StartSession begins protocol operation on a session (BGP: ManualStart +
// TransportOpen). Call once the transport is connected.
func (r *Router) StartSession(session uint64) error {
        rc := C.lr_router_start_session(r.ptr, C.uint64_t(session))
        if rc != 0 {
                return fmt.Errorf("lr_router_start_session: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// OriginateV4 injects a local IPv4 route ("203.0.113.0/24"-style addr + plen
// + optional next-hop) into Loc-RIB and advertises it to established peers.
func (r *Router) OriginateV4(prefix [4]byte, prefixLen uint8, nextHop *[4]byte) error {
        var nhPtr *C.uint8_t
        if nextHop != nil {
                nhPtr = (*C.uint8_t)(unsafe.Pointer(&nextHop[0]))
        }
        rc := C.lr_router_originate_v4(
                r.ptr,
                (*C.uint8_t)(unsafe.Pointer(&prefix[0])),
                C.uint8_t(prefixLen),
                nhPtr,
        )
        if rc != 0 {
                return fmt.Errorf("lr_router_originate_v4: %s (rc=%d)", LastError(), int(rc))
        }
        return nil
}

// RibLen returns the number of routes currently in Loc-RIB.
func (r *Router) RibLen() (int64, error) {
        n := C.lr_router_rib_len(r.ptr)
        if n < 0 {
                return 0, fmt.Errorf("lr_router_rib_len failed (rc=%d)", int(n))
        }
        return int64(n), nil
}

// RibDump renders the Loc-RIB as a text table (one route per line).
func (r *Router) RibDump() (string, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_router_rib_dump(r.ptr, &b)
        if rc != 0 {
                return "", fmt.Errorf("lr_router_rib_dump: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return string(copyBytes(&b)), nil
}

// SessionsDump renders every session's operational summary as a text
// table (one line per session: handle, kind, ASNs, state, ...).
func (r *Router) SessionsDump() (string, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_router_sessions_dump(r.ptr, &b)
        if rc != 0 {
                return "", fmt.Errorf("lr_router_sessions_dump: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return string(copyBytes(&b)), nil
}

// ABIVersion returns the packed ABI version of the linked library.
func ABIVersion() uint32 {
        return uint32(C.lr_abi_version())
}

// LastError returns the most recent error message from the C side.
func LastError() string {
        cstr := C.lr_last_error()
        if cstr == nil {
                return "no error"
        }
        return C.GoString(cstr)
}

// EncodeKeepalive returns the bytes of a BGP KEEPALIVE message.
func EncodeKeepalive() ([]byte, error) {
        var b C.struct_lr_bytes_t
        rc := C.lr_bgp_encode_keepalive(&b)
        if rc != 0 {
                return nil, fmt.Errorf("lr_bgp_encode_keepalive: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// DecodeBGP decodes a single BGP message from `data`. Returns the canonical
// re-encoded bytes of the message on success.
func DecodeBGP(data []byte) ([]byte, error) {
        if len(data) == 0 {
                return nil, fmt.Errorf("empty input")
        }
        var b C.struct_lr_bytes_t
        rc := C.lr_bgp_decode(
                (*C.uint8_t)(unsafe.Pointer(&data[0])),
                C.size_t(len(data)),
                &b,
        )
        if rc != 0 {
                return nil, fmt.Errorf("lr_bgp_decode: %s (rc=%d)", LastError(), int(rc))
        }
        defer C.lr_bytes_free(&b)
        return copyBytes(&b), nil
}

// toCBool converts a Go bool to a C.uint8_t (0 or 1).
func toCBool(b bool) C.uint8_t {
        if b {
                return 1
        }
        return 0
}

// copyBytes copies a C lr_bytes_t's contents into a Go slice.
func copyBytes(b *C.struct_lr_bytes_t) []byte {
        n := int(C.lr_bytes_len(b))
        if n == 0 {
                return nil
        }
        ptr := C.lr_bytes_ptr(b)
        out := make([]byte, n)
        copy(out, C.GoBytes(unsafe.Pointer(ptr), C.int(n)))
        return out
}
