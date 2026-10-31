// BFD Control packet wire codec (RFC 5880 §4.1).
//
// Mirrors the C ABI surface lr_bfd_* in lr_ffi.h. Resource cleanup is
// garbage-collected via runtime.SetFinalizer, matching the rest of
// the package.

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

// BFD state constants (RFC 5880 §6.1).
const (
	BFDStateAdminDown = C.LR_BFD_STATE_ADMIN_DOWN
	BFDStateDown      = C.LR_BFD_STATE_DOWN
	BFDStateInit      = C.LR_BFD_STATE_INIT
	BFDStateUp        = C.LR_BFD_STATE_UP
)

// BFD diagnostic constants (RFC 5880 §A.1).
const (
	BFDDiagNone             = C.LR_BFD_DIAG_NONE
	BFDDiagCtrlExpired      = C.LR_BFD_DIAG_CTRL_EXPIRED
	BFDDiagEchoFailed       = C.LR_BFD_DIAG_ECHO_FAILED
	BFDDiagNeighborSignaled = C.LR_BFD_DIAG_NEIGHBOR_SIGNALLED
	BFDDiagFwdReset         = C.LR_BFD_DIAG_FWD_RESET
	BFDDiagPathDown         = C.LR_BFD_DIAG_PATH_DOWN
	BFDDiagConcatPathDown   = C.LR_BFD_DIAG_CONCAT_PATH_DOWN
	BFDDiagAdminDown        = C.LR_BFD_DIAG_ADMIN_DOWN
	BFDDiagRevPathDown      = C.LR_BFD_DIAG_REV_PATH_DOWN
	BFDDiagMisConnDefect    = C.LR_BFD_DIAG_MISCONN_DEFECT
)

// BfdPacket is an owned handle to one BFD Control packet.
type BfdPacket struct {
	ptr C.lr_bfd_packet_t
}

// NewBfdPacket constructs an empty BFD packet with sensible defaults
// (state=Down, diag=None, detect_mult=3, intervals=1s, no auth).
func NewBfdPacket() *BfdPacket {
	p := &BfdPacket{ptr: C.lr_bfd_packet_new()}
	runtime.SetFinalizer(p, (*BfdPacket).destroy)
	return p
}

// NewBfdHeartbeat constructs an "Up" heartbeat packet.
func NewBfdHeartbeat(myDisc, yourDisc uint32) *BfdPacket {
	p := &BfdPacket{ptr: C.lr_bfd_packet_heartbeat(C.uint32_t(myDisc), C.uint32_t(yourDisc))}
	runtime.SetFinalizer(p, (*BfdPacket).destroy)
	return p
}

func (p *BfdPacket) destroy() {
	if p.ptr != nil {
		C.lr_bfd_packet_free(p.ptr)
		p.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (p *BfdPacket) Free() {
	runtime.SetFinalizer(p, nil)
	p.destroy()
}

// Version reads the BFD version (always 1 per RFC 5880 §4.1).
func (p *BfdPacket) Version() uint8 {
	return uint8(C.lr_bfd_packet_version(p.ptr))
}

// Diag reads the diagnostic code (one of the BFDDiag* constants).
func (p *BfdPacket) Diag() uint8 {
	return uint8(C.lr_bfd_packet_diag(p.ptr))
}

// State reads the peer state (one of the BFDState* constants).
func (p *BfdPacket) State() uint8 {
	return uint8(C.lr_bfd_packet_state(p.ptr))
}

// Flags reads the flags bitmask (M | D | A | C | F | P).
func (p *BfdPacket) Flags() uint8 {
	return uint8(C.lr_bfd_packet_flags(p.ptr))
}

// DetectMult reads the detect multiplier.
func (p *BfdPacket) DetectMult() uint8 {
	return uint8(C.lr_bfd_packet_detect_mult(p.ptr))
}

// MyDiscriminator reads the My Discriminator field.
func (p *BfdPacket) MyDiscriminator() uint32 {
	return uint32(C.lr_bfd_packet_my_discriminator(p.ptr))
}

// YourDiscriminator reads the Your Discriminator field.
func (p *BfdPacket) YourDiscriminator() uint32 {
	return uint32(C.lr_bfd_packet_your_discriminator(p.ptr))
}

// DesiredMinTxInterval reads the Desired Min TX Interval (microseconds).
func (p *BfdPacket) DesiredMinTxInterval() uint32 {
	return uint32(C.lr_bfd_packet_desired_min_tx_interval(p.ptr))
}

// RequiredMinRxInterval reads the Required Min RX Interval (microseconds).
func (p *BfdPacket) RequiredMinRxInterval() uint32 {
	return uint32(C.lr_bfd_packet_required_min_rx_interval(p.ptr))
}

// RequiredMinEchoInterval reads the Required Min Echo Interval.
func (p *BfdPacket) RequiredMinEchoInterval() uint32 {
	return uint32(C.lr_bfd_packet_required_min_echo_interval(p.ptr))
}

// Length reads the wire length (24 + auth section).
func (p *BfdPacket) Length() uint8 {
	return uint8(C.lr_bfd_packet_length(p.ptr))
}

// SetDiag sets the diagnostic code.
func (p *BfdPacket) SetDiag(diag uint8) error {
	rc := C.lr_bfd_packet_set_diag(p.ptr, C.uint8_t(diag))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_diag: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetState sets the peer state.
func (p *BfdPacket) SetState(state uint8) error {
	rc := C.lr_bfd_packet_set_state(p.ptr, C.uint8_t(state))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_state: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetFlags sets the flags bitmask.
func (p *BfdPacket) SetFlags(flags uint8) error {
	rc := C.lr_bfd_packet_set_flags(p.ptr, C.uint8_t(flags))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_flags: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetDetectMult sets the detect multiplier.
func (p *BfdPacket) SetDetectMult(mult uint8) error {
	rc := C.lr_bfd_packet_set_detect_mult(p.ptr, C.uint8_t(mult))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_detect_mult: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetMyDiscriminator sets the My Discriminator field.
func (p *BfdPacket) SetMyDiscriminator(disc uint32) error {
	rc := C.lr_bfd_packet_set_my_discriminator(p.ptr, C.uint32_t(disc))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_my_discriminator: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetYourDiscriminator sets the Your Discriminator field.
func (p *BfdPacket) SetYourDiscriminator(disc uint32) error {
	rc := C.lr_bfd_packet_set_your_discriminator(p.ptr, C.uint32_t(disc))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_your_discriminator: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetDesiredMinTxInterval sets the Desired Min TX Interval (microseconds).
func (p *BfdPacket) SetDesiredMinTxInterval(interval uint32) error {
	rc := C.lr_bfd_packet_set_desired_min_tx_interval(p.ptr, C.uint32_t(interval))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_desired_min_tx_interval: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetRequiredMinRxInterval sets the Required Min RX Interval (microseconds).
func (p *BfdPacket) SetRequiredMinRxInterval(interval uint32) error {
	rc := C.lr_bfd_packet_set_required_min_rx_interval(p.ptr, C.uint32_t(interval))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_required_min_rx_interval: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// SetRequiredMinEchoInterval sets the Required Min Echo Interval.
func (p *BfdPacket) SetRequiredMinEchoInterval(interval uint32) error {
	rc := C.lr_bfd_packet_set_required_min_echo_interval(p.ptr, C.uint32_t(interval))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_required_min_echo_interval: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Encode encodes the packet to its wire form.
func (p *BfdPacket) Encode() ([]byte, error) {
	var out C.struct_lr_bytes_t
	rc := C.lr_bfd_encode(p.ptr, &out)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bfd_encode: %s (rc=%d)", LastError(), int(rc))
	}
	return copyBytes(&out), nil
}

// DecodeBfdPacket decodes one BFD Control packet from raw bytes.
func DecodeBfdPacket(data []byte) (*BfdPacket, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("DecodeBfdPacket: empty input")
	}
	var p C.lr_bfd_packet_t
	rc := C.lr_bfd_decode((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), &p)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bfd_decode: %s (rc=%d)", LastError(), int(rc))
	}
	if p == nil {
		return nil, fmt.Errorf("lr_bfd_decode: %s", LastError())
	}
	pkt := &BfdPacket{ptr: p}
	runtime.SetFinalizer(pkt, (*BfdPacket).destroy)
	return pkt, nil
}

// ---- BfdPacket auth integration (RFC 5880 §4.1 A bit) ----

// SetAuth installs (or replaces) the Authentication Section on the
// packet. The section handle is *consumed* — the boxed AuthSection
// is moved into the packet, so the caller must NOT call Free() on
// the same BfdAuthSection afterwards. Pass nil to clear the auth
// field.
func (p *BfdPacket) SetAuth(section *BfdAuthSection) error {
	var raw C.lr_bfd_auth_section_t
	if section != nil {
		raw = section.ptr
		section.ptr = nil // Take ownership on the Go side.
	}
	rc := C.lr_bfd_packet_set_auth(p.ptr, raw)
	if rc != 0 {
		return fmt.Errorf("lr_bfd_packet_set_auth: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// AuthPresent reports whether the packet carries an Authentication
// Section (RFC 5880 §4.1 A bit).
func (p *BfdPacket) AuthPresent() bool {
	return C.lr_bfd_packet_auth_present(p.ptr) != 0
}

// Auth reads a *copy* of the packet's Authentication Section. Returns
// nil when the packet has no auth section. The returned BfdAuthSection
// is owned by the caller — Free() it (or let the finalizer pick it
// up).
func (p *BfdPacket) Auth() (*BfdAuthSection, error) {
	var raw C.lr_bfd_auth_section_t
	rc := C.lr_bfd_packet_auth(p.ptr, &raw)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bfd_packet_auth: %s (rc=%d)", LastError(), int(rc))
	}
	if raw == nil {
		return nil, nil
	}
	s := &BfdAuthSection{ptr: raw}
	runtime.SetFinalizer(s, (*BfdAuthSection).destroy)
	return s, nil
}

// ---- BFD AuthType constants (RFC 5880 §8 IANA registry) ----

const (
	BFDAuthTypeSimplePassword      = C.LR_BFD_AUTH_TYPE_SIMPLE_PASSWORD
	BFDAuthTypeKeyedMd5            = C.LR_BFD_AUTH_TYPE_KEYED_MD5
	BFDAuthTypeMeticulousKeyedMd5  = C.LR_BFD_AUTH_TYPE_METICULOUS_KEYED_MD5
	BFDAuthTypeKeyedSha1           = C.LR_BFD_AUTH_TYPE_KEYED_SHA1
	BFDAuthTypeMeticulousKeyedSha1 = C.LR_BFD_AUTH_TYPE_METICULOUS_KEYED_SHA1
)

// BFD auth algorithm ids (mirror LR_BFD_AUTH_ALGO_*).
const (
	BFDAuthAlgoKeyedMd5            = C.LR_BFD_AUTH_ALGO_KEYED_MD5
	BFDAuthAlgoMeticulousKeyedMd5  = C.LR_BFD_AUTH_ALGO_METICULOUS_KEYED_MD5
	BFDAuthAlgoKeyedSha1           = C.LR_BFD_AUTH_ALGO_KEYED_SHA1
	BFDAuthAlgoMeticulousKeyedSha1 = C.LR_BFD_AUTH_ALGO_METICULOUS_KEYED_SHA1
)

// BFDAuthTypeExpectedDigestLen returns the expected digest length for
// the keyed-hash auth types (RFC 5880 §4.3 / §4.4): 16 for the MD5
// variants, 20 for the SHA1 variants. Returns -1 for Simple Password
// (variable length) and unknown types (no fixed length to validate
// against).
func BFDAuthTypeExpectedDigestLen(authType uint8) int {
	return int(C.lr_bfd_auth_type_expected_digest_len(C.uint8_t(authType)))
}

// BFDAuthTypeIsKeyedHash reports whether authType is one of the four
// keyed-hash types (KeyedMd5 / MeticulousKeyedMd5 / KeyedSha1 /
// MeticulousKeyedSha1).
func BFDAuthTypeIsKeyedHash(authType uint8) bool {
	return C.lr_bfd_auth_type_is_keyed_hash(C.uint8_t(authType)) != 0
}

// BFDAuthTypeIsMeticulous reports whether authType is one of the two
// Meticulous variants (MeticulousKeyedMd5 / MeticulousKeyedSha1).
func BFDAuthTypeIsMeticulous(authType uint8) bool {
	return C.lr_bfd_auth_type_is_meticulous(C.uint8_t(authType)) != 0
}

// ---- BfdAuthKey ----

// BfdAuthKey is an owned handle to one BFD AuthKey (RFC 5880 §4.2) —
// the per-key shared secret + key id pair.
type BfdAuthKey struct {
	ptr C.lr_bfd_auth_key_t
}

func (k *BfdAuthKey) destroy() {
	if k.ptr != nil {
		C.lr_bfd_auth_key_free(k.ptr)
		k.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (k *BfdAuthKey) Free() {
	runtime.SetFinalizer(k, nil)
	k.destroy()
}

// NewBfdAuthKey constructs an AuthKey from a raw key id and secret.
func NewBfdAuthKey(keyID uint8, secret []byte) (*BfdAuthKey, error) {
	var rawPtr C.lr_bfd_auth_key_t
	if len(secret) > 0 {
		rawPtr = C.lr_bfd_auth_key_new(C.uint8_t(keyID), (*C.uint8_t)(unsafe.Pointer(&secret[0])), C.size_t(len(secret)))
	} else {
		rawPtr = C.lr_bfd_auth_key_new(C.uint8_t(keyID), nil, 0)
	}
	if rawPtr == nil {
		return nil, fmt.Errorf("lr_bfd_auth_key_new: %s", LastError())
	}
	k := &BfdAuthKey{ptr: rawPtr}
	runtime.SetFinalizer(k, (*BfdAuthKey).destroy)
	return k, nil
}

// NewBfdAuthKeySimplePassword constructs a Simple Password AuthKey
// (RFC 5880 §4.2).
func NewBfdAuthKeySimplePassword(keyID uint8, password []byte) (*BfdAuthKey, error) {
	var rawPtr C.lr_bfd_auth_key_t
	if len(password) > 0 {
		rawPtr = C.lr_bfd_auth_key_simple_password(C.uint8_t(keyID), (*C.uint8_t)(unsafe.Pointer(&password[0])), C.size_t(len(password)))
	} else {
		rawPtr = C.lr_bfd_auth_key_simple_password(C.uint8_t(keyID), nil, 0)
	}
	if rawPtr == nil {
		return nil, fmt.Errorf("lr_bfd_auth_key_simple_password: %s", LastError())
	}
	k := &BfdAuthKey{ptr: rawPtr}
	runtime.SetFinalizer(k, (*BfdAuthKey).destroy)
	return k, nil
}

// KeyID reads the Auth Key ID.
func (k *BfdAuthKey) KeyID() uint8 {
	return uint8(C.lr_bfd_auth_key_key_id(k.ptr))
}

// DataLen reads the secret length in bytes.
func (k *BfdAuthKey) DataLen() int {
	return int(C.lr_bfd_auth_key_data_len(k.ptr))
}

// Data reads the secret bytes.
func (k *BfdAuthKey) Data() ([]byte, error) {
	n := k.DataLen()
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	var outLen C.size_t
	rc := C.lr_bfd_auth_key_data(k.ptr, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(n), &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bfd_auth_key_data: %s (rc=%d)", LastError(), int(rc))
	}
	return buf[:int(outLen)], nil
}

// ---- BfdAuthSection ----

// BfdAuthSection is an owned handle to one BFD Authentication Section
// (RFC 5880 §4.2-§4.4) — the wire form of the Authentication Section.
type BfdAuthSection struct {
	ptr C.lr_bfd_auth_section_t
}

func (s *BfdAuthSection) destroy() {
	if s.ptr != nil {
		C.lr_bfd_auth_section_free(s.ptr)
		s.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (s *BfdAuthSection) Free() {
	runtime.SetFinalizer(s, nil)
	s.destroy()
}

func newBfdAuthSection(raw C.lr_bfd_auth_section_t) *BfdAuthSection {
	s := &BfdAuthSection{ptr: raw}
	runtime.SetFinalizer(s, (*BfdAuthSection).destroy)
	return s
}

func digestPtr(b []byte) (ptr *C.uint8_t) {
	if len(b) > 0 {
		return (*C.uint8_t)(unsafe.Pointer(&b[0]))
	}
	return nil
}

// NewBfdAuthSectionSimplePassword constructs a Simple Password
// AuthSection (RFC 5880 §4.2).
func NewBfdAuthSectionSimplePassword(password []byte, keyID uint8) (*BfdAuthSection, error) {
	raw := C.lr_bfd_auth_section_simple_password(digestPtr(password), C.size_t(len(password)), C.uint8_t(keyID))
	if raw == nil {
		return nil, fmt.Errorf("lr_bfd_auth_section_simple_password: %s", LastError())
	}
	return newBfdAuthSection(raw), nil
}

// NewBfdAuthSectionKeyedMd5 constructs a Keyed MD5 AuthSection
// (RFC 5880 §4.3, type 2).
func NewBfdAuthSectionKeyedMd5(keyID uint8, sequence uint32, digest []byte) (*BfdAuthSection, error) {
	raw := C.lr_bfd_auth_section_keyed_md5(C.uint8_t(keyID), C.uint32_t(sequence), digestPtr(digest), C.size_t(len(digest)))
	if raw == nil {
		return nil, fmt.Errorf("lr_bfd_auth_section_keyed_md5: %s", LastError())
	}
	return newBfdAuthSection(raw), nil
}

// NewBfdAuthSectionMeticulousKeyedMd5 constructs a Meticulous Keyed
// MD5 AuthSection (RFC 5880 §4.3, type 3).
func NewBfdAuthSectionMeticulousKeyedMd5(keyID uint8, sequence uint32, digest []byte) (*BfdAuthSection, error) {
	raw := C.lr_bfd_auth_section_meticulous_keyed_md5(C.uint8_t(keyID), C.uint32_t(sequence), digestPtr(digest), C.size_t(len(digest)))
	if raw == nil {
		return nil, fmt.Errorf("lr_bfd_auth_section_meticulous_keyed_md5: %s", LastError())
	}
	return newBfdAuthSection(raw), nil
}

// NewBfdAuthSectionKeyedSha1 constructs a Keyed SHA1 AuthSection
// (RFC 5880 §4.4, type 4).
func NewBfdAuthSectionKeyedSha1(keyID uint8, sequence uint32, digest []byte) (*BfdAuthSection, error) {
	raw := C.lr_bfd_auth_section_keyed_sha1(C.uint8_t(keyID), C.uint32_t(sequence), digestPtr(digest), C.size_t(len(digest)))
	if raw == nil {
		return nil, fmt.Errorf("lr_bfd_auth_section_keyed_sha1: %s", LastError())
	}
	return newBfdAuthSection(raw), nil
}

// NewBfdAuthSectionMeticulousKeyedSha1 constructs a Meticulous Keyed
// SHA1 AuthSection (RFC 5880 §4.4, type 5).
func NewBfdAuthSectionMeticulousKeyedSha1(keyID uint8, sequence uint32, digest []byte) (*BfdAuthSection, error) {
	raw := C.lr_bfd_auth_section_meticulous_keyed_sha1(C.uint8_t(keyID), C.uint32_t(sequence), digestPtr(digest), C.size_t(len(digest)))
	if raw == nil {
		return nil, fmt.Errorf("lr_bfd_auth_section_meticulous_keyed_sha1: %s", LastError())
	}
	return newBfdAuthSection(raw), nil
}

// AuthType reads the auth type code (one of the BFDAuthType* constants).
func (s *BfdAuthSection) AuthType() uint8 {
	return uint8(C.lr_bfd_auth_section_auth_type(s.ptr))
}

// KeyID reads the Auth Key ID.
func (s *BfdAuthSection) KeyID() uint8 {
	return uint8(C.lr_bfd_auth_section_key_id(s.ptr))
}

// Sequence reads the sequence number, or (0, false) when the section
// has no sequence (Simple Password / unknown types).
func (s *BfdAuthSection) Sequence() (uint32, bool) {
	var seq C.uint32_t
	rc := C.lr_bfd_auth_section_sequence(s.ptr, &seq)
	if rc < 0 {
		return 0, false
	}
	return uint32(seq), rc == 1
}

// DataLen reads the data length (password / digest bytes).
func (s *BfdAuthSection) DataLen() int {
	return int(C.lr_bfd_auth_section_data_len(s.ptr))
}

// Data reads the data bytes (password / digest).
func (s *BfdAuthSection) Data() ([]byte, error) {
	n := s.DataLen()
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	var outLen C.size_t
	rc := C.lr_bfd_auth_section_data(s.ptr, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(n), &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("lr_bfd_auth_section_data: %s (rc=%d)", LastError(), int(rc))
	}
	return buf[:int(outLen)], nil
}

// WireLen reads the total wire length of the section (the Auth Len
// field value): Simple Password = 3 + password length; Keyed MD5 = 24;
// Keyed SHA1 = 28 (RFC 5880 §4.2-§4.4).
func (s *BfdAuthSection) WireLen() int {
	return int(C.lr_bfd_auth_section_wire_len(s.ptr))
}

// ---- BfdKeyedAuth ----

// BfdKeyedAuth is an owned handle to one BFD keyed-hash auth state
// (RFC 5880 §6.7 / §6.8.5).
type BfdKeyedAuth struct {
	ptr C.lr_bfd_keyed_auth_t
}

func (a *BfdKeyedAuth) destroy() {
	if a.ptr != nil {
		C.lr_bfd_keyed_auth_free(a.ptr)
		a.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (a *BfdKeyedAuth) Free() {
	runtime.SetFinalizer(a, nil)
	a.destroy()
}

// NewBfdKeyedAuth constructs a new keyed-hash auth state.
func NewBfdKeyedAuth(algorithm int32, keyID uint8, secret []byte) (*BfdKeyedAuth, error) {
	var rawPtr C.lr_bfd_keyed_auth_t
	if len(secret) > 0 {
		rawPtr = C.lr_bfd_keyed_auth_new(C.int32_t(algorithm), C.uint8_t(keyID), (*C.uint8_t)(unsafe.Pointer(&secret[0])), C.size_t(len(secret)))
	} else {
		rawPtr = C.lr_bfd_keyed_auth_new(C.int32_t(algorithm), C.uint8_t(keyID), nil, 0)
	}
	if rawPtr == nil {
		return nil, fmt.Errorf("lr_bfd_keyed_auth_new: %s", LastError())
	}
	a := &BfdKeyedAuth{ptr: rawPtr}
	runtime.SetFinalizer(a, (*BfdKeyedAuth).destroy)
	return a, nil
}

// KeyID reads the configured key ID.
func (a *BfdKeyedAuth) KeyID() uint8 {
	return uint8(C.lr_bfd_keyed_auth_key_id(a.ptr))
}

// Algorithm reads the configured algorithm id (one of the BFDAuthAlgo* constants).
func (a *BfdKeyedAuth) Algorithm() int32 {
	return int32(C.lr_bfd_keyed_auth_algorithm(a.ptr))
}

// AuthTypeValue reads the wire AuthType code corresponding to the configured algorithm.
func (a *BfdKeyedAuth) AuthTypeValue() uint8 {
	return uint8(C.lr_bfd_keyed_auth_auth_type_value(a.ptr))
}

// DigestLen reads the digest length (16 for MD5, 20 for SHA1).
func (a *BfdKeyedAuth) DigestLen() int {
	return int(C.lr_bfd_keyed_auth_digest_len(a.ptr))
}

// IsMeticulous reports whether the algorithm is one of the Meticulous variants.
func (a *BfdKeyedAuth) IsMeticulous() bool {
	return C.lr_bfd_keyed_auth_is_meticulous(a.ptr) != 0
}

// XmitSeq reads the next transmit sequence number.
func (a *BfdKeyedAuth) XmitSeq() uint32 {
	return uint32(C.lr_bfd_keyed_auth_xmit_seq(a.ptr))
}

// RcvAuthSeqKnown reports whether the receiver has seen any
// authenticated packet yet.
func (a *BfdKeyedAuth) RcvAuthSeqKnown() bool {
	return C.lr_bfd_keyed_auth_rcv_auth_seq_known(a.ptr) != 0
}

// RcvAuthSeq reads the last accepted receive sequence number.
func (a *BfdKeyedAuth) RcvAuthSeq() uint32 {
	return uint32(C.lr_bfd_keyed_auth_rcv_auth_seq(a.ptr))
}

// AdvanceXmitSeq advances the transmit sequence number circularly
// after a successful transmit.
func (a *BfdKeyedAuth) AdvanceXmitSeq() error {
	rc := C.lr_bfd_keyed_auth_advance_xmit_seq(a.ptr)
	if rc != 0 {
		return fmt.Errorf("lr_bfd_keyed_auth_advance_xmit_seq: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// AuthSectionForTx builds the wire auth section to ride the next
// outbound packet (RFC 5880 §6.7.3 / §6.7.4): the auth type, key ID,
// current transmit sequence and the shared key in the digest field.
func (a *BfdKeyedAuth) AuthSectionForTx() (*BfdAuthSection, error) {
	raw := C.lr_bfd_keyed_auth_auth_section_for_tx(a.ptr)
	if raw == nil {
		return nil, fmt.Errorf("lr_bfd_keyed_auth_auth_section_for_tx: %s", LastError())
	}
	return newBfdAuthSection(raw), nil
}

// SignPacket signs an encoded outbound BFD Control packet in place
// (RFC 5880 §6.7.3 / §6.7.4). The packet MUST be the full encoded
// packet with the auth section's digest field carrying the shared
// key (as produced by AuthSectionForTx + BfdPacket.Encode).
func (a *BfdKeyedAuth) SignPacket(packet []byte) error {
	if len(packet) == 0 {
		return fmt.Errorf("SignPacket: empty packet")
	}
	rc := C.lr_bfd_keyed_auth_sign_packet(a.ptr, (*C.uint8_t)(unsafe.Pointer(&packet[0])), C.size_t(len(packet)))
	if rc != 0 {
		return fmt.Errorf("lr_bfd_keyed_auth_sign_packet: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// VerifyInbound verifies an inbound BFD Control packet against this
// auth state (RFC 5880 §6.7.3 / §6.7.4 anti-replay + digest check).
// Returns true when the packet authenticates and the sequence number
// is within the anti-replay window (the receive state is updated in
// place); false otherwise.
func (a *BfdKeyedAuth) VerifyInbound(packet []byte, section *BfdAuthSection, detectMult uint8) (bool, error) {
	if len(packet) == 0 {
		return false, fmt.Errorf("VerifyInbound: empty packet")
	}
	if section == nil || section.ptr == nil {
		return false, fmt.Errorf("VerifyInbound: nil section")
	}
	rc := C.lr_bfd_keyed_auth_verify_inbound(a.ptr, (*C.uint8_t)(unsafe.Pointer(&packet[0])), C.size_t(len(packet)), section.ptr, C.uint8_t(detectMult))
	if rc < 0 {
		return false, fmt.Errorf("lr_bfd_keyed_auth_verify_inbound: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 1, nil
}
