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
	BFDStateDown       = C.LR_BFD_STATE_DOWN
	BFDStateInit       = C.LR_BFD_STATE_INIT
	BFDStateUp         = C.LR_BFD_STATE_UP
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
