// MPLS label and label-stack codec (RFC 3032 §2.1, RFC 8277 §2.2/§2.3).
//
// This file mirrors the public Rust API of `lr_mpls::{Label, LabelStack}`
// and the C ABI surface in `lr_ffi.h` (`lr_mpls_*`). All resources are
// garbage-collected via runtime.SetFinalizer when the corresponding Go
// values leave scope, matching the rest of this package.

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

// MPLSLabel is an owned handle to a single MPLS label value with its
// Traffic-Class and TTL fields (RFC 3032 §2.1). The bottom-of-stack
// bit is NOT stored on a Label — it is positional (1 only on the last
// entry of a stack) and is therefore owned by the MPLSLabelStack
// container.
type MPLSLabel struct {
	ptr C.lr_mpls_label_t
}

// MPLSLabelSpec is a fully-specified label `(value, tc, ttl)`. Used by
// NewMPLSLabelStackFromLabels to build a stack from a flat slice of
// label specs without round-tripping through individual MPLSLabel
// handles.
type MPLSLabelSpec struct {
	Value uint32
	TC    uint8
	TTL   uint8
}

// MPLSLabelStack is an owned handle to an ordered MPLS label stack
// (RFC 3032 §2.1). The first element is the top of the stack — the
// label that is examined first when a labelled packet arrives. The
// bottom-of-stack bit is set automatically on the last entry when
// encoding and is stripped when decoding.
type MPLSLabelStack struct {
	ptr C.lr_mpls_label_stack_t
}

// NewMPLSLabel constructs a Label with default TC=0 and TTL=64 (RFC
// 3032 §2.1). Infallible — the value is masked to 20 bits on encode.
//
// Use NewMPLSLabelChecked to validate the 20-bit range up front.
func NewMPLSLabel(value uint32) *MPLSLabel {
	l := &MPLSLabel{ptr: C.lr_mpls_label_new(C.uint32_t(value))}
	runtime.SetFinalizer(l, (*MPLSLabel).destroy)
	return l
}

// NewMPLSLabelChecked constructs a Label, validating that value fits
// in the 20-bit label range (RFC 3032 §2.1). Returns an error when
// value > 0xfffff.
func NewMPLSLabelChecked(value uint32) (*MPLSLabel, error) {
	l := C.lr_mpls_label_new_checked(C.uint32_t(value))
	if l == nil {
		return nil, fmt.Errorf("lr_mpls_label_new_checked: %s", LastError())
	}
	out := &MPLSLabel{ptr: l}
	runtime.SetFinalizer(out, (*MPLSLabel).destroy)
	return out, nil
}

func (l *MPLSLabel) destroy() {
	if l.ptr != nil {
		C.lr_mpls_label_free(l.ptr)
		l.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (l *MPLSLabel) Free() {
	runtime.SetFinalizer(l, nil)
	l.destroy()
}

// WithTC returns a NEW Label with the Traffic Class set to the lower
// 3 bits of tc (RFC 5462). The receiver is consumed and freed — use
// the returned handle for subsequent reads.
func (l *MPLSLabel) WithTC(tc uint8) *MPLSLabel {
	// Take ownership of the underlying handle so the finalizer on `l`
	// does not double-free it after C consumes it.
	ptr := l.ptr
	l.ptr = nil
	runtime.SetFinalizer(l, nil)
	out := C.lr_mpls_label_with_tc(ptr, C.uint8_t(tc))
	if out == nil {
		return nil
	}
	wrapped := &MPLSLabel{ptr: out}
	runtime.SetFinalizer(wrapped, (*MPLSLabel).destroy)
	return wrapped
}

// WithTTL returns a NEW Label with the TTL set. The receiver is
// consumed and freed — use the returned handle for subsequent reads.
func (l *MPLSLabel) WithTTL(ttl uint8) *MPLSLabel {
	ptr := l.ptr
	l.ptr = nil
	runtime.SetFinalizer(l, nil)
	out := C.lr_mpls_label_with_ttl(ptr, C.uint8_t(ttl))
	if out == nil {
		return nil
	}
	wrapped := &MPLSLabel{ptr: out}
	runtime.SetFinalizer(wrapped, (*MPLSLabel).destroy)
	return wrapped
}

// Value reads the 20-bit label value.
func (l *MPLSLabel) Value() uint32 {
	return uint32(C.lr_mpls_label_value(l.ptr))
}

// TC reads the 3-bit Traffic Class.
func (l *MPLSLabel) TC() uint8 {
	return uint8(C.lr_mpls_label_tc(l.ptr))
}

// TTL reads the 8-bit TTL.
func (l *MPLSLabel) TTL() uint8 {
	return uint8(C.lr_mpls_label_ttl(l.ptr))
}

// IsReserved returns true when the label value is in the reserved
// range 0–15 (RFC 3032 §2.1).
func (l *MPLSLabel) IsReserved() bool {
	return uint8(C.lr_mpls_label_is_reserved(l.ptr)) != 0
}

// Encode3Octet encodes the label as a single 3-octet NLRI entry (RFC
// 8277 §2.2/§2.3: `Label(20) | Rsrv(3) | S(1)`, no TTL and no TC
// field). bottom sets the S bit. Returns 3 bytes.
func (l *MPLSLabel) Encode3Octet(bottom bool) ([]byte, error) {
	out := make([]byte, 3)
	rc := C.lr_mpls_label_encode_3octet(
		l.ptr,
		boolToU8(bottom),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_mpls_label_encode_3octet: %s (rc=%d)", LastError(), int(rc))
	}
	return out, nil
}

// Encode4Octet encodes the label as a single 4-octet wire entry (RFC
// 3032 §2.1: label + TC + S + TTL). bottom sets the S bit. Returns 4
// bytes.
func (l *MPLSLabel) Encode4Octet(bottom bool) ([]byte, error) {
	out := make([]byte, 4)
	rc := C.lr_mpls_label_encode_4octet(
		l.ptr,
		boolToU8(bottom),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_mpls_label_encode_4octet: %s (rc=%d)", LastError(), int(rc))
	}
	return out, nil
}

// NewMPLSLabelStack constructs an empty LabelStack (RFC 3032 §2.1).
// Useful as a builder starting point; not a valid wire value (an MPLS
// frame must carry at least one label).
func NewMPLSLabelStack() *MPLSLabelStack {
	s := &MPLSLabelStack{ptr: C.lr_mpls_label_stack_new()}
	runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
	return s
}

// NewMPLSLabelStackFromValues builds a stack from a slice of label
// values (TC=0, TTL=64).
func NewMPLSLabelStackFromValues(values []uint32) (*MPLSLabelStack, error) {
	if len(values) == 0 {
		// from_values with count=0 mirrors LabelStack::from_values([]).
		s := &MPLSLabelStack{ptr: C.lr_mpls_label_stack_new()}
		runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
		return s, nil
	}
	ptr := (*C.uint32_t)(unsafe.Pointer(&values[0]))
	out := C.lr_mpls_label_stack_from_values(ptr, C.size_t(len(values)))
	if out == nil {
		return nil, fmt.Errorf("lr_mpls_label_stack_from_values: %s", LastError())
	}
	s := &MPLSLabelStack{ptr: out}
	runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
	return s, nil
}

// NewMPLSLabelStackFromLabels builds a stack from a slice of
// fully-specified label specs.
func NewMPLSLabelStackFromLabels(labels []MPLSLabelSpec) (*MPLSLabelStack, error) {
	if len(labels) == 0 {
		s := &MPLSLabelStack{ptr: C.lr_mpls_label_stack_new()}
		runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
		return s, nil
	}
	// Build a flat C array of lr_mpls_label_spec_t.
	cSpecs := make([]C.struct_lr_mpls_label_spec_t, len(labels))
	for i, l := range labels {
		cSpecs[i].value = C.uint32_t(l.Value)
		cSpecs[i].tc = C.uint8_t(l.TC)
		cSpecs[i].ttl = C.uint8_t(l.TTL)
	}
	ptr := (*C.struct_lr_mpls_label_spec_t)(unsafe.Pointer(&cSpecs[0]))
	out := C.lr_mpls_label_stack_from_labels(ptr, C.size_t(len(labels)))
	if out == nil {
		return nil, fmt.Errorf("lr_mpls_label_stack_from_labels: %s", LastError())
	}
	s := &MPLSLabelStack{ptr: out}
	runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
	return s, nil
}

// DecodeMPLSLabelStack4Octet decodes the 4-octet-per-entry wire form
// (RFC 3032 §2.1). The S bit must mark the bottom entry only.
func DecodeMPLSLabelStack4Octet(data []byte) (*MPLSLabelStack, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("DecodeMPLSLabelStack4Octet: empty input")
	}
	var out C.lr_mpls_label_stack_t
	rc := C.lr_mpls_label_stack_decode_4octet(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&out,
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_mpls_label_stack_decode_4octet: %s (rc=%d)", LastError(), int(rc))
	}
	if out == nil {
		return nil, fmt.Errorf("lr_mpls_label_stack_decode_4octet: %s", LastError())
	}
	s := &MPLSLabelStack{ptr: out}
	runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
	return s, nil
}

// DecodeMPLSLabelStack3Octet decodes the 3-octet-per-entry NLRI form
// (RFC 8277 §2.2/§2.3).
func DecodeMPLSLabelStack3Octet(data []byte) (*MPLSLabelStack, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("DecodeMPLSLabelStack3Octet: empty input")
	}
	var out C.lr_mpls_label_stack_t
	rc := C.lr_mpls_label_stack_decode_3octet(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&out,
	)
	if rc != 0 {
		return nil, fmt.Errorf("lr_mpls_label_stack_decode_3octet: %s (rc=%d)", LastError(), int(rc))
	}
	if out == nil {
		return nil, fmt.Errorf("lr_mpls_label_stack_decode_3octet: %s", LastError())
	}
	s := &MPLSLabelStack{ptr: out}
	runtime.SetFinalizer(s, (*MPLSLabelStack).destroy)
	return s, nil
}

func (s *MPLSLabelStack) destroy() {
	if s.ptr != nil {
		C.lr_mpls_label_stack_free(s.ptr)
		s.ptr = nil
	}
}

// Free releases the handle (optional; a finalizer also runs).
func (s *MPLSLabelStack) Free() {
	runtime.SetFinalizer(s, nil)
	s.destroy()
}

// Len returns the number of labels in the stack.
func (s *MPLSLabelStack) Len() int {
	return int(C.lr_mpls_label_stack_len(s.ptr))
}

// IsEmpty returns true when the stack holds no labels.
func (s *MPLSLabelStack) IsEmpty() bool {
	return uint8(C.lr_mpls_label_stack_is_empty(s.ptr)) != 0
}

// At returns the label at the given index as a fully-specified
// (value, tc, ttl) spec. Returns an error when index is out of range.
func (s *MPLSLabelStack) At(index int) (MPLSLabelSpec, error) {
	var v C.uint32_t
	var tc, ttl C.uint8_t
	rc := C.lr_mpls_label_stack_at(
		s.ptr,
		C.size_t(index),
		&v,
		&tc,
		&ttl,
	)
	if rc != 0 {
		return MPLSLabelSpec{}, fmt.Errorf("lr_mpls_label_stack_at: %s (rc=%d)", LastError(), int(rc))
	}
	return MPLSLabelSpec{
		Value: uint32(v),
		TC:    uint8(tc),
		TTL:   uint8(ttl),
	}, nil
}

// Labels returns the full slice of label specs in stack order
// (top first).
func (s *MPLSLabelStack) Labels() ([]MPLSLabelSpec, error) {
	n := s.Len()
	out := make([]MPLSLabelSpec, n)
	for i := 0; i < n; i++ {
		spec, err := s.At(i)
		if err != nil {
			return nil, err
		}
		out[i] = spec
	}
	return out, nil
}

// Push pushes a label onto the top of the stack (the label examined
// first when a labelled packet arrives). The label handle is
// consumed and freed.
func (s *MPLSLabelStack) Push(label *MPLSLabel) error {
	if label == nil {
		return fmt.Errorf("MPLSLabelStack.Push: nil label")
	}
	// Take ownership so label's finalizer does not double-free after
	// the C call consumes it.
	ptr := label.ptr
	label.ptr = nil
	runtime.SetFinalizer(label, nil)
	rc := C.lr_mpls_label_stack_push(s.ptr, ptr)
	if rc != 0 {
		return fmt.Errorf("lr_mpls_label_stack_push: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// PushBottom pushes a label onto the bottom of the stack (last to be
// examined). The label handle is consumed and freed.
func (s *MPLSLabelStack) PushBottom(label *MPLSLabel) error {
	if label == nil {
		return fmt.Errorf("MPLSLabelStack.PushBottom: nil label")
	}
	ptr := label.ptr
	label.ptr = nil
	runtime.SetFinalizer(label, nil)
	rc := C.lr_mpls_label_stack_push_bottom(s.ptr, ptr)
	if rc != 0 {
		return fmt.Errorf("lr_mpls_label_stack_push_bottom: %s (rc=%d)", LastError(), int(rc))
	}
	return nil
}

// Pop removes and drops the top label. Returns true when a label was
// popped, false when the stack was already empty.
func (s *MPLSLabelStack) Pop() (bool, error) {
	rc := C.lr_mpls_label_stack_pop(s.ptr)
	if rc < 0 {
		return false, fmt.Errorf("lr_mpls_label_stack_pop: %s (rc=%d)", LastError(), int(rc))
	}
	return rc == 1, nil
}

// Encode4Octet encodes the stack as the 4-octet-per-entry wire form
// (RFC 3032 §2.1). The S bit is set on the last entry.
func (s *MPLSLabelStack) Encode4Octet() ([]byte, error) {
	var out C.struct_lr_bytes_t
	rc := C.lr_mpls_label_stack_encode_4octet(s.ptr, &out)
	if rc != 0 {
		return nil, fmt.Errorf("lr_mpls_label_stack_encode_4octet: %s (rc=%d)", LastError(), int(rc))
	}
	return copyBytes(&out), nil
}

// Encode3Octet encodes the stack as the 3-octet-per-entry NLRI form
// (RFC 8277 §2.2/§2.3).
func (s *MPLSLabelStack) Encode3Octet() ([]byte, error) {
	var out C.struct_lr_bytes_t
	rc := C.lr_mpls_label_stack_encode_3octet(s.ptr, &out)
	if rc != 0 {
		return nil, fmt.Errorf("lr_mpls_label_stack_encode_3octet: %s (rc=%d)", LastError(), int(rc))
	}
	return copyBytes(&out), nil
}
