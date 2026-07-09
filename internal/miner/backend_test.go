// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package miner

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCPUBackendRegistered ensures the CPU backend is always available
// so that operators on CPU-only builds always have a working default.
func TestCPUBackendRegistered(t *testing.T) {
	b, err := NewBackend("cpu")
	if err != nil {
		t.Fatalf("cpu backend not registered: %v", err)
	}
	defer b.Close()
	if b.Name() != "cpu" {
		t.Fatalf("expected backend name cpu, got %q", b.Name())
	}
}

// TestNewBackendUnknown verifies that requesting an unsupported backend
// returns an actionable error.
func TestNewBackendUnknown(t *testing.T) {
	if _, err := NewBackend("frobnicate"); err == nil {
		t.Fatalf("expected error for unknown backend")
	}
}

// TestNewBackendOpenCLBuildHint ensures that, on builds without the
// `opencl` tag, requesting the OpenCL backend returns a clear hint
// telling operators how to enable it.
func TestNewBackendOpenCLBuildHint(t *testing.T) {
	if _, ok := registeredBackends["opencl"]; ok {
		t.Skip("opencl backend is registered in this build")
	}
	_, err := NewBackend("opencl")
	if err == nil {
		t.Fatalf("expected error when opencl backend missing")
	}
	if !strings.Contains(err.Error(), "opencl") ||
		!strings.Contains(err.Error(), "build tag") {
		t.Fatalf("error message missing build hint: %v", err)
	}
}

// TestTargetStateV1NonceOffset locks in the byte offset of the nonce
// inside the marshaled V1 CBOR state. The OpenCL/CUDA kernels splice
// the nonce into the CBOR buffer at this offset, so a change here
// would silently break GPU mining.
func TestTargetStateV1NonceOffset(t *testing.T) {
	nonce := [16]byte{
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	}
	s := &TargetStateV1{
		Nonce:            nonce,
		BlockNumber:      1,
		CurrentHash:      bytes.Repeat([]byte{0xcc}, 32),
		LeadingZeros:     5,
		DifficultyNumber: 1234,
		EpochTime:        9999,
	}
	out, err := s.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const off = 4
	if got := out[off : off+16]; !bytes.Equal(got, nonce[:]) {
		t.Fatalf(
			"nonce not at offset %d in V1 CBOR; got %x at offset %d",
			off, got, off,
		)
	}
}

// TestTargetStateV2NonceOffset is the analogue of the V1 test for V2
// states and additionally confirms the cached-CBOR fast path keeps the
// nonce slot at the same offset.
func TestTargetStateV2NonceOffset(t *testing.T) {
	nonce := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	s := &TargetStateV2{
		Nonce:            nonce,
		MinerCredHash:    bytes.Repeat([]byte{0xab}, 32),
		EpochTime:        12345,
		BlockNumber:      42,
		CurrentHash:      bytes.Repeat([]byte{0xcd}, 32),
		LeadingZeros:     6,
		DifficultyNumber: 4567,
	}
	out, err := s.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const off = 4
	if got := out[off : off+16]; !bytes.Equal(got, nonce[:]) {
		t.Fatalf(
			"nonce not at offset %d in V2 CBOR; got %x at offset %d",
			off, got, off,
		)
	}
	// Mutate the nonce and re-marshal to ensure the cached path also
	// places it at offset 4.
	var nonce2 [16]byte
	for i := range nonce2 {
		nonce2[i] = byte(i + 1)
	}
	s.SetNonce(nonce2)
	out2, err := s.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal2: %v", err)
	}
	if got := out2[off : off+16]; !bytes.Equal(got, nonce2[:]) {
		t.Fatalf(
			"cached CBOR did not update nonce slot; got %x", got,
		)
	}
}

// TestCPUBackendDoubleSHA256 confirms that the CPU backend's hashing
// matches the canonical "double SHA-256 over the marshaled state"
// definition, which the GPU kernels also implement.
func TestCPUBackendDoubleSHA256(t *testing.T) {
	s := &TargetStateV2{
		Nonce:            [16]byte{0xde, 0xad, 0xbe, 0xef},
		MinerCredHash:    bytes.Repeat([]byte{0xab}, 32),
		EpochTime:        1,
		BlockNumber:      2,
		CurrentHash:      bytes.Repeat([]byte{0xcd}, 32),
		LeadingZeros:     0, // accept any hash on first attempt
		DifficultyNumber: 0xffffffff,
	}
	stateBytes, err := s.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	h1 := sha256.Sum256(stateBytes)
	h2 := sha256.Sum256(h1[:])

	b := &cpuBackend{}
	target := DifficultyMetrics{LeadingZeros: 0, DifficultyNumber: 0xffffffff}
	done := make(chan any)
	got, err := b.Search(s, target, done, &atomic.Uint64{})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if !bytes.Equal(got, h2[:]) {
		t.Fatalf("backend hash %x != reference %x", got, h2[:])
	}
}
