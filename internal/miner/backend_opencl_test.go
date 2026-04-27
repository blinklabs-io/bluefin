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

//go:build opencl

package miner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"
)

// TestOpenCLBackendEndToEnd builds a real OpenCL backend, asks it to
// solve a trivially low-difficulty target (1 leading nibble zero), and
// verifies that:
//  1. the returned hash is the double-SHA256 of the marshaled state with
//     the returned nonce spliced in at the documented CBOR offset, and
//  2. that hash actually meets the requested difficulty.
//
// The test is skipped if no OpenCL platform/device is available on the
// host (e.g. CI runners without GPUs and without a CPU ICD installed).
func TestOpenCLBackendEndToEnd(t *testing.T) {
	b, err := newOpenCLBackend()
	if err != nil {
		// Only skip when the host genuinely has no OpenCL
		// platform/device available; any other backend init error
		// (e.g. clCreateContext / build failures) should fail the
		// test so we don't mask regressions.
		if errors.Is(err, ErrNoOpenCLPlatform) || errors.Is(err, ErrNoOpenCLDevice) {
			t.Skipf("opencl backend unavailable: %v", err)
		}
		t.Fatalf("opencl backend init failed: %v", err)
	}
	defer b.Close()

	// Use a small batch so each kernel dispatch is cheap on the CPU
	// ICD used in CI.
	b.globalSize = 1 << 12

	s := &TargetStateV2{
		Nonce:            randomNonce(),
		MinerCredHash:    bytes.Repeat([]byte{0x42}, 32),
		EpochTime:        1,
		BlockNumber:      1,
		CurrentHash:      bytes.Repeat([]byte{0x37}, 32),
		LeadingZeros:     0,
		DifficultyNumber: 0,
	}
	target := DifficultyMetrics{LeadingZeros: 1, DifficultyNumber: 0xffff}

	done := make(chan any)
	defer close(done)

	hash, err := b.Search(s, target, done, &atomic.Uint64{})
	if err != nil {
		t.Fatalf("opencl search failed: %v", err)
	}
	if hash == nil {
		t.Fatalf("opencl search returned no hash")
	}

	// Recompute on the host and verify it matches.
	stateBytes, err := s.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	h1 := sha256.Sum256(stateBytes)
	h2 := sha256.Sum256(h1[:])
	if !bytes.Equal(hash, h2[:]) {
		t.Fatalf("opencl hash %x != cpu reference %x", hash, h2[:])
	}

	// And that hash should meet the requested difficulty.
	got := getDifficulty(hash)
	if !(got.LeadingZeros > target.LeadingZeros ||
		(got.LeadingZeros == target.LeadingZeros && got.DifficultyNumber < target.DifficultyNumber)) {
		t.Fatalf(
			"returned hash %x does not meet target %+v (got %+v)",
			hash, target, got,
		)
	}
}
