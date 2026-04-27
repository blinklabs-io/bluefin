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
	"log/slog"
	"sync/atomic"

	"github.com/minio/sha256-simd"
)

func init() {
	RegisterBackend("cpu", func() (Backend, error) {
		return &cpuBackend{}, nil
	})
}

// cpuBackend implements Backend using github.com/minio/sha256-simd
// running on the host CPU. This is the original (and default) mining
// backend; the GPU backends fall back to it when not available.
type cpuBackend struct{}

func (b *cpuBackend) Name() string { return "cpu" }
func (b *cpuBackend) Close() error { return nil }

func (b *cpuBackend) Search(
	state TargetState,
	target DifficultyMetrics,
	doneChan <-chan any,
	hashCounter *atomic.Uint64,
) ([]byte, error) {
	var nonceCount uint8
	for {
		// Check for shutdown
		select {
		case <-doneChan:
			return nil, nil
		default:
		}

		stateBytes, err := state.MarshalCBOR()
		if err != nil {
			slog.Error(err.Error())
			return nil, err
		}

		// Hash it once
		hasher := sha256.New()
		hasher.Write(stateBytes)
		hash := hasher.Sum(nil)

		// And hash it again
		hasher2 := sha256.New()
		hasher2.Write(hash)
		hash2 := hasher2.Sum(nil)

		// Increment hash counter
		hashCounter.Add(1)

		// Get the difficulty metrics for the hash
		metrics := getDifficulty(hash2)

		// Check the condition
		if metrics.LeadingZeros > target.LeadingZeros ||
			(metrics.LeadingZeros == target.LeadingZeros &&
				metrics.DifficultyNumber < target.DifficultyNumber) {
			return hash2, nil
		}

		// Generate a new random nonce when nonceCount rolls over, and
		// increment bytes in existing nonce otherwise
		if nonceCount == 0 {
			state.SetNonce(randomNonce())
		} else {
			nonce := state.GetNonce()
			for j := range 16 {
				nonce[j]++ //nolint:gosec
			}
			state.SetNonce(nonce)
		}
		nonceCount++
	}
}
