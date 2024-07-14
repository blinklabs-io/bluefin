// Copyright 2024 Blink Labs Software
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
	"crypto/sha256"
	"hash"
	"testing"

	sha256_simd "github.com/minio/sha256-simd"
)

// BenchmarkRandomNonce tests the performance of generating a completely new random nonce
// each iteration
func BenchmarkRandomNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		randomNonce()
	}
}

// BenchmarkRandomNonceAndIncrement tests the performance of generating a random nonce
// and incrementing each byte 255 times
func BenchmarkRandomNonceAndIncrement(b *testing.B) {
	var tmpNonce [16]byte
	for i := 0; i < b.N; i++ {
		if i%256 == 0 {
			// Generate random nonce for first and every 256 iterations
			tmpNonce = randomNonce()
		} else {
			// Increment each byte of the last nonce
			for j := 0; j < 16; j++ {
				tmpNonce[j] = byte(uint8(tmpNonce[j]) + 1)
			}
		}
	}
}

// BenchmarkSha256Builtin tests the performance of crypto/sha256
func BenchmarkSha256Builtin(b *testing.B) {
	var hasher hash.Hash
	tmpNonce := randomNonce()
	for i := 0; i < b.N; i++ {
		hasher = sha256.New()
		hasher.Write(tmpNonce[:])
		hasher.Sum(nil)
	}
}

// BenchmarkSha256Simd tests the performance github.com/minio/sha256-simd
func BenchmarkSha256Simd(b *testing.B) {
	var hasher hash.Hash
	tmpNonce := randomNonce()
	for i := 0; i < b.N; i++ {
		hasher = sha256_simd.New()
		hasher.Write(tmpNonce[:])
		hasher.Sum(nil)
	}
}
