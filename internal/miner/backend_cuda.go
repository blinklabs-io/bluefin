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

//go:build cuda

package miner

/*
#cgo linux LDFLAGS: -L${SRCDIR} -l:cuda_kernel.o -L/usr/local/cuda/lib64 -lcudart -lstdc++
#cgo darwin LDFLAGS: -L${SRCDIR} -lcuda_kernel -lcudart -lstdc++
#include <stdint.h>

typedef struct bluefin_cuda_backend bluefin_cuda_backend;
int bluefin_cuda_create(int device, int batch_size, bluefin_cuda_backend **out);
int bluefin_cuda_search(bluefin_cuda_backend *backend, const uint8_t *state,
    int state_len, uint32_t target_lz, uint32_t target_diff, uint32_t round,
    const uint8_t *base_nonce, uint8_t *nonce, uint8_t *hash);
void bluefin_cuda_destroy(bluefin_cuda_backend *backend);
const char *bluefin_cuda_last_error(void);
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"unsafe"

	"github.com/blinklabs-io/bluefin/internal/config"
)

const defaultCUDABatchSize = 1 << 20

// Leave room for THREADS_PER_BLOCK-1 in the CUDA launch block calculation.
const maxCUDABatchSize = int64(1<<31 - 1 - (256 - 1))

func init() {
	RegisterBackend("cuda", func() (Backend, error) {
		return newCUDABackend()
	})
}

type cudaBackend struct {
	handle    *C.bluefin_cuda_backend
	batchSize int
	closed    atomic.Bool
}

func newCUDABackend() (*cudaBackend, error) {
	cfg := config.GetConfig()
	batchSize := cfg.Miner.GpuBatchSize
	if batchSize <= 0 {
		batchSize = defaultCUDABatchSize
	}
	if int64(batchSize) > maxCUDABatchSize {
		return nil, fmt.Errorf(
			"cuda batch size %d exceeds maximum supported value %d",
			batchSize,
			maxCUDABatchSize,
		)
	}
	var handle *C.bluefin_cuda_backend
	if C.bluefin_cuda_create(C.int(cfg.Miner.GpuDevice), C.int(batchSize), &handle) != 0 {
		return nil, fmt.Errorf("cuda backend initialization failed: %s", C.GoString(C.bluefin_cuda_last_error()))
	}
	b := &cudaBackend{handle: handle, batchSize: batchSize}
	slog.Info(fmt.Sprintf("cuda backend initialized: device=%d batch_size=%d", cfg.Miner.GpuDevice, batchSize))
	return b, nil
}

func (b *cudaBackend) Name() string { return "cuda" }

func (b *cudaBackend) Close() error {
	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}
	C.bluefin_cuda_destroy(b.handle)
	b.handle = nil
	return nil
}

func (b *cudaBackend) Search(
	state TargetState,
	target DifficultyMetrics,
	doneChan <-chan any,
	hashCounter *atomic.Uint64,
) ([]byte, error) {
	if b.closed.Load() {
		return nil, errors.New("cuda backend is closed")
	}
	stateBytes, err := state.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal state: %w", err)
	}
	if len(stateBytes) > maxStateLen {
		return nil, fmt.Errorf("state length %d exceeds cuda kernel limit %d", len(stateBytes), maxStateLen)
	}
	if len(stateBytes) == 0 {
		return nil, errors.New("cannot mine an empty state")
	}

	var baseNonce [16]byte
	var nonce [16]byte
	var hash [32]byte
	for round := uint32(0); ; round++ {
		select {
		case <-doneChan:
			return nil, nil
		default:
		}
		if _, err := rand.Read(baseNonce[:]); err != nil {
			return nil, err
		}
		found := C.bluefin_cuda_search(
			b.handle,
			(*C.uint8_t)(unsafe.Pointer(&stateBytes[0])),
			C.int(len(stateBytes)),
			C.uint32_t(uint32(target.LeadingZeros)),
			C.uint32_t(uint32(target.DifficultyNumber)),
			C.uint32_t(round),
			(*C.uint8_t)(unsafe.Pointer(&baseNonce[0])),
			(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
			(*C.uint8_t)(unsafe.Pointer(&hash[0])),
		)
		if found < 0 {
			return nil, fmt.Errorf("cuda search failed: %s", C.GoString(C.bluefin_cuda_last_error()))
		}
		hashCounter.Add(uint64(b.batchSize))
		if found != 0 {
			state.SetNonce(nonce)
			return hash[:], nil
		}
	}
}
