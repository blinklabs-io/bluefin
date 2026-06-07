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

/*
#cgo CFLAGS: -DCL_TARGET_OPENCL_VERSION=120 -DCL_USE_DEPRECATED_OPENCL_1_2_APIS
#cgo linux LDFLAGS: -lOpenCL
#cgo windows LDFLAGS: -lOpenCL
#cgo darwin LDFLAGS: -framework OpenCL

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/blinklabs-io/bluefin/internal/config"
)

//go:embed opencl_kernel.cl
var openclKernelSource string

const (
	// nonceOffsetCBOR is the byte offset of the 16-byte nonce inside
	// the CBOR-encoded TUNA state. It is fixed at 4 because the state
	// is encoded as a constructor 0 wrapping an indefinite-length list
	// whose first element is the nonce bytestring; the four leading
	// bytes are constructor tag (D8 79), indef list (9F), and bytestring
	// header (50 = bytestring length 16). This matches the layout
	// assumed by TargetStateV2.MarshalCBOR's CBOR cache.
	nonceOffsetCBOR = 4

	// maxStateLen mirrors the kernel constant MAX_STATE_LEN. Real TUNA
	// states are 70-100 bytes; we leave generous headroom.
	maxStateLen = 192

	// defaultGlobalSize is the default kernel global work size when
	// MINER_GPU_BATCH_SIZE is unset. This balances throughput against
	// shutdown responsiveness.
	defaultGlobalSize = 1 << 20 // ~1M nonces / dispatch
)

// ErrNoOpenCLPlatform is returned by newOpenCLBackend when the host has
// no OpenCL platforms installed (e.g. no ICD loader or no installable
// client drivers).
var ErrNoOpenCLPlatform = errors.New("no OpenCL platforms found")

// ErrNoOpenCLDevice is returned by newOpenCLBackend when at least one
// OpenCL platform is available but no usable compute device was
// discovered on any of them.
var ErrNoOpenCLDevice = errors.New("no OpenCL devices available")

func init() {
	RegisterBackend("opencl", func() (Backend, error) {
		return newOpenCLBackend()
	})
}

// openCLBackend implements Backend on top of an OpenCL device.
//
// One backend instance owns a single device, context, command queue,
// program and kernel for its lifetime. Each call to Search reuses these
// objects, only re-uploading the changed state buffer per round.
type openCLBackend struct {
	platform   C.cl_platform_id
	device     C.cl_device_id
	context    C.cl_context
	queue      C.cl_command_queue
	program    C.cl_program
	kernel     C.cl_kernel
	deviceName string
	globalSize int
	closed     atomic.Bool
}

func newOpenCLBackend() (*openCLBackend, error) {
	cfg := config.GetConfig()

	device, platform, name, err := pickOpenCLDevice(cfg.Miner.GpuDevice)
	if err != nil {
		return nil, err
	}

	props := [3]C.cl_context_properties{
		C.CL_CONTEXT_PLATFORM,
		C.cl_context_properties(uintptr(unsafe.Pointer(platform))),
		0,
	}
	var status C.cl_int
	ctx := C.clCreateContext(
		&props[0], 1, &device, nil, nil, &status,
	)
	if status != C.CL_SUCCESS {
		return nil, fmt.Errorf("clCreateContext failed: %d", int(status))
	}

	queue := C.clCreateCommandQueue(ctx, device, 0, &status)
	if status != C.CL_SUCCESS {
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("clCreateCommandQueue failed: %d", int(status))
	}

	cSrc := C.CString(openclKernelSource)
	defer C.free(unsafe.Pointer(cSrc))
	srcLen := C.size_t(len(openclKernelSource))
	program := C.clCreateProgramWithSource(ctx, 1, &cSrc, &srcLen, &status)
	if status != C.CL_SUCCESS {
		C.clReleaseCommandQueue(queue)
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("clCreateProgramWithSource failed: %d", int(status))
	}

	if status = C.clBuildProgram(program, 1, &device, nil, nil, nil); status != C.CL_SUCCESS {
		buildLog := readBuildLog(program, device)
		C.clReleaseProgram(program)
		C.clReleaseCommandQueue(queue)
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf(
			"clBuildProgram failed (%d): %s", int(status), buildLog,
		)
	}

	kname := C.CString("tuna_search")
	defer C.free(unsafe.Pointer(kname))
	kernel := C.clCreateKernel(program, kname, &status)
	if status != C.CL_SUCCESS {
		C.clReleaseProgram(program)
		C.clReleaseCommandQueue(queue)
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("clCreateKernel failed: %d", int(status))
	}

	globalSize := defaultGlobalSize
	if cfg.Miner.GpuBatchSize > 0 {
		globalSize = cfg.Miner.GpuBatchSize
	}

	b := &openCLBackend{
		platform:   platform,
		device:     device,
		context:    ctx,
		queue:      queue,
		program:    program,
		kernel:     kernel,
		deviceName: name,
		globalSize: globalSize,
	}

	slog.Info(
		fmt.Sprintf(
			"opencl backend initialized: device=%q global_size=%d",
			name,
			globalSize,
		),
	)
	return b, nil
}

func (b *openCLBackend) Name() string { return "opencl" }

func (b *openCLBackend) Close() error {
	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}
	if b.kernel != nil {
		C.clReleaseKernel(b.kernel)
	}
	if b.program != nil {
		C.clReleaseProgram(b.program)
	}
	if b.queue != nil {
		C.clReleaseCommandQueue(b.queue)
	}
	if b.context != nil {
		C.clReleaseContext(b.context)
	}
	return nil
}

// Search dispatches batches of nonce search work to the OpenCL device
// until either a match is found or doneChan is closed.
func (b *openCLBackend) Search(
	state TargetState,
	target DifficultyMetrics,
	doneChan <-chan any,
	hashCounter *atomic.Uint64,
) ([]byte, error) {
	if b.closed.Load() {
		return nil, errors.New("opencl backend is closed")
	}

	stateBytes, err := state.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal state: %w", err)
	}
	if len(stateBytes) > maxStateLen {
		return nil, fmt.Errorf(
			"state length %d exceeds opencl kernel limit %d",
			len(stateBytes), maxStateLen,
		)
	}

	// Sanity check: the nonce in the marshaled CBOR really lives at the
	// expected offset. If it doesn't, the kernel would happily mutate
	// random bytes; refuse to mine instead.
	currNonce := state.GetNonce()
	for i := 0; i < 16; i++ {
		if stateBytes[nonceOffsetCBOR+i] != currNonce[i] {
			return nil, fmt.Errorf(
				"unexpected CBOR layout: nonce not at offset %d",
				nonceOffsetCBOR,
			)
		}
	}

	var status C.cl_int

	stateBuf := C.clCreateBuffer(
		b.context,
		C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(len(stateBytes)),
		unsafe.Pointer(&stateBytes[0]),
		&status,
	)
	if status != C.CL_SUCCESS {
		return nil, fmt.Errorf("clCreateBuffer(state) failed: %d", int(status))
	}
	defer C.clReleaseMemObject(stateBuf)

	baseNonce := make([]byte, 16)
	if _, err := rand.Read(baseNonce); err != nil {
		return nil, err
	}
	nonceBuf := C.clCreateBuffer(
		b.context,
		C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(16),
		unsafe.Pointer(&baseNonce[0]),
		&status,
	)
	if status != C.CL_SUCCESS {
		return nil, fmt.Errorf("clCreateBuffer(nonce) failed: %d", int(status))
	}
	defer C.clReleaseMemObject(nonceBuf)

	// Result layout: 13 uint32s (see kernel comment).
	const resultWords = 13
	resultHost := make([]uint32, resultWords)
	resultBuf := C.clCreateBuffer(
		b.context,
		C.CL_MEM_READ_WRITE|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(resultWords*4),
		unsafe.Pointer(&resultHost[0]),
		&status,
	)
	if status != C.CL_SUCCESS {
		return nil, fmt.Errorf("clCreateBuffer(result) failed: %d", int(status))
	}
	defer C.clReleaseMemObject(resultBuf)

	stateLen := C.cl_uint(len(stateBytes))
	targetLZ := C.cl_uint(uint32(target.LeadingZeros))       //nolint:gosec
	targetDiff := C.cl_uint(uint32(target.DifficultyNumber)) //nolint:gosec

	if err := setKernelArg(b.kernel, 0, unsafe.Sizeof(stateBuf), unsafe.Pointer(&stateBuf)); err != nil {
		return nil, err
	}
	if err := setKernelArg(b.kernel, 1, unsafe.Sizeof(stateLen), unsafe.Pointer(&stateLen)); err != nil {
		return nil, err
	}
	if err := setKernelArg(b.kernel, 2, unsafe.Sizeof(nonceBuf), unsafe.Pointer(&nonceBuf)); err != nil {
		return nil, err
	}
	// Arg 3 (round_seed) is updated per-iteration below.
	if err := setKernelArg(b.kernel, 4, unsafe.Sizeof(targetLZ), unsafe.Pointer(&targetLZ)); err != nil {
		return nil, err
	}
	if err := setKernelArg(b.kernel, 5, unsafe.Sizeof(targetDiff), unsafe.Pointer(&targetDiff)); err != nil {
		return nil, err
	}
	if err := setKernelArg(b.kernel, 6, unsafe.Sizeof(resultBuf), unsafe.Pointer(&resultBuf)); err != nil {
		return nil, err
	}

	globalSize := C.size_t(b.globalSize)
	round := C.cl_uint(0)

	for {
		select {
		case <-doneChan:
			return nil, nil
		default:
		}

		// Reset result buffer's "found" flag for this round.
		zero := C.cl_uint(0)
		if status = C.clEnqueueWriteBuffer(
			b.queue, resultBuf, C.CL_TRUE, 0, C.size_t(4),
			unsafe.Pointer(&zero), 0, nil, nil,
		); status != C.CL_SUCCESS {
			return nil, fmt.Errorf("clEnqueueWriteBuffer(result) failed: %d", int(status))
		}

		if err := setKernelArg(b.kernel, 3, unsafe.Sizeof(round), unsafe.Pointer(&round)); err != nil {
			return nil, err
		}

		if status = C.clEnqueueNDRangeKernel(
			b.queue, b.kernel, 1, nil, &globalSize, nil, 0, nil, nil,
		); status != C.CL_SUCCESS {
			return nil, fmt.Errorf("clEnqueueNDRangeKernel failed: %d", int(status))
		}
		if status = C.clFinish(b.queue); status != C.CL_SUCCESS {
			return nil, fmt.Errorf("clFinish failed: %d", int(status))
		}

		hashCounter.Add(uint64(b.globalSize))

		if status = C.clEnqueueReadBuffer(
			b.queue, resultBuf, C.CL_TRUE, 0, C.size_t(resultWords*4),
			unsafe.Pointer(&resultHost[0]), 0, nil, nil,
		); status != C.CL_SUCCESS {
			return nil, fmt.Errorf("clEnqueueReadBuffer(result) failed: %d", int(status))
		}

		if resultHost[0] != 0 {
			var nonce [16]byte
			for w := 0; w < 4; w++ {
				binary.BigEndian.PutUint32(nonce[w*4:], resultHost[1+w])
			}
			state.SetNonce(nonce)
			hash := make([]byte, 32)
			for w := 0; w < 8; w++ {
				binary.BigEndian.PutUint32(hash[w*4:], resultHost[5+w])
			}
			return hash, nil
		}

		round++
		// Periodically rotate the base nonce to avoid revisiting the
		// same (state, gid, round) tuples. Rotating every 256 rounds
		// gives 256*global_size ≈ 256M nonces between rotations, well
		// below 2^32.
		if round&0xFF == 0 {
			if _, err := rand.Read(baseNonce); err != nil {
				return nil, err
			}
			if status = C.clEnqueueWriteBuffer(
				b.queue, nonceBuf, C.CL_TRUE, 0, C.size_t(16),
				unsafe.Pointer(&baseNonce[0]), 0, nil, nil,
			); status != C.CL_SUCCESS {
				return nil, fmt.Errorf("clEnqueueWriteBuffer(nonce) failed: %d", int(status))
			}
		}
	}
}

func setKernelArg(kernel C.cl_kernel, idx C.cl_uint, size uintptr, ptr unsafe.Pointer) error {
	status := C.clSetKernelArg(kernel, idx, C.size_t(size), ptr)
	if status != C.CL_SUCCESS {
		return fmt.Errorf("clSetKernelArg(%d) failed: %d", int(idx), int(status))
	}
	return nil
}

// pickOpenCLDevice walks all platforms and returns the GPU device at
// the requested logical index (counting GPUs across platforms in order).
// If no GPU is found, it falls back to any compute device. The selected
// platform is returned alongside the device for context creation.
func pickOpenCLDevice(want int) (C.cl_device_id, C.cl_platform_id, string, error) {
	var nPlatforms C.cl_uint
	if status := C.clGetPlatformIDs(0, nil, &nPlatforms); status != C.CL_SUCCESS {
		return nil, nil, "", fmt.Errorf("clGetPlatformIDs failed: %d", int(status))
	}
	if nPlatforms == 0 {
		return nil, nil, "", ErrNoOpenCLPlatform
	}
	platforms := make([]C.cl_platform_id, nPlatforms)
	if status := C.clGetPlatformIDs(nPlatforms, &platforms[0], nil); status != C.CL_SUCCESS {
		return nil, nil, "", fmt.Errorf("clGetPlatformIDs failed: %d", int(status))
	}

	type devInfo struct {
		id       C.cl_device_id
		platform C.cl_platform_id
		name     string
	}
	var gpus, all []devInfo

	collect := func(devType C.cl_device_type, dst *[]devInfo) {
		for _, p := range platforms {
			var nDevs C.cl_uint
			st := C.clGetDeviceIDs(p, devType, 0, nil, &nDevs)
			if st != C.CL_SUCCESS || nDevs == 0 {
				continue
			}
			devs := make([]C.cl_device_id, nDevs)
			if st = C.clGetDeviceIDs(p, devType, nDevs, &devs[0], nil); st != C.CL_SUCCESS {
				continue
			}
			for _, d := range devs {
				*dst = append(*dst, devInfo{id: d, platform: p, name: getDeviceName(d)})
			}
		}
	}
	collect(C.CL_DEVICE_TYPE_GPU, &gpus)
	collect(C.CL_DEVICE_TYPE_ALL, &all)

	pool := gpus
	if len(pool) == 0 {
		pool = all
	}
	if len(pool) == 0 {
		return nil, nil, "", ErrNoOpenCLDevice
	}
	if want < 0 || want >= len(pool) {
		// If MINER_GPU_DEVICE was explicitly set out of range, log the
		// available devices for the operator.
		var lines string
		for i, d := range pool {
			lines += fmt.Sprintf("  [%d] %s\n", i, d.name)
		}
		if env := os.Getenv("MINER_GPU_DEVICE"); env != "" {
			if _, err := strconv.Atoi(env); err == nil {
				return nil, nil, "", fmt.Errorf(
					"MINER_GPU_DEVICE=%d is out of range; %d device(s) available:\n%s",
					want, len(pool), lines,
				)
			}
		}
		want = 0
	}
	d := pool[want]
	return d.id, d.platform, d.name, nil
}

func getDeviceName(d C.cl_device_id) string {
	var size C.size_t
	if C.clGetDeviceInfo(d, C.CL_DEVICE_NAME, 0, nil, &size) != C.CL_SUCCESS || size == 0 {
		return "(unknown)"
	}
	buf := make([]byte, size)
	if C.clGetDeviceInfo(d, C.CL_DEVICE_NAME, size, unsafe.Pointer(&buf[0]), nil) != C.CL_SUCCESS {
		return "(unknown)"
	}
	// Trim trailing NUL.
	if n := len(buf); n > 0 && buf[n-1] == 0 {
		buf = buf[:n-1]
	}
	return string(buf)
}

func readBuildLog(program C.cl_program, device C.cl_device_id) string {
	var size C.size_t
	if C.clGetProgramBuildInfo(
		program, device, C.CL_PROGRAM_BUILD_LOG, 0, nil, &size,
	) != C.CL_SUCCESS || size == 0 {
		return "(no build log)"
	}
	buf := make([]byte, size)
	if C.clGetProgramBuildInfo(
		program, device, C.CL_PROGRAM_BUILD_LOG, size, unsafe.Pointer(&buf[0]), nil,
	) != C.CL_SUCCESS {
		return "(no build log)"
	}
	if n := len(buf); n > 0 && buf[n-1] == 0 {
		buf = buf[:n-1]
	}
	return string(buf)
}
