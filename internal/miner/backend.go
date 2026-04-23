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
	"fmt"
	"strings"
	"sync/atomic"
)

// Backend is an interface implemented by mining backends (CPU, OpenCL,
// CUDA, ...). A Backend is responsible for running the proof-of-work
// search loop for a single worker.
//
// Implementations must:
//   - mutate state.SetNonce(...) to track the nonce currently being
//     evaluated, and leave it set to the matching nonce on success;
//   - increment hashCounter as hashes are evaluated;
//   - check doneChan periodically and return promptly (with a nil hash
//     and no error) when it is closed;
//   - return the matching double-SHA256 hash bytes when a hash meeting
//     the target difficulty is found.
type Backend interface {
	// Search runs the PoW search loop for a single worker.
	Search(
		state TargetState,
		target DifficultyMetrics,
		doneChan <-chan any,
		hashCounter *atomic.Uint64,
	) ([]byte, error)

	// Close releases any resources held by the backend (e.g. GPU
	// contexts). It is safe to call Close multiple times.
	Close() error

	// Name returns a short human-readable name for the backend
	// (e.g. "cpu", "opencl", "cuda").
	Name() string
}

// BackendFactory constructs a new Backend instance. Factories are
// registered by build-tagged backend implementations via
// RegisterBackend.
type BackendFactory func() (Backend, error)

var registeredBackends = map[string]BackendFactory{}

// RegisterBackend registers a backend factory under the given name. It
// is intended to be called from package init functions of backend
// implementations (which are typically gated by build tags).
//
// Calling RegisterBackend with a name that has already been registered
// panics; this should only happen in case of a programming error.
func RegisterBackend(name string, factory BackendFactory) {
	name = strings.ToLower(name)
	if _, ok := registeredBackends[name]; ok {
		panic(fmt.Sprintf("miner: backend %q already registered", name))
	}
	registeredBackends[name] = factory
}

// NewBackend constructs a Backend by name. Unknown or unavailable
// backends return an error explaining how to enable them.
func NewBackend(name string) (Backend, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "cpu"
	}
	factory, ok := registeredBackends[name]
	if !ok {
		switch name {
		case "opencl":
			return nil, fmt.Errorf(
				"opencl backend is not available in this build; rebuild bluefin with the 'opencl' build tag (e.g. `go build -tags opencl ./cmd/bluefin`) and ensure OpenCL headers and an ICD loader are installed",
			)
		case "cuda":
			return nil, fmt.Errorf(
				"cuda backend is not available in this build; rebuild bluefin with the 'cuda' build tag (e.g. `go build -tags cuda ./cmd/bluefin`) and ensure the CUDA toolkit is installed",
			)
		default:
			return nil, fmt.Errorf("unknown miner backend %q", name)
		}
	}
	return factory()
}

// AvailableBackends returns the names of all registered backends.
func AvailableBackends() []string {
	out := make([]string, 0, len(registeredBackends))
	for name := range registeredBackends {
		out = append(out, name)
	}
	return out
}
