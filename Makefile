# Determine root directory
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Gather all .go files for use in dependencies below
GO_FILES=$(shell find $(ROOT_DIR) -name '*.go')

# Gather list of expected binaries
BINARIES=$(shell cd $(ROOT_DIR)/cmd && ls -1 | grep -v ^common)

# Extract Go module name from go.mod
GOMODULE=$(shell grep ^module $(ROOT_DIR)/go.mod | awk '{ print $$2 }')

# Set version strings based on git tag and current ref
GO_LDFLAGS=-ldflags "-s -w -X '$(GOMODULE)/internal/version.Version=$(shell git describe --tags --exact-match 2>/dev/null)' -X '$(GOMODULE)/internal/version.CommitHash=$(shell git rev-parse --short HEAD)'"

.PHONY: build mod-tidy clean test build-opencl

# Alias for building program binary
build: $(BINARIES)

mod-tidy:
	# Needed to fetch new dependencies and add them to go.mod
	go mod tidy

clean:
	rm -f $(BINARIES)

format: mod-tidy
	go fmt ./...
	gofmt -s -w $(GO_FILES)

golines:
	golines -w --ignore-generated --chain-split-dots --max-len=80 --reformat-tags .

test: mod-tidy
	go test -v -race ./...

bench: mod-tidy
	go test -v -bench=. ./...

# Build our program binaries
# Depends on GO_FILES to determine when rebuild is needed
$(BINARIES): mod-tidy $(GO_FILES)
	CGO_ENABLED=0 go build \
		$(GO_LDFLAGS) \
		-o $(@) \
		./cmd/$(@)

# Build with the OpenCL GPU mining backend enabled. Requires CGO, the
# OpenCL headers (e.g. `opencl-headers`), and an OpenCL ICD loader
# (e.g. `ocl-icd-opencl-dev` on Debian/Ubuntu) at build time, plus an
# OpenCL ICD for your GPU at runtime (e.g. nvidia-opencl-icd,
# mesa-opencl-icd, intel-opencl-icd, ...). To select the OpenCL backend
# at runtime, set MINER_BACKEND=opencl.
build-opencl: mod-tidy $(GO_FILES)
	CGO_ENABLED=1 go build \
		-tags opencl \
		$(GO_LDFLAGS) \
		-o bluefin \
		./cmd/bluefin
