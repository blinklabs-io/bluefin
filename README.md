# bluefin

<div align="center">
    <img src="./assets/bluefin-logo.png" alt="bluefin Logo" width="640">
</div>

A $TUNA miner, written in Go

## Running the miner

Bluefin is self-contained and runs with no external dependencies. You can run it via
the [Docker images](https://ghcr.io/blinklabs-io/bluefin) or binaries from the
[releases page](https://github.com/blinklabs-io/bluefin/releases).

Bluefin is designed to take its configuration from environment variables. All examples below
show running the bluefin binary directly from the shell and will need to be adapted for use
with Docker.

When run with no configuration, bluefin defaults to mining TUNA v1 on `mainnet`. It will generate a new
wallet and write the seed phrase to the `seed.txt` file in the current directory.

```
$ ./bluefin
...
{"level":"info","timestamp":"2024-07-04T20:13:53-05:00","caller":"wallet/wallet.go:62","msg":"wrote generated mnemonic to seed.txt"}
{"level":"info","timestamp":"2024-07-04T20:13:53-05:00","caller":"bluefin/main.go:73","msg":"loaded mnemonic for address: addr1..."}
{"level":"info","timestamp":"2024-07-04T20:13:53-05:00","caller":"bluefin/main.go:79","msg":"starting indexer on mainnet"}
```

You can use the `NETWORK` and `PROFILE` environment variables to change the mode that bluefin operates in.
For example, to mine TUNA v2 on `preview`:

```
$ NETWORK=preview PROFILE=tuna-v2 ./bluefin
```

If you want to provide your own wallet seed phrase, you can set the `MNEMONIC` environment variable or create the `seed.txt` file before
running bluefin.

### Seeding the wallet

If allowing bluefin to generate a new wallet, you will need to seed the wallet with some initial funds using the wallet address
logged at startup. If the wallet already exists, you may need to send funds back to your own wallet so that they're visible to bluefin.
The wallet will need at least 2 available UTxOs, one to cover TX fees, and another of at least 5 (t)ADA to use as collateral.

### Submitting TXs

By default, bluefin will use the NtN (node-to-node) TxSubmission protocol to submit transactions directly to the Cardano network.
This method has the downside of not providing any feedback if a transaction fails. You can use the `SUBMIT_URL` environment variable
to specify the URL for a submit API to use instead, which will provide feedback about any transaction validation issues.

### Clearing the local data

Bluefin stores its local data in `.bluefin/` in the current directory. If you run into a problem that requires clearing the data, you can
delete this data and bluefin will re-sync from scratch.

## Development / Building

This requires Go 1.19 or better is installed. You also need `make`.

```bash
# Build
make
# Run
./bluefin
```

You can also run the code without building a binary, first
```bash
go run ./cmd/bluefin
```

## GPU mining (OpenCL and CUDA)

Bluefin can optionally mine on a GPU using OpenCL or CUDA. The GPU
backends are gated behind the `opencl` and `cuda` Go build tags so that
the default, pure-Go, `CGO_ENABLED=0` build keeps working everywhere.

### Build requirements

* A C toolchain (`build-essential` on Debian/Ubuntu).
* OpenCL headers (`opencl-headers` on Debian/Ubuntu).
* An OpenCL ICD loader development package
  (`ocl-icd-opencl-dev` on Debian/Ubuntu).

### Build the binary

```bash
make build-opencl
```

This is equivalent to:

```bash
CGO_ENABLED=1 go build -tags opencl -o bluefin ./cmd/bluefin
```

For NVIDIA GPUs, build the CUDA backend with the CUDA toolkit and `nvcc`:

```bash
make build-cuda              # RTX A400 / compute capability 8.9
make build-cuda CUDA_ARCH=86 # override for another GPU
```

The Docker image is built with both backends using `make build-gpu`.

### Runtime requirements

You need a vendor OpenCL ICD installed for your GPU at runtime:

* NVIDIA: `nvidia-opencl-icd` (ships with the NVIDIA proprietary driver).
* AMD: `mesa-opencl-icd` (open-source) or AMDGPU-PRO/ROCm OpenCL.
* Intel: `intel-opencl-icd` / NEO.

CUDA runtime libraries are required for the CUDA backend when running the
binary directly. When using Docker, run a CUDA-enabled container with
`--gpus all` and the NVIDIA Container Toolkit.

You can verify what OpenCL devices are visible with `clinfo`.

### Running with the OpenCL backend

Select the OpenCL backend at runtime via the `MINER_BACKEND` env var:

```bash
MINER_BACKEND=opencl ./bluefin
```

Other relevant env vars:

| Variable | Description | Default |
| --- | --- | --- |
| `MINER_BACKEND` | Mining backend: `auto`, `cpu`, `opencl`, or `cuda`. `auto` probes CUDA, then OpenCL, then CPU. | `auto` |
| `MINER_GPU_DEVICE` | Index of the GPU to use (0 = first). | `0` |
| `MINER_GPU_BATCH_SIZE` | Nonces per kernel dispatch. `0` = sensible default. | `0` |

If `MINER_BACKEND=opencl` is requested on a binary built **without** the
`opencl` tag, bluefin will exit with a clear error explaining how to
rebuild with GPU support.

If `MINER_BACKEND=cuda` is requested on a binary built without the `cuda`
tag, bluefin logs the configuration error and retries initialization after
two minutes. Automatic backend selection falls back to the next available
backend instead.

## WE WANT YOU!!!

We're looking for people to join this project and help get it off the ground.

Discussion is on Discord at https://discord.gg/5fPRZnX4qW
