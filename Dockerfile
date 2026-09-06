ARG CUDA_IMAGE=nvidia/cuda:12.8.1-devel-ubuntu24.04
ARG CUDA_RUNTIME_IMAGE=nvidia/cuda:12.8.1-runtime-ubuntu24.04

FROM ghcr.io/blinklabs-io/go:1.26.3-1 AS go

FROM ${CUDA_IMAGE} AS build

ENV PATH=/usr/lib/go/bin:${PATH}
COPY --from=go /usr/lib/go /usr/lib/go

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        build-essential \
        ca-certificates \
        git \
        make \
        ocl-icd-opencl-dev \
        opencl-headers \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
COPY . .
ARG CUDA_ARCH=all-major
RUN make build-gpu CUDA_ARCH=${CUDA_ARCH}

FROM ${CUDA_RUNTIME_IMAGE} AS bluefin

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        ca-certificates \
        ocl-icd-libopencl1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home bluefin \
    && mkdir -p /data \
    && chown bluefin:bluefin /data

COPY --from=build /code/bluefin /bin/
# Create data dir owned by container user and use it as default dir
VOLUME /data
WORKDIR /data
USER bluefin
ENTRYPOINT ["bluefin"]
