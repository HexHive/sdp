# Two images from one base: eval runs the security evaluation, build also compiles
# LLVM, QEMU and the kernels. Sources live in the tree mounted at /sdp.
FROM debian:trixie-slim AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash python3 openssh-client procps \
        qemu-system-misc qemu-utils \
        libglib2.0-0t64 libpixman-1-0 libslirp0 libfdt1 libattr1 zlib1g \
        binutils-riscv64-linux-gnu pahole \
    && rm -rf /var/lib/apt/lists/*
# The drivers read symbols out of a riscv64 vmlinux and honour $NM.
ENV NM=riscv64-linux-gnu-nm SDP_ROOT=/sdp SDP_WORK=/work
WORKDIR /sdp

FROM base AS eval
CMD ["bash"]

FROM base AS build
# git/curl/ca-certificates: only this image runs scripts/fetch_upstream.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config patch python3-venv \
        git curl ca-certificates \
        libglib2.0-dev libpixman-1-dev libslirp-dev libfdt-dev libattr1-dev zlib1g-dev \
        gcc-riscv64-linux-gnu \
        bc bison flex libssl-dev libelf-dev cpio kmod rsync xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*
CMD ["bash"]
