# syntax=docker/dockerfile:1

# Keep the framework toolchain independent of any consuming application.
FROM rust:1.98.0-bookworm

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        binutils clang cmake libclang-dev libglib2.0-dev libpixman-1-dev \
        llvm-22 make ninja-build pkg-config python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

WORKDIR /workspace/GuestWeave
