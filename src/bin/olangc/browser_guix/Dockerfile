FROM docker.io/library/python:3.14-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83 AS build
# This is an explicit build dependency, not a package operation in the guest.
# Resulting sparse chunks are hashed into the emitted bundle; no reproducible
# apt-resolution claim is made.
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY create_disk.py state-profile.json ./
RUN python3 create_disk.py
FROM scratch AS export
COPY --from=build /out/ /
