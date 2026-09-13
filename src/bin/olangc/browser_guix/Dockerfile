FROM docker.io/library/python:3.11-slim-bookworm@sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250 AS build
# This is an explicit build dependency, not a package operation in the guest.
# Resulting sparse chunks are hashed into the emitted bundle; no reproducible
# apt-resolution claim is made.
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY create_disk.py state-profile.json ./
RUN python3 create_disk.py
FROM scratch AS export
COPY --from=build /out/ /
