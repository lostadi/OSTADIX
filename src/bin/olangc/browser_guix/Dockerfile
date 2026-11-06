FROM docker.io/library/python:3.15-slim-bookworm@sha256:4e03260adeeebafccd084f3584e6b84823aba5651cfb53ef8a078ed441ddf9cd AS build
# This is an explicit build dependency, not a package operation in the guest.
# Resulting sparse chunks are hashed into the emitted bundle; no reproducible
# apt-resolution claim is made.
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY create_disk.py state-profile.json ./
RUN python3 create_disk.py
FROM scratch AS export
COPY --from=build /out/ /
