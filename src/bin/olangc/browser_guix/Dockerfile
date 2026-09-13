FROM docker.io/library/python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f AS build
# This is an explicit build dependency, not a package operation in the guest.
# Resulting sparse chunks are hashed into the emitted bundle; no reproducible
# apt-resolution claim is made.
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY create_disk.py state-profile.json ./
RUN python3 create_disk.py
FROM scratch AS export
COPY --from=build /out/ /
