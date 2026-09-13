# Supply the archive through --build-context guix-distribution=/absolute/path.
# No daemon or package installation runs in this recipe. The only Guix command
# authorizes an official substitute signing key from the verified distribution.
FROM --platform=linux/amd64 docker.io/library/python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f AS guix-distribution-unpacked
COPY --from=guix-distribution guix-binary-1.5.0.x86_64-linux.tar.xz /tmp/guix-binary.tar.xz
COPY extract-guix.py /tmp/extract-guix.py
RUN --network=none python3 /tmp/extract-guix.py /tmp/guix-binary.tar.xz /

FROM --platform=linux/amd64 docker.io/library/python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f
# Keep the binary distribution's complete store/profile closure and symlinks.
COPY --from=guix-distribution-unpacked /gnu /gnu
COPY --from=guix-distribution-unpacked /var/guix /var/guix
ENV GUILE_AUTO_COMPILE=0 LANG=C LC_ALL=C
RUN --network=none test -x /var/guix/profiles/per-user/root/current-guix/bin/guix
RUN --network=none /var/guix/profiles/per-user/root/current-guix/bin/guix archive --authorize < /gnu/store/ganla421f3g1p9rh3r68zj9djc9b807m-guix-1.5.0/share/guix/bordeaux.guix.gnu.org.pub
WORKDIR /tmp
CMD ["python3"]
