# Class-A executor container (compute plane P8): the `whip executor` sidecar
# that runs sha-pinned scripts for the DO runtime (whip-executor/1 wire).
# Build context = this directory; `npm run build:executor` drops the release
# `whip` binary here first. The image digest is the environment hash the
# delta-kernel cache keys on (the image-digest wiring box).
# Ubuntu 26.04 supplies the glibc 2.43 runtime used by the supported native
# build host. Keep this digest pinned; the physical executor suite consumes
# this exact recipe instead of substituting its own compatibility image.
FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d
COPY whip /usr/local/bin/whip
EXPOSE 8080
ENTRYPOINT ["whip", "executor", "--bind", "0.0.0.0:8080"]
