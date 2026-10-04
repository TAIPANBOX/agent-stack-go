# The chain verifier as a published image.
#
# Measured 2026-09-17 (agent-stack-go#64): a byte flipped on a sealed line of
# the shared events bus was seen by nothing, because `agent-conform` existed
# only as source in this repository and nothing on the box could run it. This
# image is that tool in the shape a launcher can schedule:
#
#   docker run --rm -v bus:/bus:ro -v out:/out \
#     ghcr.io/taipanbox/agent-conform:<tag> \
#     watch-dir -out /out/agent-conform.ndjson /bus
#
# The README has the compose service and the Kubernetes CronJob.
#
# Static, distroless, non-root, multi-arch. CGO off is what makes the binary
# runnable on distroless static AND what makes cross-compiling to arm64 free:
# there is no C toolchain to arrange, so the arm64 image costs the same as the
# amd64 one. The three flags on the build line are the same three invariant 11
# holds for the release binaries (CGO_ENABLED=0, -trimpath, -s -w).
#
# Base images are pinned by digest, not by tag: a tag can move under an
# operator without anyone choosing that, a digest cannot (gate:
# scripts/base-images-pinned-by-digest.sh). The two digests are the ones
# vouchryx pins today.
#
# NEEDS BUILDKIT. `$BUILDPLATFORM` is a BuildKit variable, so a legacy-builder
# `docker build` expands it to nothing and fails with "failed to parse
# platform : \"\" is an invalid OS component". BuildKit is the default in
# Docker 23+ and in Docker Desktop; a host without it needs
# `docker buildx build`, or drop the `--platform=` from the line below and
# lose only the cross-compile (arm64 then builds under emulation).

FROM --platform=$BUILDPLATFORM golang@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
# Dependencies first, so a code-only change does not re-download the module
# graph on every build.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
# TARGETARCH comes from buildx, one value per platform being built. Building
# FROM the build platform and cross-compiling, rather than emulating the
# target under QEMU, is the difference between a minute and a quarter of an
# hour.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/agent-conform ./cmd/agent-conform

FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="agent-conform"
LABEL org.opencontainers.image.description="Checks agent-passport documents and agent-event streams against the canonical schemas, and verifies the prev_hash chain of a shared events bus (watch-dir)."
LABEL org.opencontainers.image.source="https://github.com/TAIPANBOX/agent-stack-go"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/agent-conform /usr/local/bin/agent-conform
# 65532 is distroless's `nonroot` uid. Numeric on purpose: a kubelet with
# runAsNonRoot cannot verify a NAME and refuses the container outright. A
# deployment that lets it write its own stream on the bus runs it as the uid
# that owns that file (`user:` in compose, `runAsUser` in Kubernetes).
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agent-conform"]
