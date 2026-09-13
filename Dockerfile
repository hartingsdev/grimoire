# Build stage. It runs on the BUILD platform and cross-compiles for the TARGET
# platform — pure Go with CGO_ENABLED=0 makes that free, so a multi-arch build
# needs no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
WORKDIR /src

# Dependencies before the source, so a code change does not invalidate the
# module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=

# CGO_ENABLED=0 is why modernc.org/sqlite was chosen: it yields a statically
# linked binary with no libc dependency.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/hartingsdev/grimoire/internal/buildinfo.Version=${VERSION} \
        -X github.com/hartingsdev/grimoire/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/hartingsdev/grimoire/internal/buildinfo.Date=${BUILD_DATE}" \
      -o /out/grimoire ./cmd/server

# Prepare the directory with the right ownership; Docker carries it over when
# creating the volume. Otherwise /data would belong to root and the nonroot
# process could not write.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# Runtime stage: no shell, no package manager, nothing to patch.
# distroless/static ships the CA certificates needed for HTTPS to the IdP.
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=
LABEL org.opencontainers.image.title="Grimoire" \
      org.opencontainers.image.description="Self-hosted prompt library with OIDC sign-in and a REST API" \
      org.opencontainers.image.source="https://github.com/hartingsdev/grimoire" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/grimoire /grimoire
COPY --from=build --chown=nonroot:nonroot /out/data /data

USER nonroot:nonroot
WORKDIR /
EXPOSE 8080
VOLUME ["/data"]

# The runtime image has no curl; the binary carries its own check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/grimoire", "-healthcheck"]

ENTRYPOINT ["/grimoire"]
