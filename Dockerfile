# Build stage. Dependencies are fetched before the source so a code change does
# not invalidate the module cache.
FROM golang:1.25-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 is why modernc.org/sqlite was chosen: it yields a statically
# linked binary with no libc dependency.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/grimoire ./cmd/server

# Prepare the directory with the right ownership; Docker carries it over when
# creating the volume. Otherwise /data would belong to root and the nonroot
# process could not write.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# Runtime stage: no shell, no package manager, nothing to patch.
# distroless/static ships the CA certificates needed for HTTPS to the IdP.
FROM gcr.io/distroless/static-debian12:nonroot

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
