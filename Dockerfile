# Übersetzungsstufe. Die Abhängigkeiten werden vor dem Quelltext geholt, damit
# eine Änderung am Code den Modul-Cache nicht entwertet.
FROM golang:1.25-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 ist der Grund, warum modernc.org/sqlite gewählt wurde: dadurch
# entsteht eine statisch gelinkte Binary ohne libc-Abhängigkeit.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/prompt-library ./cmd/server

# Verzeichnis mit der richtigen Eigentümerschaft vorbereiten. Docker übernimmt
# sie beim Anlegen des Volumes — sonst gehörte /data root und der Prozess
# (nonroot) dürfte nicht schreiben.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# Laufzeitstufe: keine Shell, kein Paketmanager, nichts zu patchen.
# distroless/static bringt die CA-Zertifikate mit, die für HTTPS zum
# Anmeldedienst gebraucht werden.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/prompt-library /prompt-library
COPY --from=build --chown=nonroot:nonroot /out/data /data

USER nonroot:nonroot
WORKDIR /
EXPOSE 8080
VOLUME ["/data"]

# Das Laufzeit-Image hat kein curl; die Binary bringt die Prüfung selbst mit.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/prompt-library", "-healthcheck"]

ENTRYPOINT ["/prompt-library"]
