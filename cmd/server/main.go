// Command promptory serves the UI and the REST API of one instance on a
// single port.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hartingsdev/solid-bassoon/internal/auth"
	"github.com/hartingsdev/solid-bassoon/internal/config"
	"github.com/hartingsdev/solid-bassoon/internal/httpapi"
	"github.com/hartingsdev/solid-bassoon/internal/store"
	"github.com/hartingsdev/solid-bassoon/web"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false,
		"prüft den laufenden Server und beendet sich mit 0 oder 1 (für Docker HEALTHCHECK)")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Start fehlgeschlagen:\n"+err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	log.Info("Instanz startet",
		"instanz", cfg.AppInstance, "titel", cfg.AppTitle,
		"adresse", cfg.ListenAddr, "datenbank", cfg.DBPath)

	st, err := store.Open(cfg.DBPath, cfg.DataEncryptionKey)
	if err != nil {
		return err
	}
	defer st.Close()

	provider, err := auth.NewProvider(cfg.OIDC, log)
	if err != nil {
		return err
	}

	static, err := staticFS(cfg.StaticDir, log)
	if err != nil {
		return err
	}
	api, err := httpapi.New(cfg, st, provider, log, static)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Discovery retries in the background: an IdP that happens to be down must
	// not put the container into a restart loop. /readyz reports not-ready
	// until it succeeds.
	go provider.Discover(ctx)
	go background(ctx, api, log)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("Server hört", "adresse", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("Beenden angefordert, laufende Anfragen werden noch bedient")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// staticFS serves the embedded UI, or a directory from disk when STATIC_DIR
// is set, so CSS and JS can be edited without recompiling.
func staticFS(dir string, log *slog.Logger) (fs.FS, error) {
	if dir == "" {
		return web.FS, nil
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("STATIC_DIR %q nicht lesbar: %w", dir, err)
	}
	log.Warn("Oberfläche wird von der Platte geladen statt aus der Binary", "verzeichnis", dir)
	return os.DirFS(dir), nil
}

func background(ctx context.Context, api *httpapi.Server, log *slog.Logger) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			api.Background(ctx, now)
		}
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// runHealthcheck probes this process. The runtime image has no shell and no
// curl, so the binary carries its own check.
func runHealthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "LISTEN_ADDR unlesbar:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Healthcheck fehlgeschlagen:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "Healthcheck lieferte Status", resp.StatusCode)
		return 1
	}
	return 0
}
