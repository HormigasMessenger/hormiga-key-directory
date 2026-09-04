// Command keydirectory is the standalone, Kratos-anchored E2E public-key
// directory (ADR-023 + addendum). It stores and serves PUBLIC prekeys only and
// does no cryptography — X3DH/Double Ratchet run entirely on the clients.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hormigasmessenger/hormiga-key-directory/internal/api"
	"github.com/hormigasmessenger/hormiga-key-directory/internal/config"
	"github.com/hormigasmessenger/hormiga-key-directory/internal/migrate"
	"github.com/hormigasmessenger/hormiga-key-directory/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.FromEnv()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	var st store.Store
	if cfg.DevStub {
		log.Warn("using in-memory store (dev/e2e only) — data is not persisted")
		st = store.NewMemory()
	} else {
		pg, err := store.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Error("connect postgres", "err", err)
			os.Exit(1)
		}
		if cfg.AutoMigrate {
			if err := migrate.Run(ctx, pg.Pool()); err != nil {
				log.Error("migrate", "err", err)
				os.Exit(1)
			}
		}
		st = pg
	}
	defer st.Close()

	h := &api.Handlers{Store: st, MaxOPK: cfg.MaxOPKPerRequest, MaxKeyBytes: cfg.MaxKeyBytes}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Router(st, h, cfg.UserHeader, log),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info("listening", "addr", cfg.Addr, "dev_stub", cfg.DevStub)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "err", err)
	}
	log.Info("stopped")
}
