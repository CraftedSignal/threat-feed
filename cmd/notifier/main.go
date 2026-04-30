// feed-notifier — public threat-feed alert subscription service.
//
// HTTP API (Cloud Run):
//
//	POST /subscribe                — start subscription, send magic-link verification
//	GET  /verify?token=…           — confirm subscription
//	GET  /unsubscribe?token=…      — remove subscription
//	POST /dispatch                 — bearer-authed; threat-feed CI POSTs new briefs here
//	GET  /healthz                  — liveness
//
// Storage: Firestore Native, collection "subscriptions".
// Email: SMTP (Workspace relay) configured via env (SMTP_*).
// Slack / Teams: incoming webhook URLs supplied by subscribers.
package main

import (
	"context"
	_ "embed"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed favicon.svg
var faviconSVG []byte

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(os.Getenv("LOG_LEVEL")),
	}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := newFirestoreStore(ctx, cfg.ProjectID)
	if err != nil {
		logger.Error("firestore init failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	mailer := newSMTPMailer(cfg.SMTP, logger)

	dispatcher := &dispatcher{
		store:  store,
		mailer: mailer,
		logger: logger,
	}

	srv := &server{
		cfg:        cfg,
		store:      store,
		mailer:     mailer,
		dispatcher: dispatcher,
		logger:     logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/subscribe", srv.handleSubscribe)
	mux.HandleFunc("/verify", srv.handleVerify)
	mux.HandleFunc("/unsubscribe", srv.handleUnsubscribe)
	mux.HandleFunc("/dispatch", srv.handleDispatch)
	// Browsers eagerly fetch /favicon.ico against any host the user
	// visits. Without a handler the LB returned 404 noise; serve the
	// same SVG the static site uses.
	mux.HandleFunc("/favicon.ico", srv.handleFavicon)
	mux.HandleFunc("/favicon.svg", srv.handleFavicon)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           withCORSAndLog(mux, cfg.SiteOrigin, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("listening", "addr", httpSrv.Addr, "site_origin", cfg.SiteOrigin)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
}

func parseLogLevel(v string) slog.Level {
	switch v {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
