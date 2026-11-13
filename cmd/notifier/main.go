// feed-notifier - public threat-feed alert subscription service.
//
// HTTP API (Cloud Run):
//
//	POST /subscribe                - start subscription, send magic-link verification
//	GET  /verify?token=…           - confirm subscription
//	GET  /unsubscribe?token=…      - remove subscription
//	POST /dispatch                 - bearer-authed; threat-feed CI POSTs new briefs here
//	GET  /healthz                  - liveness
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

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	idleTimeout       = 60 * time.Second

	flushHandlerTimeout = 90 * time.Second
	// The longest bounded handler is /flush-pending. Leave enough time for
	// it to serialize and return its response before net/http's write deadline.
	httpResponseWriteMargin = 15 * time.Second
	httpWriteTimeout        = flushHandlerTimeout + httpResponseWriteMargin

	shutdownGracePeriod = 10 * time.Second
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

	var mailer mailer
	switch cfg.MailerBackend {
	case "gmail":
		gm, err := newGmailMailer(ctx, cfg, logger)
		if err != nil {
			logger.Error("gmail mailer init failed", "err", err)
			os.Exit(1)
		}
		mailer = gm
	default:
		mailer = newSMTPMailer(cfg.SMTP, logger)
	}

	dispatcher := &dispatcher{
		store:  store,
		mailer: mailer,
		logger: logger,
	}

	srv := &server{
		cfg:             cfg,
		store:           store,
		mailer:          mailer,
		dispatcher:      dispatcher,
		logger:          logger,
		rateLimiter:     newSubscribeRateLimiter(5, 15*time.Minute),
		recaptchaClient: &http.Client{Timeout: 10 * time.Second},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/subscribe", srv.handleSubscribe)
	mux.HandleFunc("/verify", srv.handleVerify)
	mux.HandleFunc("/unsubscribe", srv.handleUnsubscribe)
	mux.HandleFunc("/dispatch", srv.handleDispatch)
	mux.HandleFunc("/flush-pending", srv.handleFlushPending)
	// Browsers eagerly fetch /favicon.ico against any host the user
	// visits. Without a handler the LB returned 404 noise; serve the
	// same SVG the static site uses.
	mux.HandleFunc("/favicon.ico", srv.handleFavicon)
	mux.HandleFunc("/favicon.svg", srv.handleFavicon)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	handler := chain(mux,
		func(next http.Handler) http.Handler { return withRequestLog(next, logger) },
		func(next http.Handler) http.Handler { return withCORS(next, cfg.SiteOrigin) },
		withSecurityHeaders,
	)

	httpSrv := newHTTPServer(":"+port, handler)

	go func() {
		logger.Info("listening", "addr", httpSrv.Addr, "site_origin", cfg.SiteOrigin)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       idleTimeout,
	}
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
