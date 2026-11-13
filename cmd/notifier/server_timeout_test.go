package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPServerAllowsFlushHandlerToFinishBeforeWriteDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/flush-pending", func(w http.ResponseWriter, _ *http.Request) {
		// Models a webhook delivery retrying until just past the old 30s
		// server write deadline, then successfully returning its response.
		time.Sleep(31 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "flushed")
	})

	// Exercise the same constructor main uses, so a regression to the old
	// 30s write deadline fails at the actual HTTP response boundary.
	srv := newHTTPServer("127.0.0.1:0", mux)
	if srv.WriteTimeout <= flushHandlerTimeout {
		t.Fatalf("server write timeout %s must exceed flush handler budget %s", srv.WriteTimeout, flushHandlerTimeout)
	}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	client := &http.Client{Timeout: 40 * time.Second}
	resp, err := client.Get("http://" + listener.Addr().String() + "/flush-pending")
	if err != nil {
		t.Fatalf("flush response failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close response: %v", err)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read flush response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "flushed" {
		t.Fatalf("flush response = %d %q, want 200 %q", resp.StatusCode, body, "flushed")
	}
}
