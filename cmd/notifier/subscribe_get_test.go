package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Crawlers and people who open the subscribe form's action URL send GET.
// They land on the subscribe page instead of getting a 405.
func TestSubscribeGetRedirectsToSubscribePage(t *testing.T) {
	srv := &server{cfg: &config{SiteOrigin: "https://feed.example.test"}}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rr := httptest.NewRecorder()
		srv.handleSubscribe(rr, httptest.NewRequest(method, "/subscribe", nil))
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("%s /subscribe: status %d, want 303", method, rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "https://feed.example.test/subscribe/" {
			t.Fatalf("%s /subscribe: Location %q", method, got)
		}
	}
}

func TestSubscribeRejectsOtherMethods(t *testing.T) {
	srv := &server{cfg: &config{SiteOrigin: "https://feed.example.test"}}
	rr := httptest.NewRecorder()
	srv.handleSubscribe(rr, httptest.NewRequest(http.MethodPut, "/subscribe", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /subscribe: status %d, want 405", rr.Code)
	}
}
