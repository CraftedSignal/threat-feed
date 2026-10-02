package main

import (
	"net/http"
	"testing"
)

func TestCheckDispatchAuthAcceptsBearerToken(t *testing.T) {
	srv := &server{}
	req, err := http.NewRequest(http.MethodPost, "/dispatch", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer expected-token")

	if !srv.checkDispatchAuth(req, "expected-token") {
		t.Fatal("bearer token was rejected")
	}
}

func TestCheckDispatchAuthAcceptsDispatchTokenHeader(t *testing.T) {
	srv := &server{}
	req, err := http.NewRequest(http.MethodPost, "/flush-pending", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(dispatchTokenHeader, "expected-token")

	if !srv.checkDispatchAuth(req, "expected-token") {
		t.Fatal("dispatch token header was rejected")
	}
}

func TestCheckDispatchAuthRejectsWrongDispatchTokenHeader(t *testing.T) {
	srv := &server{}
	req, err := http.NewRequest(http.MethodPost, "/flush-pending", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(dispatchTokenHeader, "wrong-token")

	if srv.checkDispatchAuth(req, "expected-token") {
		t.Fatal("wrong dispatch token header was accepted")
	}
}
