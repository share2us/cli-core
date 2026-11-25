package clicore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// R2 refusals come through Cloudflare (cf-ray, Server: cloudflare); they must read as a
// storage error with R2's code, not as a Cloudflare challenge.
func TestPutUploadReportsStorageErrorsNotChallenges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("cf-ray", "abc")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match</Message></Error>`))
	}))
	defer srv.Close()
	err := NewClient("http://unused", "").PutUpload(context.Background(), PresignedUpload{URL: srv.URL}, strings.NewReader("x"), 1)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "upload_failed" || !strings.Contains(apiErr.Message, "SignatureDoesNotMatch") {
		t.Fatalf("got %v", err)
	}
}
