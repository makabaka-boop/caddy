// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package requestbody

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func newRequestBodySetRequest(t *testing.T) (*http.Request, *caddy.Replacer) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)

	return req.WithContext(ctx), repl
}

// TestRequestBodySetKeepsUnknownPlaceholders is a regression test for the JSON
// case: a set body is user-supplied and commonly JSON, so braces the replacer
// does not recognize must survive the expansion instead of being blanked, the
// same known-placeholder policy the respond body already follows.
func TestRequestBodySetKeepsUnknownPlaceholders(t *testing.T) {
	const jsonBody = `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`

	rb := RequestBody{Set: jsonBody}

	req, _ := newRequestBodySetRequest(t)

	var gotBody string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		gotBody = string(body)
		return nil
	})

	err := rb.ServeHTTP(httptest.NewRecorder(), req, next)
	if err != nil {
		t.Fatalf("did not expect an error, but got: %v", err)
	}

	if gotBody != jsonBody {
		t.Errorf("set body was mangled by placeholder expansion: got %q, want %q", gotBody, jsonBody)
	}
}

// TestRequestBodySetStillReplacesKnownPlaceholders guards the other direction:
// keeping unknown braces intact must not stop real placeholders from being
// replaced.
func TestRequestBodySetStillReplacesKnownPlaceholders(t *testing.T) {
	rb := RequestBody{Set: `{"token":"{caddy_request_body_test_token}"}`}
	want := `{"token":"s3cret"}`

	req, repl := newRequestBodySetRequest(t)
	repl.Set("caddy_request_body_test_token", "s3cret")

	var gotBody string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		gotBody = string(body)
		return nil
	})

	err := rb.ServeHTTP(httptest.NewRecorder(), req, next)
	if err != nil {
		t.Fatalf("did not expect an error, but got: %v", err)
	}

	if gotBody != want {
		t.Errorf("known placeholder not expanded: got %q, want %q", gotBody, want)
	}
}

// digestFieldValue builds an RFC 9530 Content-Digest member for algo over
// content using base64-encoded raw checksum bytes.
func digestFieldValue(t *testing.T, algo, content string) string {
	t.Helper()
	var sum []byte
	switch algo {
	case "sha-256":
		s := sha256.Sum256([]byte(content))
		sum = s[:]
	case "sha-512":
		s := sha512.Sum512([]byte(content))
		sum = s[:]
	default:
		t.Fatalf("unsupported test algorithm %q", algo)
	}
	return algo + "=:" + base64.StdEncoding.EncodeToString(sum) + ":"
}

func serveVerifyingRequest(t *testing.T, rb RequestBody, r *http.Request) (status int, nextCalled bool, gotBody []byte) {
	t.Helper()

	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		nextCalled = true
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		gotBody = body
		return nil
	})

	err := rb.ServeHTTP(httptest.NewRecorder(), r, next)
	if err != nil {
		handlerErr, ok := errors.AsType[caddyhttp.HandlerError](err)
		if !ok {
			t.Fatalf("expected HandlerError, got %T: %v", err, err)
		}
		return handlerErr.StatusCode, nextCalled, nil
	}
	return 0, nextCalled, gotBody
}

// TestVerifyContentDigest covers the RFC 9530 validation matrix: supported
// digests must all match, unknown algorithms are ignored, and every bad or
// missing field is rejected with 400 before later handlers run.
func TestVerifyContentDigest(t *testing.T) {
	body := "hello world"

	for _, tc := range []struct {
		name          string
		body          string
		digestHeaders []string
		otherHeaders  map[string]string
		wantStatus    int
		nextCalled    bool
	}{
		{
			name:          "sha-256 matches",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-256", body)},
			nextCalled:    true,
		},
		{
			name:          "sha-512 matches",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-512", body)},
			nextCalled:    true,
		},
		{
			name:          "both supported digests match",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-256", body) + ", " + digestFieldValue(t, "sha-512", body)},
			nextCalled:    true,
		},
		{
			name:          "digests split across header lines",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-256", body), digestFieldValue(t, "sha-512", body)},
			nextCalled:    true,
		},
		{
			name:          "unknown algorithm is ignored alongside supported one",
			body:          body,
			digestHeaders: []string{"sha-256-128=:AAAAAAAAAAAAAAAAAAAAAA==:, " + digestFieldValue(t, "sha-256", body)},
			nextCalled:    true,
		},
		{
			name:          "member parameters are tolerated",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-256", body) + ";q=1"},
			nextCalled:    true,
		},
		{
			name:          "digest of empty body matches",
			body:          "",
			digestHeaders: []string{digestFieldValue(t, "sha-256", "")},
			nextCalled:    true,
		},
		{
			name:          "digest covers raw, pre-decoding bytes",
			body:          "\x1f\x8bnot-really-gzipped",
			otherHeaders:  map[string]string{"Content-Encoding": "gzip"},
			digestHeaders: []string{digestFieldValue(t, "sha-256", "\x1f\x8bnot-really-gzipped")},
			nextCalled:    true,
		},
		{
			name:       "missing header",
			body:       body,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:          "malformed byte sequence",
			body:          body,
			digestHeaders: []string{"sha-256=:###:"},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "bare member without value",
			body:          body,
			digestHeaders: []string{"sha-256"},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "string value instead of byte sequence",
			body:          body,
			digestHeaders: []string{`sha-256="BfAj/"`},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "inner list instead of byte sequence",
			body:          body,
			digestHeaders: []string{"sha-256=(:" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + ":)"},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "digest with wrong checksum length",
			body:          body,
			digestHeaders: []string{"sha-256=:AA==:"},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "only unknown algorithms",
			body:          body,
			digestHeaders: []string{"sha-256-128=:AAAAAAAAAAAAAAAAAAAAAA==:, id-sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "sha-256 mismatch",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-256", "tampered")},
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "one matching and one mismatching digest",
			body:          body,
			digestHeaders: []string{digestFieldValue(t, "sha-256", body) + ", " + digestFieldValue(t, "sha-512", "tampered")},
			wantStatus:    http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rb := RequestBody{MaxSize: 1 << 20, VerifyContentDigest: true}

			r := httptest.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader(tc.body))
			for k, v := range tc.otherHeaders {
				r.Header.Set(k, v)
			}
			for _, v := range tc.digestHeaders {
				r.Header.Add(contentDigestHeader, v)
			}

			status, nextCalled, gotBody := serveVerifyingRequest(t, rb, r)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if nextCalled != tc.nextCalled {
				t.Errorf("next handler called = %v, want %v", nextCalled, tc.nextCalled)
			}
			if tc.nextCalled && string(gotBody) != tc.body {
				t.Errorf("downstream body = %q, want %q", gotBody, tc.body)
			}
		})
	}
}

// TestVerifyContentDigestPreservesHeaders ensures later handlers still see the
// original Content-Digest field and any other request headers.
func TestVerifyContentDigestPreservesHeaders(t *testing.T) {
	body := "hello world"
	digest := digestFieldValue(t, "sha-256", body)

	rb := RequestBody{MaxSize: 1 << 20, VerifyContentDigest: true}
	r := httptest.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader(body))
	r.Header.Set("Content-Encoding", "gzip")
	r.Header.Set(contentDigestHeader, digest)
	r.Header.Add("X-Custom", "one")
	r.Header.Add("X-Custom", "two")

	var downstream http.Header
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		downstream = req.Header.Clone()
		return nil
	})
	if err := rb.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if got := downstream.Get(contentDigestHeader); got != digest {
		t.Errorf("Content-Digest not preserved: got %q, want %q", got, digest)
	}
	if got := downstream.Values("X-Custom"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("X-Custom values not preserved: %v", got)
	}
	if got := downstream.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding not preserved: %q", got)
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (failingReadCloser) Close() error             { return nil }

// TestVerifyContentDigestSizeAndReadErrors covers 413 (declared or observed
// over the limit, including the exact-limit boundary) and 400 when the body
// cannot be read.
func TestVerifyContentDigestSizeAndReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxSize    int64
		body       string
		chunked    bool
		failRead   bool
		wantStatus int
		nextCalled bool
	}{
		{name: "body exactly at limit", maxSize: 5, body: "hello", wantStatus: 0, nextCalled: true},
		{name: "declared length over limit", maxSize: 5, body: "hello world", wantStatus: http.StatusRequestEntityTooLarge},
		{name: "undeclared length over limit", maxSize: 5, body: "hello world", chunked: true, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "body read failure", maxSize: 1 << 20, body: "hello", failRead: true, wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rb := RequestBody{MaxSize: tc.maxSize, VerifyContentDigest: true}

			var r *http.Request
			if tc.failRead {
				r = httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
				r.Body = failingReadCloser{}
				r.ContentLength = 5
			} else {
				r = httptest.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader(tc.body))
			}
			if tc.chunked {
				r.ContentLength = -1
			}
			r.Header.Set(contentDigestHeader, digestFieldValue(t, "sha-256", tc.body))

			status, nextCalled, _ := serveVerifyingRequest(t, rb, r)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if nextCalled != tc.nextCalled {
				t.Errorf("next handler called = %v, want %v", nextCalled, tc.nextCalled)
			}
		})
	}
}

// TestVerifyContentDigestIncremental verifies that requests demanding
// incremental forwarding (RFC 10036) of an actual body get 501, while
// bodyless incremental requests are still handled; the refusal takes
// precedence over a missing or bad digest field.
func TestVerifyContentDigestIncremental(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		body       string
		header     []string
		wantStatus int
		nextCalled bool
	}{
		{
			name:       "incremental body refused",
			method:     http.MethodPost,
			body:       "hello",
			header:     []string{digestFieldValue(t, "sha-256", "hello")},
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "incremental refusal precedes missing digest",
			method:     http.MethodPost,
			body:       "hello",
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "bodyless incremental request proceeds",
			method:     http.MethodGet,
			body:       "",
			header:     []string{digestFieldValue(t, "sha-256", "")},
			nextCalled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rb := RequestBody{MaxSize: 1 << 20, VerifyContentDigest: true}
			r := httptest.NewRequest(tc.method, "https://example.com/", strings.NewReader(tc.body))
			r.Header.Set("Incremental", "?1")
			for _, v := range tc.header {
				r.Header.Set(contentDigestHeader, v)
			}

			status, nextCalled, _ := serveVerifyingRequest(t, rb, r)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if nextCalled != tc.nextCalled {
				t.Errorf("next handler called = %v, want %v", nextCalled, tc.nextCalled)
			}
		})
	}
}

// TestVerifyContentDigestIgnoresTrailers verifies that a digest advertised
// only in the request's trailer section does not satisfy validation: the
// header section is still missing, so the request fails with 400.
func TestVerifyContentDigestIgnoresTrailers(t *testing.T) {
	body := "hello world"
	rb := RequestBody{MaxSize: 1 << 20, VerifyContentDigest: true}

	r := httptest.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader(body))
	r.Header.Set("Trailer", contentDigestHeader)
	r.Trailer = http.Header{contentDigestHeader: []string{digestFieldValue(t, "sha-256", body)}}

	status, nextCalled, _ := serveVerifyingRequest(t, rb, r)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
	if nextCalled {
		t.Error("next handler must not be called")
	}
}

// TestRequestBodyValidateContentDigest covers configuration constraints:
// verification needs a positive max_size and conflicts with set.
func TestRequestBodyValidateContentDigest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rb      RequestBody
		wantErr bool
	}{
		{name: "disabled with no options", rb: RequestBody{}, wantErr: false},
		{name: "enabled with positive max size", rb: RequestBody{MaxSize: 1024, VerifyContentDigest: true}, wantErr: false},
		{name: "enabled without max size", rb: RequestBody{VerifyContentDigest: true}, wantErr: true},
		{name: "enabled with zero max size", rb: RequestBody{MaxSize: 0, VerifyContentDigest: true}, wantErr: true},
		{name: "enabled with negative max size", rb: RequestBody{MaxSize: -1, VerifyContentDigest: true}, wantErr: true},
		{name: "enabled together with set", rb: RequestBody{MaxSize: 1024, Set: "body", VerifyContentDigest: true}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rb.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got none")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestParseCaddyfileContentDigest verifies Caddyfile enablement of digest
// verification.
func TestParseCaddyfileContentDigest(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		h := httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(`
		request_body {
			max_size 1MB
			verify_content_digest
		}`)}
		m, err := parseCaddyfile(h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rb := m.(*RequestBody)
		if !rb.VerifyContentDigest {
			t.Error("VerifyContentDigest not enabled by Caddyfile")
		}
		const oneMB = 1_000_000 // humanize parses SI suffixes
		if rb.MaxSize != oneMB {
			t.Errorf("MaxSize = %d, want %d", rb.MaxSize, oneMB)
		}
	})

	t.Run("unexpected argument", func(t *testing.T) {
		h := httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(`
		request_body {
			max_size 1MB
			verify_content_digest true
		}`)}
		if _, err := parseCaddyfile(h); err == nil {
			t.Error("expected argument error, got none")
		}
	})
}

// TestRequestBodySetHeaderPlaceholders verifies that HTTP request header placeholders
// resolve to an empty string when absent under ReplaceKnown, and expand to the header
// value when present, so the backend never receives literal placeholder braces.
func TestRequestBodySetHeaderPlaceholders(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setBody  string
		setupReq func(req *http.Request)
		wantBody string
	}{
		{
			name:     "absent header resolves to empty string",
			setBody:  `{"api_key":"{http.request.header.X-Api-Key}"}`,
			wantBody: `{"api_key":""}`,
		},
		{
			name:    "present header resolves to value",
			setBody: `{"api_key":"{http.request.header.X-Api-Key}"}`,
			setupReq: func(req *http.Request) {
				req.Header.Set("X-Api-Key", "secret-token")
			},
			wantBody: `{"api_key":"secret-token"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rb := RequestBody{Set: tc.setBody}

			req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
			if tc.setupReq != nil {
				tc.setupReq(req)
			}
			_ = caddyhttp.NewTestReplacer(req)

			var gotBody string
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return err
				}
				gotBody = string(body)
				return nil
			})

			err := rb.ServeHTTP(httptest.NewRecorder(), req, next)
			if err != nil {
				t.Fatalf("did not expect an error, but got: %v", err)
			}

			if gotBody != tc.wantBody {
				t.Errorf("got %q, want %q", gotBody, tc.wantBody)
			}
		})
	}
}
