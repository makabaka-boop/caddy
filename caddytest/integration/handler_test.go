package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestBrowse(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		file_server browse
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	if err != nil {
		t.Fail()
		return
	}
	tester.AssertResponseCode(req, 200)
}

func TestRespondWithJSON(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	localhost {
		respond {http.request.body}
	}
  `, "caddyfile")

	res, _ := tester.AssertPostResponseBody("https://localhost:9443/",
		nil,
		bytes.NewBufferString(`{
		"greeting": "Hello, world!"
	}`), 200, `{
		"greeting": "Hello, world!"
	}`)
	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type to be application/json, but was %s", res.Header.Get("Content-Type"))
	}
}

func TestRequestBodyPlaceholderRespectsMaxSizeInTemplate(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		request_body {
			max_size 10
		}
		respond "{{placeholder \"http.request.body\"}}"
		templates
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/", bytes.NewBufferString("abcdefghijklm"))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	res := tester.AssertResponseCode(req, http.StatusRequestEntityTooLarge)
	res.Body.Close()
}

func TestRequestBodyPlaceholderRespectsMaxSizeInVarsRegexp(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		request_body {
			max_size 10
		}
		@bigbody {
			vars_regexp {http.request.body} "^.{20}"
		}
		handle @bigbody {
			respond "the body was too long matched"
		}
		respond "no match"
	}
  `, "caddyfile")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/", bytes.NewBufferString("abcdefghijklmnopqrstuvwxyz"))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	res := tester.AssertResponseCode(req, http.StatusRequestEntityTooLarge)
	res.Body.Close()
}

func TestRequestBodyPlaceholderDirectRespondExpansion(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		request_body {
			max_size 10
		}
		respond "{http.request.body}"
	}
  `, "caddyfile")

	// direct placeholder consumers expand the sanitized request-body limit
	// marker to its text instead of failing the request with 413; only the
	// templates and vars matchers propagate the 413 status
	tester.AssertPostResponseBody("http://localhost:9080/", nil, bytes.NewBufferString("abcdefghijklm"), http.StatusOK, "request body: http: request body too large")
}

func TestRequestBodyVerifyContentDigest(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}
	http://localhost:9080 {
		request_body {
			max_size 1MB
			verify_content_digest
		}
		respond "ok"
	}
  `, "caddyfile")

	content := []byte("hello world")
	sum := sha256.Sum256(content)
	validDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"

	newRequest := func(digest string, body []byte) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		if digest != "" {
			req.Header.Set("Content-Digest", digest)
		}
		return req
	}

	// a matching digest lets the request through with its body and headers intact
	res := tester.AssertResponseCode(newRequest(validDigest, content), http.StatusOK)
	res.Body.Close()

	// a mismatching digest is rejected before the handler runs
	badSum := sha256.Sum256([]byte("tampered content"))
	badDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(badSum[:]) + ":"
	res = tester.AssertResponseCode(newRequest(badDigest, content), http.StatusBadRequest)
	res.Body.Close()

	// no Content-Digest header at all
	res = tester.AssertResponseCode(newRequest("", content), http.StatusBadRequest)
	res.Body.Close()

	// a body larger than max_size is rejected with 413
	oversized := bytes.Repeat([]byte("a"), 1_000_001)
	bigSum := sha256.Sum256(oversized)
	bigDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(bigSum[:]) + ":"
	res = tester.AssertResponseCode(newRequest(bigDigest, oversized), http.StatusRequestEntityTooLarge)
	res.Body.Close()

	// an incremental request carrying a body cannot be buffered for verification
	req := newRequest(validDigest, content)
	req.Header.Set("Incremental", "?1")
	res = tester.AssertResponseCode(req, http.StatusNotImplemented)
	res.Body.Close()
}
