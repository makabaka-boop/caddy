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
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(RequestBody{})
}

// contentDigestHeader is the field carrying integrity digests of the message
// content. See RFC 9530: https://www.rfc-editor.org/rfc/rfc9530.html
const contentDigestHeader = "Content-Digest"

// contentDigestAlgorithms are the Content-Digest algorithm keys understood by
// this handler. Digests using other keys are ignored, as permitted by
// RFC 9530 section 2.
var contentDigestAlgorithms = map[string]struct {
	size int
	new  func() hash.Hash
}{
	"sha-256": {size: sha256.Size, new: sha256.New},
	"sha-512": {size: sha512.Size, new: sha512.New},
}

var (
	errIncrementalContentDigest = errors.New("cannot verify Content-Digest of an incrementally forwarded request")
	errMissingContentDigest     = errors.New("missing Content-Digest request header")
	errMalformedContentDigest   = errors.New("malformed Content-Digest request header")
	errUnsupportedContentDigest = errors.New("Content-Digest uses no supported algorithm")
	errContentDigestMismatch    = errors.New("Content-Digest does not match request content")
	errContentTooLarge          = errors.New("request body larger than the configured maximum size")
)

// RequestBody is a middleware for manipulating the request body.
type RequestBody struct {
	// The maximum number of bytes to allow reading from the body by a later handler.
	// If more bytes are read, an error with HTTP status 413 is returned.
	MaxSize int64 `json:"max_size,omitempty"`

	// This field permit to replace body on the fly
	// EXPERIMENTAL. Subject to change/removal.
	Set string `json:"set,omitempty"`

	// VerifyContentDigest enables validation of the Content-Digest request
	// header (RFC 9530) against the raw request content before later handlers
	// are invoked. It requires a positive MaxSize, within which the whole
	// body is buffered, and cannot be combined with Set. At least one of the
	// sha-256 or sha-512 digests must be present; every present digest for a
	// supported algorithm must match the content. Digests carried only in the
	// trailer section are not considered.
	VerifyContentDigest bool `json:"verify_content_digest,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (RequestBody) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.request_body",
		New: func() caddy.Module { return new(RequestBody) },
	}
}

// Validate ensures that the digest verifier is configured soundly.
func (rb RequestBody) Validate() error {
	if !rb.VerifyContentDigest {
		return nil
	}
	if rb.Set != "" {
		return errors.New("verify_content_digest cannot be used together with set")
	}
	if rb.MaxSize <= 0 {
		return errors.New("verify_content_digest requires a positive max_size")
	}
	return nil
}

func (rb RequestBody) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if rb.Set != "" {
		if r.Body != nil {
			err := r.Body.Close()
			if err != nil {
				return err
			}
		}
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		// Only known placeholders are replaced: the body is user-supplied and
		// often JSON, whose braces would otherwise be read as placeholders and
		// blanked, sending an empty body instead. This matches the respond body.
		replacedBody := repl.ReplaceKnown(rb.Set, "")
		r.Body = io.NopCloser(strings.NewReader(replacedBody))
		r.ContentLength = int64(len(replacedBody))
	}

	if rb.VerifyContentDigest {
		if err := rb.verifyContentDigest(w, r); err != nil {
			return err
		}
		return next.ServeHTTP(w, r)
	}

	if r.Body == nil {
		return next.ServeHTTP(w, r)
	}
	if rb.MaxSize > 0 {
		r.Body = errorWrapper{http.MaxBytesReader(w, r.Body, rb.MaxSize)}
	}
	return next.ServeHTTP(w, r)
}

// verifyContentDigest reads the whole request body within MaxSize and checks
// every supported digest advertised in the Content-Digest header. On success
// the body is replaced with a reader over the buffered bytes, leaving the
// request headers untouched. Digests in trailers are deliberately ignored.
func (rb RequestBody) verifyContentDigest(w http.ResponseWriter, r *http.Request) error {
	// Buffering the whole content before forwarding is incompatible with
	// incremental forwarding (RFC 10036). A bodyless request can still be
	// handled normally.
	if caddyhttp.IsIncremental(r.Header) && caddyhttp.RequestHasContent(r) {
		return caddyhttp.Error(http.StatusNotImplemented, errIncrementalContentDigest)
	}

	expected, err := parseContentDigestHeader(r.Header.Values(contentDigestHeader))
	if err != nil {
		return err
	}

	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	// A declared length over the limit can be refused before reading; the
	// MaxBytesReader still bounds dechunked or undeclared bodies.
	if r.ContentLength > rb.MaxSize {
		return caddyhttp.Error(http.StatusRequestEntityTooLarge, errContentTooLarge)
	}
	content, err := io.ReadAll(http.MaxBytesReader(w, body, rb.MaxSize))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return caddyhttp.Error(http.StatusRequestEntityTooLarge, err)
		}
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("reading request body: %w", err))
	}

	for algo, want := range expected {
		spec := contentDigestAlgorithms[algo]
		h := spec.new()
		h.Write(content)
		if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
			return caddyhttp.Error(http.StatusBadRequest, errContentDigestMismatch)
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(content))
	r.ContentLength = int64(len(content))

	return nil
}

// parseContentDigestHeader parses the Content-Digest field (an RFC 8941
// Structured Fields Dictionary) and returns the raw digests for every
// supported algorithm key. Missing, malformed, or unsupported fields are
// reported as HTTP 400 errors. Unknown algorithm keys are ignored.
func parseContentDigestHeader(values []string) (map[string][]byte, error) {
	if len(values) == 0 {
		return nil, caddyhttp.Error(http.StatusBadRequest, errMissingContentDigest)
	}

	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("%w: %v", errMalformedContentDigest, err))
	}

	expected := make(map[string][]byte)
	for _, name := range dict.Names() {
		spec, supported := contentDigestAlgorithms[name]
		if !supported {
			// unknown algorithms are ignored, even if their value is unusual
			continue
		}
		member, _ := dict.Get(name)
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("%w: digest for %q must be a byte sequence", errMalformedContentDigest, name))
		}
		digest, ok := item.Value.([]byte)
		if !ok {
			return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("%w: digest for %q must be a byte sequence", errMalformedContentDigest, name))
		}
		if len(digest) != spec.size {
			return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("%w: digest for %q must be %d bytes, got %d", errMalformedContentDigest, name, spec.size, len(digest)))
		}
		expected[name] = digest
	}

	if len(expected) == 0 {
		return nil, caddyhttp.Error(http.StatusBadRequest, errUnsupportedContentDigest)
	}

	return expected, nil
}

// errorWrapper wraps errors that are returned from Read()
// so that they can be associated with a proper status code.
type errorWrapper struct {
	io.ReadCloser
}

func (ew errorWrapper) Read(p []byte) (n int, err error) {
	n, err = ew.ReadCloser.Read(p)
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		err = caddyhttp.Error(http.StatusRequestEntityTooLarge, err)
	}
	return n, err
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*RequestBody)(nil)
	_ caddy.Validator             = (*RequestBody)(nil)
)
