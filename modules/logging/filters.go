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

package logging

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/internal"
)

func init() {
	caddy.RegisterModule(DeleteFilter{})
	caddy.RegisterModule(HashFilter{})
	caddy.RegisterModule(ReplaceFilter{})
	caddy.RegisterModule(IPMaskFilter{})
	caddy.RegisterModule(QueryFilter{})
	caddy.RegisterModule(CookieFilter{})
	caddy.RegisterModule(SetCookieFilter{})
	caddy.RegisterModule(RegexpFilter{})
	caddy.RegisterModule(RenameFilter{})
	caddy.RegisterModule(MultiRegexpFilter{})
	caddy.RegisterModule(JSONRedactFilter{})
}

// LogFieldFilter can filter (or manipulate)
// a field in a log entry.
type LogFieldFilter interface {
	Filter(zapcore.Field) zapcore.Field
}

// DeleteFilter is a Caddy log field filter that
// deletes the field.
type DeleteFilter struct{}

// CaddyModule returns the Caddy module information.
func (DeleteFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.delete",
		New: func() caddy.Module { return new(DeleteFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (DeleteFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Filter filters the input field.
func (DeleteFilter) Filter(in zapcore.Field) zapcore.Field {
	in.Type = zapcore.SkipType
	return in
}

// hash returns the first 4 bytes of the SHA-256 hash of the given data as hexadecimal
func hash(s string) string {
	return fmt.Sprintf("%.4x", sha256.Sum256([]byte(s)))
}

// HashFilter is a Caddy log field filter that
// replaces the field with the initial 4 bytes
// of the SHA-256 hash of the content. Operates
// on string fields, or on arrays of strings
// where each string is hashed.
type HashFilter struct{}

// CaddyModule returns the Caddy module information.
func (HashFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.hash",
		New: func() caddy.Module { return new(HashFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *HashFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Filter filters the input field with the replacement value.
func (f *HashFilter) Filter(in zapcore.Field) zapcore.Field {
	if array, ok := in.Interface.(internal.LoggableStringArray); ok {
		newArray := make(internal.LoggableStringArray, len(array))
		for i, s := range array {
			newArray[i] = hash(s)
		}
		in.Interface = newArray
	} else {
		in.String = hash(in.String)
	}

	return in
}

// ReplaceFilter is a Caddy log field filter that
// replaces the field with the indicated string.
type ReplaceFilter struct {
	Value string `json:"value,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ReplaceFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.replace",
		New: func() caddy.Module { return new(ReplaceFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *ReplaceFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	if d.NextArg() {
		f.Value = d.Val()
	}
	return nil
}

// Filter filters the input field with the replacement value.
func (f *ReplaceFilter) Filter(in zapcore.Field) zapcore.Field {
	in.Type = zapcore.StringType
	in.String = f.Value
	return in
}

// IPMaskFilter is a Caddy log field filter that
// masks IP addresses in a string, or in an array
// of strings. The string may be a comma separated
// list of IP addresses, where all of the values
// will be masked.
type IPMaskFilter struct {
	// The IPv4 mask, as a subnet size CIDR.
	IPv4MaskRaw int `json:"ipv4_cidr,omitempty"`

	// The IPv6 mask, as a subnet size CIDR.
	IPv6MaskRaw int `json:"ipv6_cidr,omitempty"`

	v4Mask net.IPMask
	v6Mask net.IPMask
}

// CaddyModule returns the Caddy module information.
func (IPMaskFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.ip_mask",
		New: func() caddy.Module { return new(IPMaskFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *IPMaskFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name

	args := d.RemainingArgs()
	if len(args) > 2 {
		return d.Errf("too many arguments")
	}
	if len(args) > 0 {
		val, err := strconv.Atoi(args[0])
		if err != nil {
			return d.Errf("error parsing %s: %v", args[0], err)
		}
		m.IPv4MaskRaw = val

		if len(args) > 1 {
			val, err := strconv.Atoi(args[1])
			if err != nil {
				return d.Errf("error parsing %s: %v", args[1], err)
			}
			m.IPv6MaskRaw = val
		}
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "ipv4":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("error parsing %s: %v", d.Val(), err)
			}
			m.IPv4MaskRaw = val

		case "ipv6":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("error parsing %s: %v", d.Val(), err)
			}
			m.IPv6MaskRaw = val

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}
	return nil
}

// Provision parses m's IP masks, from integers.
func (m *IPMaskFilter) Provision(ctx caddy.Context) error {
	if m.IPv4MaskRaw < 0 || m.IPv4MaskRaw > 32 {
		return fmt.Errorf("invalid IPv4 mask: %d (must be between 0 and 32)", m.IPv4MaskRaw)
	}
	if m.IPv6MaskRaw < 0 || m.IPv6MaskRaw > 128 {
		return fmt.Errorf("invalid IPv6 mask: %d (must be between 0 and 128)", m.IPv6MaskRaw)
	}

	parseRawToMask := func(rawField int, bitLen int) net.IPMask {
		if rawField == 0 {
			return nil
		}

		// we assume the int is a subnet size CIDR
		// e.g. "16" being equivalent to masking the last
		// two bytes of an ipv4 address, like "255.255.0.0"
		return net.CIDRMask(rawField, bitLen)
	}

	m.v4Mask = parseRawToMask(m.IPv4MaskRaw, 32)
	m.v6Mask = parseRawToMask(m.IPv6MaskRaw, 128)

	return nil
}

// Filter filters the input field.
func (m IPMaskFilter) Filter(in zapcore.Field) zapcore.Field {
	if array, ok := in.Interface.(internal.LoggableStringArray); ok {
		newArray := make(internal.LoggableStringArray, len(array))
		for i, s := range array {
			newArray[i] = m.mask(s)
		}
		in.Interface = newArray
	} else {
		in.String = m.mask(in.String)
	}

	return in
}

func (m IPMaskFilter) mask(s string) string {
	parts := make([]string, 0)
	for value := range strings.SplitSeq(s, ",") {
		value = strings.TrimSpace(value)
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			host = value // assume whole thing was IP address
		}
		ipAddr := net.ParseIP(host)
		if ipAddr == nil {
			parts = append(parts, value)
			continue
		}
		mask := m.v4Mask
		if ipAddr.To4() == nil {
			mask = m.v6Mask
		}
		masked := ipAddr.Mask(mask)
		if port == "" {
			parts = append(parts, masked.String())
			continue
		}

		parts = append(parts, net.JoinHostPort(masked.String(), port))
	}
	return strings.Join(parts, ", ")
}

type filterAction string

const (
	// Replace value(s).
	replaceAction filterAction = "replace"

	// Hash value(s).
	hashAction filterAction = "hash"

	// Delete.
	deleteAction filterAction = "delete"
)

func (a filterAction) IsValid() error {
	switch a {
	case replaceAction, deleteAction, hashAction:
		return nil
	}

	return errors.New("invalid action type")
}

type queryFilterAction struct {
	// `replace` to replace the value(s) associated with the parameter(s), `hash` to replace them with the 4 initial bytes of the SHA-256 of their content or `delete` to remove them entirely.
	Type filterAction `json:"type"`

	// The name of the query parameter.
	Parameter string `json:"parameter"`

	// The value to use as replacement if the action is `replace`.
	Value string `json:"value,omitempty"`
}

// QueryFilter is a Caddy log field filter that filters
// query parameters from a URL.
//
// This filter updates the logged URL string to remove, replace or hash
// query parameters containing sensitive data. For instance, it can be
// used to redact any kind of secrets which were passed as query parameters,
// such as OAuth access tokens, session IDs, magic link tokens, etc.
type QueryFilter struct {
	// A list of actions to apply to the query parameters of the URL.
	Actions []queryFilterAction `json:"actions"`
}

// Validate checks that action types are correct.
func (f *QueryFilter) Validate() error {
	for _, a := range f.Actions {
		if err := a.Type.IsValid(); err != nil {
			return err
		}
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (QueryFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.query",
		New: func() caddy.Module { return new(QueryFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *QueryFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	for d.NextBlock(0) {
		qfa := queryFilterAction{}
		switch d.Val() {
		case "replace":
			if !d.NextArg() {
				return d.ArgErr()
			}

			qfa.Type = replaceAction
			qfa.Parameter = d.Val()

			if !d.NextArg() {
				return d.ArgErr()
			}
			qfa.Value = d.Val()

		case "hash":
			if !d.NextArg() {
				return d.ArgErr()
			}

			qfa.Type = hashAction
			qfa.Parameter = d.Val()

		case "delete":
			if !d.NextArg() {
				return d.ArgErr()
			}

			qfa.Type = deleteAction
			qfa.Parameter = d.Val()

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}

		m.Actions = append(m.Actions, qfa)
	}
	return nil
}

// Filter filters the input field.
func (m QueryFilter) Filter(in zapcore.Field) zapcore.Field {
	if array, ok := in.Interface.(internal.LoggableStringArray); ok {
		newArray := make(internal.LoggableStringArray, len(array))
		for i, s := range array {
			newArray[i] = m.processQueryString(s)
		}
		in.Interface = newArray
	} else {
		in.String = m.processQueryString(in.String)
	}

	return in
}

func (m QueryFilter) processQueryString(s string) string {
	parse := url.Parse
	if strings.HasPrefix(s, "/") {
		// parse a request-target like the server does. Browsers and most
		// clients strip a #fragment before sending, but a client that
		// sends a raw '#' has it kept in the query by the server
		// (url.ParseRequestURI does not split it off), so filter it too
		parse = url.ParseRequestURI
	}
	u, err := parse(s)
	if err != nil {
		return s
	}

	q := u.Query()
	for _, a := range m.Actions {
		switch a.Type {
		case replaceAction:
			for i := range q[a.Parameter] {
				q[a.Parameter][i] = a.Value
			}

		case hashAction:
			for i := range q[a.Parameter] {
				q[a.Parameter][i] = hash(q[a.Parameter][i])
			}

		case deleteAction:
			q.Del(a.Parameter)
		}
	}

	u.RawQuery = q.Encode()
	return u.String()
}

type cookieFilterAction struct {
	// `replace` to replace the value of the cookie, `hash` to replace it with the 4 initial bytes of the SHA-256 of its content or `delete` to remove it entirely.
	Type filterAction `json:"type"`

	// The name of the cookie.
	Name string `json:"name"`

	// The value to use as replacement if the action is `replace`.
	Value string `json:"value,omitempty"`
}

// CookieFilter is a Caddy log field filter that filters
// cookies.
//
// This filter updates the logged HTTP header string
// to remove, replace or hash cookies containing sensitive data. For instance,
// it can be used to redact any kind of secrets, such as session IDs.
//
// If several actions are configured for the same cookie name, only the first
// will be applied.
type CookieFilter struct {
	// A list of actions to apply to the cookies.
	Actions []cookieFilterAction `json:"actions"`
}

// Validate checks that action types are correct.
func (f *CookieFilter) Validate() error {
	for _, a := range f.Actions {
		if err := a.Type.IsValid(); err != nil {
			return err
		}
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (CookieFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.cookie",
		New: func() caddy.Module { return new(CookieFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *CookieFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	for d.NextBlock(0) {
		cfa := cookieFilterAction{}
		switch d.Val() {
		case "replace":
			if !d.NextArg() {
				return d.ArgErr()
			}

			cfa.Type = replaceAction
			cfa.Name = d.Val()

			if !d.NextArg() {
				return d.ArgErr()
			}
			cfa.Value = d.Val()

		case "hash":
			if !d.NextArg() {
				return d.ArgErr()
			}

			cfa.Type = hashAction
			cfa.Name = d.Val()

		case "delete":
			if !d.NextArg() {
				return d.ArgErr()
			}

			cfa.Type = deleteAction
			cfa.Name = d.Val()

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}

		m.Actions = append(m.Actions, cfa)
	}
	return nil
}

// Filter filters the input field.
func (m CookieFilter) Filter(in zapcore.Field) zapcore.Field {
	cookiesSlice, ok := in.Interface.(internal.LoggableStringArray)
	if !ok {
		return in
	}

	// using a dummy Request to make use of the Cookies() function to parse it
	originRequest := http.Request{Header: http.Header{"Cookie": cookiesSlice}}
	cookies := originRequest.Cookies()
	transformedRequest := http.Request{Header: make(http.Header)}

OUTER:
	for _, c := range cookies {
		for _, a := range m.Actions {
			if c.Name != a.Name {
				continue
			}

			switch a.Type {
			case replaceAction:
				c.Value = a.Value
				transformedRequest.AddCookie(c)
				continue OUTER

			case hashAction:
				c.Value = hash(c.Value)
				transformedRequest.AddCookie(c)
				continue OUTER

			case deleteAction:
				continue OUTER
			}
		}

		transformedRequest.AddCookie(c)
	}

	in.Interface = internal.LoggableStringArray(transformedRequest.Header["Cookie"])

	return in
}

// SetCookieFilter is a Caddy log field filter that filters
// Set-Cookie header values.
//
// This filter updates logged Set-Cookie header values to remove,
// replace or hash cookies containing sensitive data while preserving
// the original attribute suffix verbatim.
//
// It is typically used with access log fields such as
// "resp_headers>Set-Cookie".
//
// If several actions are configured for the same cookie name, only the first
// will be applied.
type SetCookieFilter struct {
	// A list of actions to apply to the Set-Cookie values.
	Actions []cookieFilterAction `json:"actions"`
}

// Validate checks that action types are correct.
func (f *SetCookieFilter) Validate() error {
	for _, a := range f.Actions {
		if err := a.Type.IsValid(); err != nil {
			return err
		}
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (SetCookieFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.set_cookie",
		New: func() caddy.Module { return new(SetCookieFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *SetCookieFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	for d.NextBlock(0) {
		cfa := cookieFilterAction{}
		switch d.Val() {
		case "replace":
			if !d.NextArg() {
				return d.ArgErr()
			}

			cfa.Type = replaceAction
			cfa.Name = d.Val()

			if !d.NextArg() {
				return d.ArgErr()
			}
			cfa.Value = d.Val()

		case "hash":
			if !d.NextArg() {
				return d.ArgErr()
			}

			cfa.Type = hashAction
			cfa.Name = d.Val()

		case "delete":
			if !d.NextArg() {
				return d.ArgErr()
			}

			cfa.Type = deleteAction
			cfa.Name = d.Val()

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}

		m.Actions = append(m.Actions, cfa)
	}
	return nil
}

// Filter filters the input field.
func (m SetCookieFilter) Filter(in zapcore.Field) zapcore.Field {
	setCookies, ok := in.Interface.(internal.LoggableStringArray)
	if !ok {
		return in
	}

	transformed := make(internal.LoggableStringArray, 0, len(setCookies))
	for _, line := range setCookies {
		filtered, keep := m.filterLine(line)
		if keep {
			transformed = append(transformed, filtered)
		}
	}

	in.Interface = transformed

	return in
}

func (m SetCookieFilter) filterLine(line string) (string, bool) {
	cookie, err := http.ParseSetCookie(line)
	if err != nil {
		return line, true
	}

	for _, a := range m.Actions {
		if cookie.Name != a.Name {
			continue
		}

		switch a.Type {
		case replaceAction:
			return replaceSetCookieValue(line, cookie, a.Value), true

		case hashAction:
			// A Set-Cookie-based deletion may still have an empty value
			// (for example with Max-Age=0). As with the existing hash filter,
			// hashing an empty value yields the SHA-256 prefix "e3b0c442".
			return replaceSetCookieValue(line, cookie, hash(cookie.Value)), true

		case deleteAction:
			return "", false
		}
	}

	return line, true
}

// replaceSetCookieValue keeps the original Set-Cookie suffix verbatim and only
// swaps out the leading cookie value after ParseSetCookie has identified it.
func replaceSetCookieValue(line string, cookie *http.Cookie, newValue string) string {
	// Only operate on the first Set-Cookie segment: "name=value".
	headEnd := strings.IndexByte(line, ';')
	if headEnd == -1 {
		headEnd = len(line)
	}

	head := line[:headEnd]
	eq := strings.IndexByte(head, '=')
	if eq == -1 {
		return line
	}

	name := strings.TrimSpace(head[:eq])
	if name != cookie.Name {
		return line
	}

	// Preserve the original spacing around the value so the logged header stays
	// as close as possible to the original input.
	rawValue := head[eq+1:]
	trimmedValue := strings.TrimSpace(rawValue)
	leadingWhitespaceLen := len(rawValue) - len(strings.TrimLeftFunc(rawValue, unicode.IsSpace))
	trailingWhitespaceLen := len(rawValue) - len(strings.TrimRightFunc(rawValue, unicode.IsSpace))

	replacement := newValue
	// If the original cookie value was quoted, keep the replacement quoted too.
	if cookie.Quoted && len(trimmedValue) >= 2 && trimmedValue[0] == '"' && trimmedValue[len(trimmedValue)-1] == '"' {
		replacement = `"` + newValue + `"`
	}

	// Rebuild only the first "name=value" pair and keep the attribute suffix
	// byte-for-byte unchanged.
	return line[:eq+1] +
		rawValue[:leadingWhitespaceLen] +
		replacement +
		rawValue[len(rawValue)-trailingWhitespaceLen:] +
		line[headEnd:]
}

// RegexpFilter is a Caddy log field filter that
// replaces the field matching the provided regexp
// with the indicated string. If the field is an
// array of strings, each of them will have the
// regexp replacement applied.
type RegexpFilter struct {
	// The regular expression pattern defining what to replace.
	RawRegexp string `json:"regexp,omitempty"`

	// The value to use as replacement
	Value string `json:"value,omitempty"`

	regexp *regexp.Regexp
}

// CaddyModule returns the Caddy module information.
func (RegexpFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.regexp",
		New: func() caddy.Module { return new(RegexpFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *RegexpFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	if d.NextArg() {
		f.RawRegexp = d.Val()
	}
	if d.NextArg() {
		f.Value = d.Val()
	}
	return nil
}

// Provision compiles m's regexp.
func (m *RegexpFilter) Provision(ctx caddy.Context) error {
	r, err := regexp.Compile(m.RawRegexp)
	if err != nil {
		return err
	}

	m.regexp = r

	return nil
}

// Filter filters the input field with the replacement value if it matches the regexp.
func (f *RegexpFilter) Filter(in zapcore.Field) zapcore.Field {
	if array, ok := in.Interface.(internal.LoggableStringArray); ok {
		newArray := make(internal.LoggableStringArray, len(array))
		for i, s := range array {
			newArray[i] = f.regexp.ReplaceAllString(s, f.Value)
		}
		in.Interface = newArray
	} else {
		in.String = f.regexp.ReplaceAllString(in.String, f.Value)
	}

	return in
}

// regexpFilterOperation represents a single regexp operation
// within a MultiRegexpFilter.
type regexpFilterOperation struct {
	// The regular expression pattern defining what to replace.
	RawRegexp string `json:"regexp,omitempty"`

	// The value to use as replacement
	Value string `json:"value,omitempty"`

	regexp *regexp.Regexp
}

// MultiRegexpFilter is a Caddy log field filter that
// can apply multiple regular expression replacements to
// the same field. This filter processes operations in the
// order they are defined, applying each regexp replacement
// sequentially to the result of the previous operation.
//
// This allows users to define multiple regexp filters for
// the same field without them overwriting each other.
//
// Security considerations:
// - Uses Go's regexp package (RE2 engine) which is safe from ReDoS attacks
// - Validates all patterns during provisioning
// - Limits the maximum number of operations to prevent resource exhaustion
// - Sanitizes input to prevent injection attacks
type MultiRegexpFilter struct {
	// A list of regexp operations to apply in sequence.
	// Maximum of 50 operations allowed for security and performance.
	Operations []regexpFilterOperation `json:"operations"`
}

// Security constants
const (
	maxRegexpOperations = 50   // Maximum operations to prevent resource exhaustion
	maxPatternLength    = 1000 // Maximum pattern length to prevent abuse
)

// CaddyModule returns the Caddy module information.
func (MultiRegexpFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.multi_regexp",
		New: func() caddy.Module { return new(MultiRegexpFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
// Syntax:
//
//	multi_regexp {
//	    regexp <pattern> <replacement>
//	    regexp <pattern> <replacement>
//	    ...
//	}
func (f *MultiRegexpFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	for d.NextBlock(0) {
		switch d.Val() {
		case "regexp":
			// Security check: limit number of operations
			if len(f.Operations) >= maxRegexpOperations {
				return d.Errf("too many regexp operations (maximum %d allowed)", maxRegexpOperations)
			}

			op := regexpFilterOperation{}
			if !d.NextArg() {
				return d.ArgErr()
			}
			op.RawRegexp = d.Val()

			// Security validation: check pattern length
			if len(op.RawRegexp) > maxPatternLength {
				return d.Errf("regexp pattern too long (maximum %d characters)", maxPatternLength)
			}

			// Security validation: basic pattern validation
			if op.RawRegexp == "" {
				return d.Errf("regexp pattern cannot be empty")
			}

			if !d.NextArg() {
				return d.ArgErr()
			}
			op.Value = d.Val()
			f.Operations = append(f.Operations, op)
		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	// Security check: ensure at least one operation is defined
	if len(f.Operations) == 0 {
		return d.Err("multi_regexp filter requires at least one regexp operation")
	}

	return nil
}

// Provision compiles all regexp patterns with security validation.
func (f *MultiRegexpFilter) Provision(ctx caddy.Context) error {
	// Security check: validate operation count
	if len(f.Operations) > maxRegexpOperations {
		return fmt.Errorf("too many regexp operations: %d (maximum %d allowed)", len(f.Operations), maxRegexpOperations)
	}

	if len(f.Operations) == 0 {
		return fmt.Errorf("multi_regexp filter requires at least one operation")
	}

	for i := range f.Operations {
		// Security validation: pattern length check
		if len(f.Operations[i].RawRegexp) > maxPatternLength {
			return fmt.Errorf("regexp pattern %d too long: %d characters (maximum %d)", i, len(f.Operations[i].RawRegexp), maxPatternLength)
		}

		// Security validation: empty pattern check
		if f.Operations[i].RawRegexp == "" {
			return fmt.Errorf("regexp pattern %d cannot be empty", i)
		}

		// Compile and validate the pattern (uses RE2 engine - safe from ReDoS)
		r, err := regexp.Compile(f.Operations[i].RawRegexp)
		if err != nil {
			return fmt.Errorf("compiling regexp pattern %d (%s): %v", i, f.Operations[i].RawRegexp, err)
		}
		f.Operations[i].regexp = r
	}
	return nil
}

// Validate ensures the filter is properly configured with security checks.
func (f *MultiRegexpFilter) Validate() error {
	if len(f.Operations) == 0 {
		return fmt.Errorf("multi_regexp filter requires at least one operation")
	}

	if len(f.Operations) > maxRegexpOperations {
		return fmt.Errorf("too many regexp operations: %d (maximum %d allowed)", len(f.Operations), maxRegexpOperations)
	}

	for i, op := range f.Operations {
		if op.RawRegexp == "" {
			return fmt.Errorf("regexp pattern %d cannot be empty", i)
		}
		if len(op.RawRegexp) > maxPatternLength {
			return fmt.Errorf("regexp pattern %d too long: %d characters (maximum %d)", i, len(op.RawRegexp), maxPatternLength)
		}
		if op.regexp == nil {
			return fmt.Errorf("regexp pattern %d not compiled (call Provision first)", i)
		}
	}
	return nil
}

// Filter applies all regexp operations sequentially to the input field.
// Input is sanitized and validated for security.
func (f *MultiRegexpFilter) Filter(in zapcore.Field) zapcore.Field {
	if array, ok := in.Interface.(internal.LoggableStringArray); ok {
		newArray := make(internal.LoggableStringArray, len(array))
		for i, s := range array {
			newArray[i] = f.processString(s)
		}
		in.Interface = newArray
	} else {
		in.String = f.processString(in.String)
	}

	return in
}

// processString applies all regexp operations to a single string with input validation.
func (f *MultiRegexpFilter) processString(s string) string {
	// Security: validate input string length to prevent resource exhaustion
	const maxInputLength = 1000000 // 1MB max input size
	if len(s) > maxInputLength {
		// Log warning but continue processing (truncated)
		s = s[:maxInputLength]
	}

	result := s
	for _, op := range f.Operations {
		// Each regexp operation is applied sequentially
		// Using RE2 engine which is safe from ReDoS attacks
		result = op.regexp.ReplaceAllString(result, op.Value)

		// Ensure result doesn't exceed max length after each operation
		if len(result) > maxInputLength {
			result = result[:maxInputLength]
		}
	}
	return result
}

// AddOperation adds a single regexp operation to the filter with validation.
// This is used when merging multiple RegexpFilter instances.
func (f *MultiRegexpFilter) AddOperation(rawRegexp, value string) error {
	// Security checks
	if len(f.Operations) >= maxRegexpOperations {
		return fmt.Errorf("cannot add operation: maximum %d operations allowed", maxRegexpOperations)
	}

	if rawRegexp == "" {
		return fmt.Errorf("regexp pattern cannot be empty")
	}

	if len(rawRegexp) > maxPatternLength {
		return fmt.Errorf("regexp pattern too long: %d characters (maximum %d)", len(rawRegexp), maxPatternLength)
	}

	f.Operations = append(f.Operations, regexpFilterOperation{
		RawRegexp: rawRegexp,
		Value:     value,
	})
	return nil
}

// RenameFilter is a Caddy log field filter that
// renames the field's key with the indicated name.
type RenameFilter struct {
	Name string `json:"name,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (RenameFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.rename",
		New: func() caddy.Module { return new(RenameFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *RenameFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name
	if d.NextArg() {
		f.Name = d.Val()
	}
	return nil
}

// Filter renames the input field with the replacement name.
func (f *RenameFilter) Filter(in zapcore.Field) zapcore.Field {
	in.Key = f.Name
	return in
}

// redactedValue is the replacement value inserted by the JSON redaction filter.
const redactedValue = "[REDACTED]"

// JSONRedactFilter is a Caddy log field filter that redacts
// the values at the given RFC 6901 JSON Pointer locations
// in a string field containing a JSON document.
//
// The value at each selected location is replaced in its
// entirety with the string "[REDACTED]"; both object members
// and array elements may be selected. Locations that do not
// exist in the document are skipped, nothing is created, and
// all unselected content keeps its original value and type.
// The field value remains a JSON text string, though it may
// be reformatted.
//
// If the field value is not one complete JSON document, the
// whole field value is replaced with the string "[REDACTED]"
// and the original content is not preserved.
//
// This filter only operates on string fields; fields of any
// other type are left unchanged. It only affects what is
// written to the logs, never the response received by a
// client.
type JSONRedactFilter struct {
	// Pointers is the list of RFC 6901 JSON Pointers
	// identifying the values to redact. At least one
	// pointer is required.
	Pointers []string `json:"pointers,omitempty"`

	// pointers are the parsed reference tokens for each
	// configured pointer, in configuration order.
	pointers [][]string
}

// CaddyModule returns the Caddy module information.
func (JSONRedactFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.json_redact",
		New: func() caddy.Module { return new(JSONRedactFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	json_redact <pointer...> {
//	    pointer <pointer>
//	}
//
// At least one RFC 6901 JSON Pointer must be provided, either
// as an inline argument or via a `pointer` subdirective.
func (f *JSONRedactFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume filter name

	f.Pointers = append(f.Pointers, d.RemainingArgs()...)

	for d.NextBlock(0) {
		switch d.Val() {
		case "pointer":
			if !d.NextArg() {
				return d.ArgErr()
			}
			f.Pointers = append(f.Pointers, d.Val())
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	if len(f.Pointers) == 0 {
		return d.Err("json_redact filter requires at least one JSON pointer")
	}

	return nil
}

// Provision parses the configured JSON pointers so that
// malformed pointers are reported when the configuration
// is loaded, rather than while logging.
func (f *JSONRedactFilter) Provision(_ caddy.Context) error {
	f.pointers = make([][]string, 0, len(f.Pointers))
	for _, raw := range f.Pointers {
		tokens, err := parseJSONPointer(raw)
		if err != nil {
			return fmt.Errorf("invalid JSON pointer %q: %v", raw, err)
		}
		f.pointers = append(f.pointers, tokens)
	}
	return nil
}

// Validate ensures that at least one pointer is configured.
func (f *JSONRedactFilter) Validate() error {
	if len(f.Pointers) == 0 {
		return fmt.Errorf("json_redact filter requires at least one JSON pointer")
	}
	return nil
}

// Filter redacts the configured JSON Pointer locations of
// the input field.
func (f *JSONRedactFilter) Filter(in zapcore.Field) zapcore.Field {
	// only string fields carry a JSON document to filter
	if in.Type != zapcore.StringType {
		return in
	}

	// UseNumber decodes JSON numbers without lossy float
	// conversion so unselected numeric values round-trip
	// with their original value and type.
	dec := json.NewDecoder(strings.NewReader(in.String))
	dec.UseNumber()

	var doc any
	if err := dec.Decode(&doc); err != nil {
		in.String = redactedValue
		return in
	}
	// the value must be a single complete JSON document;
	// trailing values mean it is not
	if dec.More() {
		in.String = redactedValue
		return in
	}

	for _, tokens := range f.pointers {
		doc = redactJSONPointer(doc, tokens)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		in.String = redactedValue
		return in
	}
	in.String = strings.TrimSuffix(buf.String(), "\n")

	return in
}

// parseJSONPointer parses an RFC 6901 JSON Pointer into its
// reference tokens. The empty pointer, which references the
// whole document, results in no tokens.
func parseJSONPointer(raw string) ([]string, error) {
	if raw == "" {
		return []string{}, nil
	}
	if raw[0] != '/' {
		return nil, errors.New("non-empty JSON pointer must begin with '/'")
	}

	rawTokens := strings.Split(raw[1:], "/")
	tokens := make([]string, 0, len(rawTokens))
	for _, rawToken := range rawTokens {
		token, err := unescapeJSONPointerToken(rawToken)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// unescapeJSONPointerToken unescapes the "~0" and "~1"
// sequences in an RFC 6901 reference token. Any other "~"
// escape is invalid.
func unescapeJSONPointerToken(token string) (string, error) {
	if !strings.ContainsRune(token, '~') {
		return token, nil
	}

	var b strings.Builder
	for i := 0; i < len(token); i++ {
		if token[i] != '~' {
			b.WriteByte(token[i])
			continue
		}
		if i+1 >= len(token) {
			return "", errors.New("invalid escape sequence '~': must be '~0' or '~1'")
		}
		switch token[i+1] {
		case '0':
			b.WriteRune('~')
		case '1':
			b.WriteRune('/')
		default:
			return "", fmt.Errorf("invalid escape sequence '~%c': must be '~0' or '~1'", token[i+1])
		}
		i++
	}
	return b.String(), nil
}

// redactJSONPointer replaces the value at the given RFC 6901
// reference tokens with the redaction string and returns the
// document. Locations that do not exist, or whose parent is
// neither an object nor an array, are skipped.
func redactJSONPointer(doc any, tokens []string) any {
	if len(tokens) == 0 {
		// the empty pointer references the whole document
		return redactedValue
	}

	// navigate to the parent of the selected value
	parent := doc
	for _, token := range tokens[:len(tokens)-1] {
		switch node := parent.(type) {
		case map[string]any:
			child, ok := node[token]
			if !ok {
				return doc
			}
			parent = child
		case []any:
			index, ok := jsonPointerArrayIndex(token, len(node))
			if !ok {
				return doc
			}
			parent = node[index]
		default:
			return doc
		}
	}

	lastToken := tokens[len(tokens)-1]
	switch node := parent.(type) {
	case map[string]any:
		if _, ok := node[lastToken]; !ok {
			return doc
		}
		node[lastToken] = redactedValue
	case []any:
		index, ok := jsonPointerArrayIndex(lastToken, len(node))
		if !ok {
			return doc
		}
		node[index] = redactedValue
	default:
		return doc
	}

	return doc
}

// jsonPointerArrayIndex resolves an RFC 6901 array index
// reference token. The "-" token references the nonexistent
// element one past the end, leading zeros are forbidden
// (except for "0" itself), and the index must be in range.
func jsonPointerArrayIndex(token string, length int) (int, bool) {
	if token == "-" {
		return 0, false
	}
	if len(token) == 0 {
		return 0, false
	}
	if len(token) > 1 && token[0] == '0' {
		return 0, false
	}

	index := 0
	for i := 0; i < len(token); i++ {
		digit := token[i]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		if index > (math.MaxInt-int(digit-'0'))/10 {
			return 0, false
		}
		index = index*10 + int(digit-'0')
	}

	if index >= length {
		return 0, false
	}
	return index, true
}

// Interface guards
var (
	_ LogFieldFilter = (*DeleteFilter)(nil)
	_ LogFieldFilter = (*HashFilter)(nil)
	_ LogFieldFilter = (*ReplaceFilter)(nil)
	_ LogFieldFilter = (*IPMaskFilter)(nil)
	_ LogFieldFilter = (*QueryFilter)(nil)
	_ LogFieldFilter = (*CookieFilter)(nil)
	_ LogFieldFilter = (*SetCookieFilter)(nil)
	_ LogFieldFilter = (*RegexpFilter)(nil)
	_ LogFieldFilter = (*RenameFilter)(nil)
	_ LogFieldFilter = (*MultiRegexpFilter)(nil)
	_ LogFieldFilter = (*JSONRedactFilter)(nil)

	_ caddyfile.Unmarshaler = (*DeleteFilter)(nil)
	_ caddyfile.Unmarshaler = (*HashFilter)(nil)
	_ caddyfile.Unmarshaler = (*ReplaceFilter)(nil)
	_ caddyfile.Unmarshaler = (*IPMaskFilter)(nil)
	_ caddyfile.Unmarshaler = (*QueryFilter)(nil)
	_ caddyfile.Unmarshaler = (*CookieFilter)(nil)
	_ caddyfile.Unmarshaler = (*SetCookieFilter)(nil)
	_ caddyfile.Unmarshaler = (*RegexpFilter)(nil)
	_ caddyfile.Unmarshaler = (*RenameFilter)(nil)
	_ caddyfile.Unmarshaler = (*MultiRegexpFilter)(nil)
	_ caddyfile.Unmarshaler = (*JSONRedactFilter)(nil)

	_ caddy.Provisioner = (*IPMaskFilter)(nil)
	_ caddy.Provisioner = (*RegexpFilter)(nil)
	_ caddy.Provisioner = (*MultiRegexpFilter)(nil)
	_ caddy.Provisioner = (*JSONRedactFilter)(nil)

	_ caddy.Validator = (*QueryFilter)(nil)
	_ caddy.Validator = (*SetCookieFilter)(nil)
	_ caddy.Validator = (*MultiRegexpFilter)(nil)
	_ caddy.Validator = (*JSONRedactFilter)(nil)
)
