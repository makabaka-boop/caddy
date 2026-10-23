package logging

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/internal"
)

func TestIPMaskSingleValue(t *testing.T) {
	f := IPMaskFilter{IPv4MaskRaw: 16, IPv6MaskRaw: 32}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "255.255.255.255"})
	if out.String != "255.255.0.0" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"})
	if out.String != "ffff:ffff::" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "not-an-ip"})
	if out.String != "not-an-ip" {
		t.Fatalf("field has been filtered: %s", out.String)
	}
}

func TestIPMaskInvalidCIDR(t *testing.T) {
	for _, f := range []IPMaskFilter{
		{IPv4MaskRaw: 33},
		{IPv4MaskRaw: -1},
		{IPv6MaskRaw: 129},
		{IPv6MaskRaw: -8},
	} {
		if err := f.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected error for ipv4=%d ipv6=%d", f.IPv4MaskRaw, f.IPv6MaskRaw)
		}
	}

	f := IPMaskFilter{IPv4MaskRaw: 32, IPv6MaskRaw: 128}
	if err := f.Provision(caddy.Context{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := f.Filter(zapcore.Field{String: "1.2.3.4, 2001:db8::1"})
	if out.String != "1.2.3.4, 2001:db8::1" {
		t.Fatalf("field changed with full masks: %s", out.String)
	}
}

func TestIPMaskCommaValue(t *testing.T) {
	f := IPMaskFilter{IPv4MaskRaw: 16, IPv6MaskRaw: 32}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "255.255.255.255, 244.244.244.244"})
	if out.String != "255.255.0.0, 244.244.0.0" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"})
	if out.String != "ffff:ffff::, ff00:ffff::" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "not-an-ip, 255.255.255.255"})
	if out.String != "not-an-ip, 255.255.0.0" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestIPMaskMultiValue(t *testing.T) {
	f := IPMaskFilter{IPv4MaskRaw: 16, IPv6MaskRaw: 32}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"255.255.255.255",
		"244.244.244.244",
	}})
	arr, ok := out.Interface.(internal.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "255.255.0.0" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "244.244.0.0" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}

	out = f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}})
	arr, ok = out.Interface.(internal.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "ffff:ffff::" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "ff00:ffff::" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestQueryFilterSingleValue(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{replaceAction, "foo", "REDACTED"},
		{replaceAction, "notexist", "REDACTED"},
		{deleteAction, "bar", ""},
		{deleteAction, "notexist", ""},
		{hashAction, "hash", ""},
	}}

	if f.Validate() != nil {
		t.Fatalf("the filter must be valid")
	}

	out := f.Filter(zapcore.Field{String: "/path?foo=a&foo=b&bar=c&bar=d&baz=e&hash=hashed"})
	if out.String != "/path?baz=e&foo=REDACTED&foo=REDACTED&hash=1a06df82" {
		t.Fatalf("query parameters have not been filtered: %s", out.String)
	}
}

func TestQueryFilterHashInRequestURI(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{replaceAction, "token", "REDACTED"},
	}}

	// A request-target has no fragment, so '#' is part of the query.
	for uri, expected := range map[string]string{
		"/path?x=1#&token=secret": "/path?token=REDACTED&x=1%23",
		"/path?token=secret#%zz":  "/path",
	} {
		out := f.Filter(zapcore.Field{String: uri})
		if out.String != expected {
			t.Errorf("filtering %q: got %q, expected %q", uri, out.String, expected)
		}
	}
}

func TestQueryFilterMultiValue(t *testing.T) {
	f := QueryFilter{
		Actions: []queryFilterAction{
			{Type: replaceAction, Parameter: "foo", Value: "REDACTED"},
			{Type: replaceAction, Parameter: "notexist", Value: "REDACTED"},
			{Type: deleteAction, Parameter: "bar"},
			{Type: deleteAction, Parameter: "notexist"},
			{Type: hashAction, Parameter: "hash"},
		},
	}

	if f.Validate() != nil {
		t.Fatalf("the filter must be valid")
	}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"/path1?foo=a&foo=b&bar=c&bar=d&baz=e&hash=alpha",
		"/path2?foo=c&foo=d&bar=e&bar=f&baz=g&hash=beta",
	}})
	arr, ok := out.Interface.(internal.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Interface)
	}

	expected1 := "/path1?baz=e&foo=REDACTED&foo=REDACTED&hash=8ed3f6ad"
	expected2 := "/path2?baz=g&foo=REDACTED&foo=REDACTED&hash=f44e64e7"
	if arr[0] != expected1 {
		t.Fatalf("query parameters in entry 0 have not been filtered correctly: got %s, expected %s", arr[0], expected1)
	}
	if arr[1] != expected2 {
		t.Fatalf("query parameters in entry 1 have not been filtered correctly: got %s, expected %s", arr[1], expected2)
	}
}

func TestValidateQueryFilter(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{},
	}}
	if f.Validate() == nil {
		t.Fatalf("empty action type must be invalid")
	}

	f = QueryFilter{[]queryFilterAction{
		{Type: "foo"},
	}}
	if f.Validate() == nil {
		t.Fatalf("unknown action type must be invalid")
	}
}

func TestCookieFilter(t *testing.T) {
	f := CookieFilter{[]cookieFilterAction{
		{replaceAction, "foo", "REDACTED"},
		{deleteAction, "bar", ""},
		{hashAction, "hash", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"foo=a; foo=b; bar=c; bar=d; baz=e; hash=hashed",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	expected := internal.LoggableStringArray{
		"foo=REDACTED; foo=REDACTED; baz=e; hash=1a06df82",
	}
	if outval[0] != expected[0] {
		t.Fatalf("cookies have not been filtered: %s", out.String)
	}
}

func TestValidateCookieFilter(t *testing.T) {
	f := CookieFilter{[]cookieFilterAction{
		{},
	}}
	if f.Validate() == nil {
		t.Fatalf("empty action type must be invalid")
	}

	f = CookieFilter{[]cookieFilterAction{
		{Type: "foo"},
	}}
	if f.Validate() == nil {
		t.Fatalf("unknown action type must be invalid")
	}
}

func TestSetCookieFilter(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{replaceAction, "foo", "REDACTED"},
		{deleteAction, "bar", ""},
		{hashAction, "hash", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		`foo="a"; Path=/; Priority=High`,
		"bar=c; Path=/; Secure",
		"hash=hashed; Path=/; HttpOnly",
		"baz=e; Path=/; SameSite=Strict",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	expected := internal.LoggableStringArray{
		`foo="REDACTED"; Path=/; Priority=High`,
		"hash=1a06df82; Path=/; HttpOnly",
		"baz=e; Path=/; SameSite=Strict",
	}
	if len(outval) != len(expected) {
		t.Fatalf("unexpected number of Set-Cookie values: got %d, want %d", len(outval), len(expected))
	}
	for i := range expected {
		if outval[i] != expected[i] {
			t.Fatalf("Set-Cookie entry %d has not been filtered correctly: got %q, want %q", i, outval[i], expected[i])
		}
	}
}

func TestSetCookieFilterInvalidHeaderPassesThrough(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{hashAction, "session", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"not-a-cookie",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	if outval[0] != "not-a-cookie" {
		t.Fatalf("invalid Set-Cookie line should pass through unchanged: got %q", outval[0])
	}
}

func TestSetCookieFilterHashWithoutAttributes(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{hashAction, "session", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"session=secret",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	expected := "session=2bb80d53"
	if outval[0] != expected {
		t.Fatalf("cookie value was not hashed as expected: got %q, want %q", outval[0], expected)
	}
}

func TestSetCookieFilterCookieNameMatchingIsCaseSensitive(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{hashAction, "session", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"Session=secret; Path=/",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	expected := "Session=secret; Path=/"
	if outval[0] != expected {
		t.Fatalf("Set-Cookie value should remain unchanged when the cookie name does not match exactly: got %q, want %q", outval[0], expected)
	}
}

func TestSetCookieFilterFirstMatchWins(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{deleteAction, "session", ""},
		{hashAction, "session", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"session=secret; Path=/",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	if len(outval) != 0 {
		t.Fatalf("expected cookie to be deleted by first matching action, got %q", outval)
	}
}

func TestSetCookieFilterHashEmptyValue(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{hashAction, "session", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"session=; Max-Age=0; Path=/; HttpOnly",
	}})
	outval := out.Interface.(internal.LoggableStringArray)
	expected := "session=e3b0c442; Max-Age=0; Path=/; HttpOnly"
	if outval[0] != expected {
		t.Fatalf("empty cookie value was not hashed as expected: got %q, want %q", outval[0], expected)
	}
}

func TestValidateSetCookieFilter(t *testing.T) {
	f := SetCookieFilter{[]cookieFilterAction{
		{},
	}}
	if f.Validate() == nil {
		t.Fatalf("empty action type must be invalid")
	}

	f = SetCookieFilter{[]cookieFilterAction{
		{Type: "foo"},
	}}
	if f.Validate() == nil {
		t.Fatalf("unknown action type must be invalid")
	}
}

func TestRegexpFilterSingleValue(t *testing.T) {
	f := RegexpFilter{RawRegexp: `secret`, Value: "REDACTED"}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "foo-secret-bar"})
	if out.String != "foo-REDACTED-bar" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestRegexpFilterMultiValue(t *testing.T) {
	f := RegexpFilter{RawRegexp: `secret`, Value: "REDACTED"}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{"foo-secret-bar", "bar-secret-foo"}})
	arr, ok := out.Interface.(internal.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "foo-REDACTED-bar" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "bar-REDACTED-foo" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestHashFilterSingleValue(t *testing.T) {
	f := HashFilter{}

	out := f.Filter(zapcore.Field{String: "foo"})
	if out.String != "2c26b46b" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestHashFilterMultiValue(t *testing.T) {
	f := HashFilter{}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{"foo", "bar"}})
	arr, ok := out.Interface.(internal.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "2c26b46b" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "fcde2b2e" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestMultiRegexpFilterSingleOperation(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret`, Value: "REDACTED"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	out := f.Filter(zapcore.Field{String: "foo-secret-bar"})
	if out.String != "foo-REDACTED-bar" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestMultiRegexpFilterMultipleOperations(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret`, Value: "REDACTED"},
			{RawRegexp: `password`, Value: "HIDDEN"},
			{RawRegexp: `token`, Value: "XXX"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	// Test sequential application
	out := f.Filter(zapcore.Field{String: "my-secret-password-token-data"})
	expected := "my-REDACTED-HIDDEN-XXX-data"
	if out.String != expected {
		t.Fatalf("field has not been filtered correctly: got %s, expected %s", out.String, expected)
	}
}

func TestMultiRegexpFilterMultiValue(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret`, Value: "REDACTED"},
			{RawRegexp: `\d+`, Value: "NUM"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	out := f.Filter(zapcore.Field{Interface: internal.LoggableStringArray{
		"foo-secret-123",
		"bar-secret-456",
	}})
	arr, ok := out.Interface.(internal.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Interface)
	}
	if arr[0] != "foo-REDACTED-NUM" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "bar-REDACTED-NUM" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestMultiRegexpFilterAddOperation(t *testing.T) {
	f := MultiRegexpFilter{}
	err := f.AddOperation("secret", "REDACTED")
	if err != nil {
		t.Fatalf("unexpected error adding operation: %v", err)
	}
	err = f.AddOperation("password", "HIDDEN")
	if err != nil {
		t.Fatalf("unexpected error adding operation: %v", err)
	}
	err = f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	if len(f.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(f.Operations))
	}

	out := f.Filter(zapcore.Field{String: "my-secret-password"})
	expected := "my-REDACTED-HIDDEN"
	if out.String != expected {
		t.Fatalf("field has not been filtered correctly: got %s, expected %s", out.String, expected)
	}
}

func TestMultiRegexpFilterSecurityLimits(t *testing.T) {
	f := MultiRegexpFilter{}

	// Test maximum operations limit
	for i := 0; i < 51; i++ {
		err := f.AddOperation(fmt.Sprintf("pattern%d", i), "replacement")
		if i < 50 {
			if err != nil {
				t.Fatalf("unexpected error adding operation %d: %v", i, err)
			}
		} else {
			if err == nil {
				t.Fatalf("expected error when adding operation %d (exceeds limit)", i)
			}
		}
	}

	// Test empty pattern validation
	f2 := MultiRegexpFilter{}
	err := f2.AddOperation("", "replacement")
	if err == nil {
		t.Fatalf("expected error for empty pattern")
	}

	// Test pattern length limit
	f3 := MultiRegexpFilter{}
	longPattern := strings.Repeat("a", 1001)
	err = f3.AddOperation(longPattern, "replacement")
	if err == nil {
		t.Fatalf("expected error for pattern exceeding length limit")
	}
}

func TestMultiRegexpFilterValidation(t *testing.T) {
	// Test validation with empty operations
	f := MultiRegexpFilter{}
	err := f.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty operations")
	}

	// Test validation with valid operations
	err = f.AddOperation("valid", "replacement")
	if err != nil {
		t.Fatalf("unexpected error adding operation: %v", err)
	}
	err = f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}
	err = f.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestMultiRegexpFilterInputSizeLimit(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `test`, Value: "REPLACED"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	// Test with very large input (should be truncated)
	largeInput := strings.Repeat("test", 300000) // Creates ~1.2MB string
	out := f.Filter(zapcore.Field{String: largeInput})

	// The input should be truncated to 1MB and still processed
	if len(out.String) > 1000000 {
		t.Fatalf("output string not truncated: length %d", len(out.String))
	}

	// Should still contain replacements within the truncated portion
	if !strings.Contains(out.String, "REPLACED") {
		t.Fatalf("replacements not applied to truncated input")
	}
}

func TestMultiRegexpFilterOverlappingPatterns(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret.*password`, Value: "SENSITIVE"},
			{RawRegexp: `password`, Value: "HIDDEN"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	// The first pattern should match and replace the entire "secret...password" portion
	// Then the second pattern should not find "password" anymore since it was already replaced
	out := f.Filter(zapcore.Field{String: "my-secret-data-password-end"})
	expected := "my-SENSITIVE-end"
	if out.String != expected {
		t.Fatalf("field has not been filtered correctly: got %s, expected %s", out.String, expected)
	}
}

func TestJSONRedactFilterProvision(t *testing.T) {
	for _, raw := range []string{
		"",      // whole document
		"/",     // empty member name
		"/a",    // simple member
		"/a/b",  // nested member
		"/a~1b", // escaped slash in member name
		"/c~0d", // escaped tilde in member name
		"/arr/0",
		"/-",
		"/a/-",
	} {
		f := JSONRedactFilter{Pointers: []string{raw}}
		if err := f.Provision(caddy.Context{}); err != nil {
			t.Errorf("expected pointer %q to be valid, got error: %v", raw, err)
		}
	}

	for _, raw := range []string{
		"a",    // non-empty pointer must start with '/'
		"/a~",  // trailing unescaped '~'
		"/a~2", // invalid escape sequence
		"/a~x",
	} {
		f := JSONRedactFilter{Pointers: []string{raw}}
		if err := f.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected pointer %q to be rejected", raw)
		}
	}
}

func TestJSONRedactFilterValidate(t *testing.T) {
	f := JSONRedactFilter{}
	if err := f.Validate(); err == nil {
		t.Fatal("expected validation error when no pointer is configured")
	}

	f = JSONRedactFilter{Pointers: []string{"/a"}}
	if err := f.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

// decodeJSONTestValue parses JSON for semantic comparison, keeping
// numbers as their literal text so numeric value and type can be
// checked without float conversion.
func decodeJSONTestValue(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, s)
	}
	return v
}

func TestJSONRedactFilter(t *testing.T) {
	for i, tc := range []struct {
		input    string
		pointers []string
		expected string
	}{
		{
			input:    `{"user":"bob","password":"hunter2"}`,
			pointers: []string{"/password"},
			expected: `{"user":"bob","password":"[REDACTED]"}`,
		},
		{
			input:    `{"a":{"b":"secret","c":"keep"},"d":1}`,
			pointers: []string{"/a/b"},
			expected: `{"a":{"b":"[REDACTED]","c":"keep"},"d":1}`,
		},
		{
			input:    `{"tokens":["a","b","c"]}`,
			pointers: []string{"/tokens/1"},
			expected: `{"tokens":["a","[REDACTED]","c"]}`,
		},
		{
			input:    `["a","b","c"]`,
			pointers: []string{"/0"},
			expected: `["[REDACTED]","b","c"]`,
		},
		{
			// missing object member is skipped, nothing is created
			input:    `{"a":1}`,
			pointers: []string{"/missing/deep"},
			expected: `{"a":1}`,
		},
		{
			// out-of-range array index is skipped
			input:    `[1,2]`,
			pointers: []string{"/5"},
			expected: `[1,2]`,
		},
		{
			// "-" always references a nonexistent element
			input:    `[1,2]`,
			pointers: []string{"/-"},
			expected: `[1,2]`,
		},
		{
			// leading zero indices are not valid array references
			input:    `{"arr":["secret"]}`,
			pointers: []string{"/arr/01"},
			expected: `{"arr":["secret"]}`,
		},
		{
			// non-numeric array reference is skipped
			input:    `[1,2]`,
			pointers: []string{"/x"},
			expected: `[1,2]`,
		},
		{
			// escaped member names: ~1 => '/', ~0 => '~'
			input:    `{"a/b":1,"c~d":2}`,
			pointers: []string{"/a~1b", "/c~0d"},
			expected: `{"a/b":"[REDACTED]","c~d":"[REDACTED]"}`,
		},
		{
			// selected object is replaced wholesale with a string
			input:    `{"obj":{"secret":"x","keep":"y"},"n":1}`,
			pointers: []string{"/obj"},
			expected: `{"obj":"[REDACTED]","n":1}`,
		},
		{
			// selected array element that is an object is replaced wholesale
			input:    `{"items":[{"secret":"x"},{"keep":"y"}]}`,
			pointers: []string{"/items/0"},
			expected: `{"items":["[REDACTED]",{"keep":"y"}]}`,
		},
		{
			// multiple pointers, including mixed object and array targets
			input:    `{"password":"p","tokens":["t1","t2"],"keep":"k","n":3,"ok":true,"missing":null}`,
			pointers: []string{"/password", "/tokens/0", "/tokens/1"},
			expected: `{"password":"[REDACTED]","tokens":["[REDACTED]","[REDACTED]"],"keep":"k","n":3,"ok":true,"missing":null}`,
		},
		{
			// unselected number, bool, null keep value and type; large
			// integers must round-trip without float conversion
			input:    `{"big":9007199254740993,"flag":true,"nothing":null,"s":"x"}`,
			pointers: []string{"/s"},
			expected: `{"big":9007199254740993,"flag":true,"nothing":null,"s":"[REDACTED]"}`,
		},
		{
			// pointer into a primitive value does nothing
			input:    `{"a":1}`,
			pointers: []string{"/a/b"},
			expected: `{"a":1}`,
		},
		{
			// empty pointer selects the whole document
			input:    `{"a":"secret"}`,
			pointers: []string{""},
			expected: `"[REDACTED]"`,
		},
		{
			// a bare scalar is a complete JSON document too
			input:    `"hello"`,
			pointers: []string{"/a"},
			expected: `"hello"`,
		},
		{
			// whitespace around the document is tolerated and output
			// may be reformatted
			input:    "  \n {\n\t\"a\": \"secret\", \"b\": 1 }\r\n ",
			pointers: []string{"/a"},
			expected: `{"a":"[REDACTED]","b":1}`,
		},
	} {
		f := JSONRedactFilter{Pointers: tc.pointers}
		if err := f.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Test %d: unexpected provision error: %v", i, err)
		}

		out := f.Filter(zapcore.Field{Type: zapcore.StringType, String: tc.input})
		if out.Type != zapcore.StringType {
			t.Fatalf("Test %d: field type changed to %v", i, out.Type)
		}

		got := decodeJSONTestValue(t, out.String)
		want := decodeJSONTestValue(t, tc.expected)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Test %d: got %s, expected %s", i, out.String, tc.expected)
		}
	}
}

func TestJSONRedactFilterInvalidJSON(t *testing.T) {
	f := JSONRedactFilter{Pointers: []string{"/a"}}
	if err := f.Provision(caddy.Context{}); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	for i, input := range []string{
		"",              // empty field
		"not json",      // bare text
		"{",             // truncated object
		`{"a":1,}`,      // malformed object
		`[1,]`,          // malformed array
		`{"a":1} extra`, // trailing non-whitespace
		`{} {}`,         // two documents
		`[1] [2]`,       // two documents
		`{"a":1} null`,  // trailing value
	} {
		out := f.Filter(zapcore.Field{Type: zapcore.StringType, String: input})
		if out.String != redactedValue {
			t.Errorf("Test %d: invalid input %q should redact the whole field, got %q", i, input, out.String)
		}
	}
}

func TestJSONRedactFilterNonStringFields(t *testing.T) {
	f := JSONRedactFilter{Pointers: []string{"/a"}}
	if err := f.Provision(caddy.Context{}); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	in := zapcore.Field{Type: zapcore.Int64Type, Integer: 42}
	out := f.Filter(in)
	if out.Type != zapcore.Int64Type || out.Integer != 42 {
		t.Fatalf("non-string field was modified: %+v", out)
	}

	arr := internal.LoggableStringArray{`{"a":"secret"}`}
	in = zapcore.Field{Type: zapcore.ArrayMarshalerType, Interface: arr}
	out = f.Filter(in)
	if out.Type != zapcore.ArrayMarshalerType {
		t.Fatalf("array field type was modified: %v", out.Type)
	}
	if got, ok := out.Interface.(internal.LoggableStringArray); !ok || len(got) != 1 || got[0] != `{"a":"secret"}` {
		t.Fatalf("array field was modified: %#v", out.Interface)
	}
}

func TestJSONRedactFilterUnmarshalCaddyfile(t *testing.T) {
	f := &JSONRedactFilter{}
	d := caddyfile.NewTestDispenser(`
		json_redact /a/b /c {
			pointer /d~1e
		}
	`)
	if err := f.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"/a/b", "/c", "/d~1e"}
	if !reflect.DeepEqual(f.Pointers, want) {
		t.Fatalf("pointers not parsed correctly: got %#v, expected %#v", f.Pointers, want)
	}
	if err := f.Provision(caddy.Context{}); err != nil {
		t.Fatalf("parsed pointers should provision successfully: %v", err)
	}

	// at least one pointer is required
	if err := (&JSONRedactFilter{}).UnmarshalCaddyfile(
		caddyfile.NewTestDispenser(`json_redact`),
	); err == nil {
		t.Fatal("expected an error when no pointer is configured")
	}

	// unknown subdirectives are rejected
	if err := (&JSONRedactFilter{}).UnmarshalCaddyfile(
		caddyfile.NewTestDispenser(`json_redact /a { unknown /b }`),
	); err == nil {
		t.Fatal("expected an error for an unknown subdirective")
	}
}
