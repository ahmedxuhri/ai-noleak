package proxy

import "testing"

func TestJoinPaths(t *testing.T) {
	cases := []struct {
		base, incoming, want string
	}{
		// No base — passthrough
		{"", "/v1/messages", "/v1/messages"},
		{"/", "/v1/messages", "/v1/messages"},

		// Base is empty path component on upstream — passthrough
		{"", "/", "/"},

		// Upstream has /v1, incoming starts with /v1 — don't double
		{"/v1", "/v1/messages", "/v1/messages"},
		{"/v1", "/v1", "/v1"},

		// Upstream has /v1, incoming has different prefix — prepend
		{"/v1", "/messages", "/v1/messages"},
		{"/api/v1", "/messages", "/api/v1/messages"},

		// Trailing slash on base — collapsed
		{"/v1/", "/messages", "/v1/messages"},

		// Incoming without leading slash
		{"/v1", "messages", "/v1/messages"},
	}
	for _, c := range cases {
		got := joinPaths(c.base, c.incoming)
		if got != c.want {
			t.Errorf("joinPaths(%q, %q) = %q, want %q", c.base, c.incoming, got, c.want)
		}
	}
}
