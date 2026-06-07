package vault

import (
	"errors"
	"testing"
)

func TestMemoryRegisterAndResolve(t *testing.T) {
	v := NewMemory()
	defer v.Close()
	ms, _ := NewMasterSecret()

	e, err := v.Register("real-secret-A", "telegram_bot_token", "paste", []string{"api.telegram.org"}, ms)
	if err != nil {
		t.Fatal(err)
	}
	if e.Placeholder == "" || e.Value != "real-secret-A" {
		t.Fatalf("bad entry: %+v", e)
	}

	got, err := v.Resolve(e.Placeholder, "api.telegram.org")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "real-secret-A" {
		t.Fatalf("resolve returned %q", got)
	}

	if _, err := v.Resolve(e.Placeholder, "evil.example.com"); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("expected binding mismatch, got %v", err)
	}
}

func TestMemoryRegisterIdempotent(t *testing.T) {
	v := NewMemory()
	ms, _ := NewMasterSecret()

	a, _ := v.Register("dup-value", "kind", "src", []string{"a.example"}, ms)
	b, _ := v.Register("dup-value", "kind", "src", []string{"b.example"}, ms)
	if a.Placeholder != b.Placeholder {
		t.Fatalf("placeholders diverged: %s != %s", a.Placeholder, b.Placeholder)
	}
	val, err := v.Resolve(b.Placeholder, "b.example")
	if err != nil || val != "dup-value" {
		t.Fatalf("merge failed: %v %q", err, val)
	}
}

func TestMemoryRotate(t *testing.T) {
	v := NewMemory()
	ms, _ := NewMasterSecret()
	e, _ := v.Register("v1", "k", "s", []string{"x.example"}, ms)
	if err := v.Rotate(e.Placeholder, "v2"); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Resolve(e.Placeholder, "x.example")
	if got != "v2" {
		t.Fatalf("rotate failed, got %q", got)
	}
}

func TestMemoryWildcardBinding(t *testing.T) {
	v := NewMemory()
	ms, _ := NewMasterSecret()
	e, _ := v.Register("r2-secret", "r2", "src", []string{"*.r2.cloudflarestorage.com"}, ms)

	cases := []struct {
		host string
		ok   bool
	}{
		{"foo.r2.cloudflarestorage.com", true},
		{"r2.cloudflarestorage.com", true},
		{"r2.cloudflarestorage.com.evil.example", false},
		{"unrelated.example", false},
	}
	for _, c := range cases {
		_, err := v.Resolve(e.Placeholder, c.host)
		if (err == nil) != c.ok {
			t.Errorf("host %q: expected ok=%v, got err=%v", c.host, c.ok, err)
		}
	}
}

func TestMemoryDeterministicPlaceholder(t *testing.T) {
	ms := []byte("fixed-master-secret-32-bytes-XYZ")
	a := MakePlaceholder("the-value", ms)
	b := MakePlaceholder("the-value", ms)
	if a != b {
		t.Fatalf("non-deterministic: %s vs %s", a, b)
	}
	c := MakePlaceholder("different-value", ms)
	if a == c {
		t.Fatalf("collision on different values: %s", a)
	}
}
