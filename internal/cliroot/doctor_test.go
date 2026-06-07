package cliroot

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctorLoopbackHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if !loopbackHost(host) {
			t.Fatalf("expected %q to be loopback", host)
		}
	}
	for _, host := range []string{"0.0.0.0", "192.0.2.10", "example.com"} {
		if loopbackHost(host) {
			t.Fatalf("expected %q to be non-loopback", host)
		}
	}
}

func TestPrintDoctorCountsFailures(t *testing.T) {
	var buf bytes.Buffer
	n := printDoctor(&buf, []doctorCheck{
		{Name: "a", Severity: doctorOK, Message: "ok"},
		{Name: "b", Severity: doctorWarn, Message: "warn"},
		{Name: "c", Severity: doctorFail, Message: "fail"},
	})
	if n != 1 {
		t.Fatalf("expected 1 failure, got %d", n)
	}
	out := buf.String()
	for _, want := range []string{"[ok]", "[warn]", "[fail]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output: %s", want, out)
		}
	}
}
