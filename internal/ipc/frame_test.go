package ipc

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	req := &Request{
		Op:   OpScan,
		Scan: &ScanRequest{PayloadB64: "aGVsbG8=", AutoRegister: true},
	}
	var buf bytes.Buffer
	if err := WriteRequest(&buf, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Op != OpScan || got.Scan == nil || got.Scan.PayloadB64 != "aGVsbG8=" || !got.Scan.AutoRegister {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	huge := make([]byte, MaxFrame+1)
	if err := WriteFrame(&buf, huge); err == nil {
		t.Fatal("expected error on oversize frame, got nil")
	}
}
