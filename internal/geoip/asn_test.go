package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtendHostingASNs(t *testing.T) {
	t.Run("valid list", func(t *testing.T) {
		if err := ExtendHostingASNs(" 64512, 64513 "); err != nil {
			t.Fatalf("valid: %v", err)
		}
		if !IsHostingASN(64512) || !IsHostingASN(64513) {
			t.Fatal("extended ASNs missing from hosting set")
		}
	})
	t.Run("invalid entry", func(t *testing.T) {
		if err := ExtendHostingASNs("not-a-number"); err == nil {
			t.Fatal("expected error for invalid entry")
		}
	})
	t.Run("empty is no-op", func(t *testing.T) {
		if err := ExtendHostingASNs(""); err != nil {
			t.Fatalf("empty: %v", err)
		}
	})
}

func TestOpenASNReaderMissingFileDegrades(t *testing.T) {
	reader, err := OpenASNReader(filepath.Join(t.TempDir(), "GeoLite2-ASN.mmdb"))
	if err != nil {
		t.Fatalf("missing file must degrade, got error: %v", err)
	}
	defer reader.Close()
	if got := reader.Lookup(netip.MustParseAddr("1.2.3.4")); got != (ASNResult{}) {
		t.Fatalf("no-op reader must return zero values, got %+v", got)
	}
}

func TestOpenASNReaderEmptyPathDegrades(t *testing.T) {
	reader, err := OpenASNReader("")
	if err != nil {
		t.Fatalf("empty path must degrade: %v", err)
	}
	if got := reader.Lookup(netip.MustParseAddr("1.2.3.4")); got != (ASNResult{}) {
		t.Fatalf("expected zero result, got %+v", got)
	}
}

func TestOpenASNReaderCorruptFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(path, []byte("not an mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenASNReader(path); err == nil {
		t.Fatal("corrupt database must fail at boot, not degrade")
	}
}
