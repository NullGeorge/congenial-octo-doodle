package geoip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ranges taken verbatim from ip-location-db: the first two IPv4 rows and the
// block that holds 8.8.8.8.
const sample = `16777216,16777471,AU
16777472,16778239,CN
134447104,134874623,US
`

func writeSample(t *testing.T, rows string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "country.csv")
	if err := os.WriteFile(path, []byte(rows), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestCountryLookup(t *testing.T) {
	db, err := Load(writeSample(t, sample))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if db.Len() != 3 {
		t.Fatalf("loaded %d ranges, want 3", db.Len())
	}

	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "first address of a range", ip: "1.0.0.0", want: "AU"},
		{name: "last address of a range", ip: "1.0.0.255", want: "AU"},
		{name: "first address of the next range", ip: "1.0.1.0", want: "CN"},
		{name: "inside a later range", ip: "8.8.8.8", want: "US"},
		{name: "gap just past a range", ip: "1.0.4.0"},
		{name: "below every range", ip: "0.255.255.255"},
		{name: "above every range", ip: "255.255.255.255"},
		{name: "ipv6 is not covered", ip: "2001:4860:4860::8888"},
		{name: "not an address at all", ip: "openSSH"},
		{name: "empty", ip: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := db.Country(tt.ip); got != tt.want {
				t.Errorf("Country(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// The daemon holds a nil database when no file was configured, and must keep
// classifying knocks rather than crashing.
func TestNilDatabaseIsUsable(t *testing.T) {
	var db *DB
	if got := db.Country("8.8.8.8"); got != "" {
		t.Errorf("Country() on nil DB = %q, want empty", got)
	}
	if db.Len() != 0 {
		t.Errorf("Len() on nil DB = %d, want 0", db.Len())
	}
}

// A published database is already ordered, but an edited one may not be, and a
// binary search over unsorted ranges would silently miss addresses.
func TestUnsortedInputStillResolves(t *testing.T) {
	reversed := "134447104,134874623,US\n16777472,16778239,CN\n16777216,16777471,AU\n"
	db, err := Load(writeSample(t, reversed))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for ip, want := range map[string]string{"1.0.0.5": "AU", "1.0.1.5": "CN", "8.8.8.8": "US"} {
		if got := db.Country(ip); got != want {
			t.Errorf("Country(%q) = %q, want %q", ip, got, want)
		}
	}
}

// A corrupt range table must fail loudly at start-up rather than answer wrong.
func TestLoadRejectsBadRows(t *testing.T) {
	tests := []struct {
		name string
		rows string
	}{
		{name: "missing country code", rows: "16777216,16777471\n"},
		{name: "non-numeric bound", rows: "one,16777471,AU\n"},
		{name: "three letter code", rows: "16777216,16777471,AUS\n"},
		{name: "reversed range", rows: "16777471,16777216,AU\n"},
		{name: "bound wider than ipv4", rows: "16777216,4294967296,AU\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(writeSample(t, tt.rows)); err == nil {
				t.Fatalf("Load() accepted %q", strings.TrimSpace(tt.rows))
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.csv")); err == nil {
		t.Fatal("Load() accepted a missing file")
	}
}
