package version

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// A binary found on a host has to be able to say exactly which build it is, so
// every stamped value must survive into the line, not just the version. The
// values are set here rather than read, because reading them back from the
// same variables the function formats would pass even if String() ignored two
// of the three.
func TestStringCarriesEveryStampedValue(t *testing.T) {
	restore(t)
	Version, Commit, Date = "1.4.2", "0f3c9ab", "2026-08-21T10:04:00Z"

	want := fmt.Sprintf("1.4.2 (commit 0f3c9ab, built 2026-08-21T10:04:00Z, %s %s/%s)",
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// The line is embedded in log entries and in `knock-helper version` output, so
// a stray newline would break both.
func TestStringIsASingleLine(t *testing.T) {
	if got := String(); strings.ContainsAny(got, "\n\r") {
		t.Errorf("String() = %q, want a single line", got)
	}
}

// A plain `go build` leaves the stamps unset. The defaults have to stay
// recognisable, because "dev" in a log is how you tell an unreleased binary
// from a release one.
func TestUnstampedBuildReportsDev(t *testing.T) {
	if Version != "dev" || Commit != "none" || Date != "unknown" {
		t.Fatalf("defaults = %q/%q/%q, want dev/none/unknown", Version, Commit, Date)
	}
	got := String()
	if !strings.HasPrefix(got, "dev (commit none, built unknown, ") {
		t.Errorf("String() = %q, want it to start with the dev stamps", got)
	}
	if !strings.Contains(got, runtime.Version()) {
		t.Errorf("String() = %q, missing the Go version %q", got, runtime.Version())
	}
}

// restore puts the link-time variables back, so a test that overwrites them
// cannot change what a later test observes.
func restore(t *testing.T) {
	t.Helper()
	version, commit, date := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = version, commit, date })
}
