// Package version carries build identity. The values are empty in a plain
// `go build` and filled in by the release build through -ldflags, so a binary
// found on a host can always say which commit produced it.
package version

import (
	"fmt"
	"runtime"
)

// Overwritten at link time; see the Makefile.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String is one line suitable for a log entry.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s %s/%s)",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
