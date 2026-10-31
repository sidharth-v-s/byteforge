// Package version holds build identity for ByteForge.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is the semantic version of this build. It can be overridden at
// build time with:
//
//	go build -ldflags "-X github.com/zoro/byteforge/internal/version.Version=1.2.3"
var Version = "0.1.0"

// Commit is an optional VCS revision injected at build time.
var Commit = ""

// UserAgent returns a compact identifier used in generated metadata.
func UserAgent() string { return "byteforge/" + Version }

// Full returns the version plus runtime/build details for `version --verbose`.
func Full() string {
	out := fmt.Sprintf("byteforge %s\n", Version)
	if Commit != "" {
		out += fmt.Sprintf("commit: %s\n", Commit)
	}
	out += fmt.Sprintf("go: %s\n", runtime.Version())
	out += fmt.Sprintf("platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && Commit == "" {
				out += fmt.Sprintf("vcs: %s\n", s.Value)
			}
		}
	}
	return out
}
