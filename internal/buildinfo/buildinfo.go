// Package buildinfo carries the identity of a built binary. The values are set
// at link time; a build without them reports "dev", which is the honest answer
// for a binary compiled from a working tree.
package buildinfo

import "runtime/debug"

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

func init() {
	if Commit != "" {
		return
	}
	// Nothing was stamped, so fall back to what the Go toolchain recorded.
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			Commit = s.Value
		case "vcs.time":
			Date = s.Value
		}
	}
}

// String is what the -version flag and the startup log report.
func String() string {
	out := Version
	if Commit != "" {
		if len(Commit) > 12 {
			out += " (" + Commit[:12] + ")"
		} else {
			out += " (" + Commit + ")"
		}
	}
	return out
}
