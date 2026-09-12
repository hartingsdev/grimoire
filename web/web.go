// Package web carries the embedded UI, baked into the binary so a container
// is one file plus /data.
package web

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS
