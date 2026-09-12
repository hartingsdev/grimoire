// Package web enthält die eingebettete Oberfläche. Sie wird in die Binary
// gebacken, damit ein Container aus genau einer Datei plus /data besteht.
package web

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS
