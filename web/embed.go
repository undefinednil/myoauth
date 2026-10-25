package web

import "embed"

// FS embeds the built frontend assets from web/dist.
//
// The directory is populated by the Vite build (see `make web`). A committed
// web/dist/.gitkeep placeholder keeps `go build` working on a clean checkout;
// `all:` is required so the dotfile is embedded. When index.html is absent the
// SPA handler serves a 503 asking the user to run `make web`.
//
//go:embed all:dist
var FS embed.FS
