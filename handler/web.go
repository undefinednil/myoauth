package handler

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/zenpk/my-oauth/web"
)

// assetExtensions is the explicit allowlist of file extensions that are
// considered static assets. A missing path with one of these extensions is a
// real 404 instead of an SPA fallback (see FIX 2).
var assetExtensions = map[string]bool{
	".js":    true,
	".mjs":   true,
	".css":   true,
	".map":   true,
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".svg":   true,
	".ico":   true,
	".webp":  true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
	".json":  true,
	".txt":   true,
	".xml":   true,
}

const frontendNotBuiltHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MyOAuth</title>
</head>
<body>
<h1>Frontend not built</h1>
<p>The embedded frontend has not been built yet. Run <code>npm --prefix frontend run build</code> to build it.</p>
</body>
</html>
`

func (h *Handler) webHandler() http.Handler {
	dist, err := fs.Sub(web.FS, "dist")
	if err != nil {
		panic(err)
	}
	// index may be missing on a clean checkout (only .gitkeep present); that is
	// not fatal, we serve a helpful 503 instead (FIX 5).
	index, indexErr := fs.ReadFile(dist, "index.html")
	fileServer := http.FileServerFS(dist)

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		if indexErr != nil {
			h.logger.Printf("frontend not built: %v\n", indexErr)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusServiceUnavailable)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(frontendNotBuiltHTML))
			}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "." {
			if info, statErr := fs.Stat(dist, name); statErr == nil {
				if info.IsDir() {
					// never fall through to the SPA for real directories
					http.NotFound(w, r)
					return
				}
				// index.html is served from memory to avoid FileServer's
				// "/index.html" -> "./" 301 redirect and to force no-cache.
				if name == "index.html" {
					serveIndex(w, r)
					return
				}
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
			if isAssetPath(name) {
				http.NotFound(w, r)
				return
			}
		}
		serveIndex(w, r)
	})
}

// isAssetPath reports whether a request path belongs to the static asset
// namespace. Only files under `assets/` are treated as hashed/immutable, plus
// an explicit extension allowlist for asset-looking paths anywhere.
func isAssetPath(name string) bool {
	if name == "assets" || strings.HasPrefix(name, "assets/") {
		return true
	}
	return assetExtensions[strings.ToLower(path.Ext(name))]
}
