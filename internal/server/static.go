package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const frontendMissingPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>VEN</title></head>
<body><h1>VEN</h1><p>The dashboard frontend was not built into this binary.
Run <code>make web</code> (or <code>npm --prefix web run build</code>) and rebuild VEN.</p></body></html>`

// newStaticHandler serves the embedded single-page app. Unknown non-asset
// paths fall back to index.html for client-side routing.
func newStaticHandler(fsys fs.FS) http.Handler {
	var index []byte
	if fsys != nil {
		index, _ = fs.ReadFile(fsys, "index.html")
	}
	var files http.Handler
	if fsys != nil {
		files = http.FileServerFS(fsys)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if index == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(frontendMissingPage))
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "index.html" {
			if info, err := fs.Stat(fsys, p); err == nil && !info.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					// Vite emits content-hashed asset names.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				files.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(p, "assets/") || path.Ext(p) != "" {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
