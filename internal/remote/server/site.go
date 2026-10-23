package server

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/enigma-137/ven/internal/remote/api"
)

//go:embed site
var siteFS embed.FS

// siteCSP is looser than the API's default-src 'none' only as far as the
// landing page needs: its own stylesheet, script and icon.
const siteCSP = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// siteRoutes serves the static landing page at / and /assets/.
func (s *Server) siteRoutes() {
	sub, err := fs.Sub(siteFS, "site")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(sub)
	page := func(w http.ResponseWriter, r *http.Request) {
		if !sitePages[r.URL.Path] && r.URL.Path[len(r.URL.Path)-1] == '/' {
			writeJSON(w, http.StatusNotFound, api.Error{Code: api.CodeNotFound, Message: "not found"})
			return
		}
		w.Header().Set("Content-Security-Policy", siteCSP)
		w.Header().Set("Cache-Control", "public, max-age=300")
		files.ServeHTTP(w, r)
	}
	s.mux.HandleFunc("GET /{$}", page)
	s.mux.HandleFunc("GET /assets/", page)
	for p := range sitePages {
		if p == "/" {
			continue
		}
		s.mux.HandleFunc("GET "+p, page)
		s.mux.Handle("GET "+p[:len(p)-1], http.RedirectHandler(p, http.StatusMovedPermanently))
	}
	// Short install URLs for the docs; the scripts themselves live in the repository.
	for _, name := range []string{"install.sh", "install.ps1"} {
		s.mux.Handle("GET /"+name, http.RedirectHandler(installScriptBase+name, http.StatusFound))
	}
}

// sitePages are the directories served as pages (their index.html).
var sitePages = map[string]bool{"/": true, "/docs/": true, "/code-signing/": true}

const installScriptBase = "https://raw.githubusercontent.com/enigma-137/ven/HEAD/scripts/"
