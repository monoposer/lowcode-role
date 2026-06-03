package api

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed displayground/*
var displaygroundFS embed.FS

func (s *Server) mountDisplayGround(r chi.Router) {
	sub, err := fs.Sub(displaygroundFS, "displayground")
	if err != nil {
		return
	}
	fileServer := http.FileServer(http.FS(sub))
	r.Handle("/displayground/*", http.StripPrefix("/displayground", fileServer))
	r.Get("/displayground", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/displayground/", http.StatusFound)
	})
}
