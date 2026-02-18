package api

import (
	"embed"
	"io"
	"net/http"
	"strings"
)

//go:embed dashboard*.html
//go:embed assets/*
var dashboardFS embed.FS

var dashboardHTML = mustLoadDashboardHTML()
var dashboardLogoPNG = mustLoadDashboardAsset("assets/baseline-logo.png")
var openAPISpecYAML = mustLoadDashboardAsset("assets/openapi.yaml")

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	switch r.URL.Path {
	case "/":
		fallthrough
	case "/dashboard", "/dashboard/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, dashboardHTML)
		return
	case "/assets/baseline-logo.png":
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(dashboardLogoPNG)
		return
	case "/assets/dashboard.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		content := mustLoadDashboardAsset("assets/dashboard.css")
		if content != nil {
			_, _ = w.Write(content)
		}
		return
	case "/assets/dashboard.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		content := mustLoadDashboardAsset("assets/dashboard.js")
		if content != nil {
			_, _ = w.Write(content)
		}
		return
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if len(openAPISpecYAML) == 0 {
		writeError(w, http.StatusNotFound, "not_found", "OpenAPI spec unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(openAPISpecYAML)
}

func isDashboardPath(path string) bool {
	switch strings.TrimSpace(path) {
	case "/", "/dashboard", "/dashboard/":
		return true
	default:
		return false
	}
}

func mustLoadDashboardAsset(name string) []byte {
	content, err := dashboardFS.ReadFile(name)
	if err != nil {
		return nil
	}
	return content
}

func mustLoadDashboardHTML() string {
	content, err := dashboardFS.ReadFile("dashboard.html")
	if err != nil {
		return "<!doctype html><html><body><h1>Baseline dashboard asset missing</h1></body></html>"
	}
	return string(content)
}
