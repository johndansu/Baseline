package api

import (
	"embed"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed assets/openapi.yaml
//go:embed assets/baseline-logo.png
var dashboardFS embed.FS

var dashboardLogoPNG = mustLoadDashboardAsset("assets/baseline-logo.png")
var openAPISpecYAML = mustLoadDashboardAsset("assets/openapi.yaml")

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	switch r.URL.Path {
	case "/login", "/login.html":
		target := "/signin"
		if q := strings.TrimSpace(r.URL.RawQuery); q != "" {
			target = target + "?" + q
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	case "/register", "/register.html":
		target := "/signup"
		if q := strings.TrimSpace(r.URL.RawQuery); q != "" {
			target = target + "?" + q
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	case "/":
	case "/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if content, ok := readUnifiedDashboardFile(filepath.Join("frontend", "index.html")); ok {
			_, _ = w.Write(content)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "landing page unavailable")
		return
	case "/styles.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if content, ok := readUnifiedDashboardFile(filepath.Join("frontend", "styles.css")); ok {
			_, _ = w.Write(content)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "styles asset unavailable")
		return
	case "/app.js":
		fallthrough
	case "/auth.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if content, ok := readUnifiedDashboardFile(filepath.Join("frontend", strings.TrimPrefix(r.URL.Path, "/"))); ok {
			_, _ = w.Write(content)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "script asset unavailable")
		return
	case "/assets/baseline-logo.png":
		fallthrough
	case "/img/baseline logo.png":
		fallthrough
	case "/img/baseline favicon.png":
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		content := loadUnifiedDashboardImage(r.URL.Path)
		if len(content) == 0 {
			content = dashboardLogoPNG
		}
		_, _ = w.Write(content)
		return
	case "/signin", "/signin.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if content, ok := readUnifiedDashboardFile(filepath.Join("frontend", "signin.html")); ok {
			_, _ = w.Write(content)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "signin page unavailable")
		return
	case "/signup", "/signup.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if content, ok := readUnifiedDashboardFile(filepath.Join("frontend", "signup.html")); ok {
			_, _ = w.Write(content)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "signup page unavailable")
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
	case "/",
		"/login", "/login.html", "/register", "/register.html",
		"/signin", "/signin.html", "/signup", "/signup.html", "/index.html",
		"/styles.css", "/app.js", "/auth.js",
		"/assets/baseline-logo.png",
		"/img/baseline logo.png", "/img/baseline favicon.png":
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

func loadUnifiedDashboardImage(requestPath string) []byte {
	switch strings.TrimSpace(requestPath) {
	case "/img/baseline favicon.png":
		if content, ok := readUnifiedDashboardFile(filepath.Join("img", "baseline favicon.png")); ok {
			return content
		}
	case "/img/baseline logo.png", "/assets/baseline-logo.png":
		if content, ok := readUnifiedDashboardFile(filepath.Join("img", "baseline logo.png")); ok {
			return content
		}
	}
	return nil
}

func readUnifiedDashboardFile(relPath string) ([]byte, bool) {
	relPath = filepath.Clean(relPath)
	if relPath == "." || relPath == string(filepath.Separator) {
		return nil, false
	}

	seen := map[string]struct{}{}
	for _, candidate := range dashboardFileCandidates(relPath) {
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		content, err := os.ReadFile(candidate)
		if err == nil {
			return content, true
		}
	}
	return nil, false
}

func dashboardFileCandidates(relPath string) []string {
	candidates := []string{
		relPath,
		filepath.Join("..", relPath),
		filepath.Join("..", "..", relPath),
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, relPath),
			filepath.Join(exeDir, "..", relPath),
		)
	}

	if _, currentFile, _, ok := runtime.Caller(0); ok {
		repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
		candidates = append(candidates, filepath.Join(repoRoot, relPath))
	}

	return candidates
}
