package api

import (
	"embed"
	"encoding/json"
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
	case "/", "/index.html":
		serveDashboardPublicFile(w, "index.html", "text/html; charset=utf-8")
		return
	case "/cli-guide", "/cli-guide.html":
		serveDashboardPublicFile(w, "cli-guide.html", "text/html; charset=utf-8")
		return
	case "/dashboard", "/dashboard.html":
		serveDashboardPublicFile(w, "dashboard.html", "text/html; charset=utf-8")
		return
	case "/styles.css":
		serveDashboardPublicFile(w, filepath.Join("css", "styles.css"), "text/css; charset=utf-8")
		return
	case "/js/runtime-config.js":
		serveDashboardRuntimeConfig(w)
		return
	case "/app.js":
		fallthrough
	case "/auth.js":
		serveDashboardPublicFile(w, filepath.Join("js", strings.TrimPrefix(r.URL.Path, "/")), "application/javascript; charset=utf-8")
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
		serveDashboardPublicFile(w, "signin.html", "text/html; charset=utf-8")
		return
	case "/signup", "/signup.html":
		serveDashboardPublicFile(w, "signup.html", "text/html; charset=utf-8")
		return
	default:
		if strings.HasPrefix(r.URL.Path, "/css/") {
			serveDashboardPublicFile(w, strings.TrimPrefix(r.URL.Path, "/"), "text/css; charset=utf-8")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/js/") {
			serveDashboardPublicFile(w, strings.TrimPrefix(r.URL.Path, "/"), "application/javascript; charset=utf-8")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/images/") {
			serveDashboardPublicFile(w, strings.TrimPrefix(r.URL.Path, "/"), "image/png")
			return
		}
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
	trimmed := strings.TrimSpace(path)
	switch trimmed {
	case "/",
		"/login", "/login.html", "/register", "/register.html",
		"/signin", "/signin.html", "/signup", "/signup.html", "/index.html",
		"/cli-guide", "/cli-guide.html",
		"/dashboard", "/dashboard.html",
		"/styles.css", "/app.js", "/auth.js", "/js/runtime-config.js",
		"/assets/baseline-logo.png",
		"/img/baseline logo.png", "/img/baseline favicon.png":
		return true
	}
	return strings.HasPrefix(trimmed, "/css/") ||
		strings.HasPrefix(trimmed, "/js/") ||
		strings.HasPrefix(trimmed, "/assets/images/")
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
		if content, ok := readUnifiedDashboardFile(filepath.Join("assets", "images", "baseline favicon.png")); ok {
			return content
		}
	case "/img/baseline logo.png", "/assets/baseline-logo.png":
		if content, ok := readUnifiedDashboardFile(filepath.Join("assets", "images", "baseline logo.png")); ok {
			return content
		}
	}
	return nil
}

func serveDashboardPublicFile(w http.ResponseWriter, relPath, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	if content, ok := readUnifiedDashboardFile(relPath); ok {
		_, _ = w.Write(content)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "dashboard asset unavailable")
}

func serveDashboardRuntimeConfig(w http.ResponseWriter) {
	config := map[string]string{
		"SUPABASE_URL":              strings.TrimSpace(os.Getenv("SUPABASE_URL")),
		"SUPABASE_ANON_KEY":         strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY")),
		"SUPABASE_AUTH_REDIRECT_TO": strings.TrimSpace(os.Getenv("SUPABASE_AUTH_REDIRECT_TO")),
	}

	payload, err := json.Marshal(config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to render runtime config")
		return
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("window.RUNTIME_CONFIG = " + string(payload) + ";\n"))
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
		filepath.Join("frontend-nodejs", "public", relPath),
		filepath.Join("frontend", relPath),
		filepath.Join("..", relPath),
		filepath.Join("..", "frontend-nodejs", "public", relPath),
		filepath.Join("..", "frontend", relPath),
		filepath.Join("..", "..", relPath),
		filepath.Join("..", "..", "frontend-nodejs", "public", relPath),
		filepath.Join("..", "..", "frontend", relPath),
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
