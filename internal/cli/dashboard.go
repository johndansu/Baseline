package cli

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baseline/baseline/internal/types"
)

type dashboardConfig struct {
	Addr       string
	APIBaseURL string
}

var errDashboardHelp = errors.New("dashboard help requested")

// HandleDashboard serves a local web dashboard backed by the Baseline API.
func HandleDashboard(args []string) {
	cfg, err := parseDashboardConfig(args, os.Getenv)
	if err != nil {
		if errors.Is(err, errDashboardHelp) {
			printDashboardUsage()
			os.Exit(types.ExitSuccess)
		}
		fmt.Printf("DASHBOARD FAILED: %v\n\n", err)
		printDashboardUsage()
		os.Exit(types.ExitSystemError)
	}

	handler, err := newDashboardHandler(cfg, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		fmt.Printf("DASHBOARD FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Baseline dashboard listening on %s\n", dashboardListenURL(cfg.Addr))
	fmt.Printf("Proxying requests to API: %s\n", cfg.APIBaseURL)
	fmt.Println("Press Ctrl+C to stop.")

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	go func() {
		<-signalCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("DASHBOARD FAILED: %v\n", err)
		os.Exit(types.ExitSystemError)
	}

	os.Exit(types.ExitSuccess)
}

func parseDashboardConfig(args []string, getenv func(string) string) (dashboardConfig, error) {
	cfg := dashboardConfig{
		Addr: "127.0.0.1:8091",
	}

	if explicit := strings.TrimSpace(getenv("BASELINE_DASHBOARD_API_URL")); explicit != "" {
		cfg.APIBaseURL = explicit
	} else {
		cfg.APIBaseURL = apiURLFromAPIAddr(getenv("BASELINE_API_ADDR"))
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			return dashboardConfig{}, errDashboardHelp
		case "--addr":
			if i+1 >= len(args) {
				return dashboardConfig{}, errors.New("--addr requires a value")
			}
			cfg.Addr = strings.TrimSpace(args[i+1])
			i++
		case "--api":
			if i+1 >= len(args) {
				return dashboardConfig{}, errors.New("--api requires a value")
			}
			cfg.APIBaseURL = strings.TrimSpace(args[i+1])
			i++
		default:
			return dashboardConfig{}, fmt.Errorf("unknown flag %s", args[i])
		}
	}

	if err := validateListenAddr(cfg.Addr); err != nil {
		return dashboardConfig{}, err
	}

	normalizedURL, err := validateAPIBaseURL(cfg.APIBaseURL)
	if err != nil {
		return dashboardConfig{}, err
	}
	cfg.APIBaseURL = normalizedURL

	return cfg, nil
}

func validateListenAddr(addr string) error {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return errors.New("--addr cannot be empty")
	}
	if strings.HasPrefix(trimmed, ":") {
		return nil
	}
	if _, _, err := net.SplitHostPort(trimmed); err != nil {
		return fmt.Errorf("invalid --addr value %q: %w", trimmed, err)
	}
	return nil
}

func validateAPIBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("--api cannot be empty")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid --api value: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("--api must use http or https")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", errors.New("--api must include a host")
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func apiURLFromAPIAddr(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "http://127.0.0.1:8080"
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return strings.TrimRight(trimmed, "/")
	}
	if strings.HasPrefix(trimmed, ":") {
		return "http://127.0.0.1" + trimmed
	}

	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "http://" + strings.TrimRight(trimmed, "/")
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + port
}

func dashboardListenURL(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if strings.HasPrefix(trimmed, ":") {
		return "http://127.0.0.1" + trimmed
	}
	if strings.HasPrefix(trimmed, "0.0.0.0:") {
		return "http://127.0.0.1:" + strings.TrimPrefix(trimmed, "0.0.0.0:")
	}
	if strings.HasPrefix(trimmed, "[::]:") {
		return "http://127.0.0.1:" + strings.TrimPrefix(trimmed, "[::]:")
	}
	return "http://" + trimmed
}

func newDashboardHandler(cfg dashboardConfig, client *http.Client) (http.Handler, error) {
	apiBase, err := url.Parse(cfg.APIBaseURL)
	if err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, renderDashboardHTML(cfg.APIBaseURL))
	})
	mux.HandleFunc("/dashboard-healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/proxy/", dashboardProxyHandler(apiBase, client))
	return mux, nil
}

func dashboardProxyHandler(apiBase *url.URL, client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeDashboardProxyError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/proxy")
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !isAllowedDashboardProxyPath(path) {
			writeDashboardProxyError(w, http.StatusNotFound, "endpoint not available in dashboard")
			return
		}

		target := *apiBase
		target.Path = joinURLPath(apiBase.Path, path)
		target.RawQuery = r.URL.RawQuery

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
		if err != nil {
			writeDashboardProxyError(w, http.StatusInternalServerError, "failed to build proxy request")
			return
		}
		req.Header.Set("Accept", "application/json")

		apiKey := strings.TrimSpace(r.Header.Get("X-Baseline-API-Key"))
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			writeDashboardProxyError(w, http.StatusBadGateway, "unable to reach Baseline API")
			return
		}
		defer resp.Body.Close()

		if contentType := strings.TrimSpace(resp.Header.Get("Content-Type")); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

func isAllowedDashboardProxyPath(path string) bool {
	allowedPrefixes := []string{
		"/healthz",
		"/readyz",
		"/v1/dashboard",
		"/v1/projects",
		"/v1/scans",
		"/v1/policies",
		"/v1/rulesets",
		"/v1/audit/events",
	}
	for _, prefix := range allowedPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func joinURLPath(basePath, path string) string {
	base := strings.TrimRight(basePath, "/")
	joined := "/" + strings.TrimLeft(path, "/")
	if base == "" {
		return joined
	}
	return base + joined
}

func writeDashboardProxyError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, message)
}

func printDashboardUsage() {
	fmt.Println("Usage: baseline dashboard [--addr <host:port>] [--api <url>]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --addr <host:port>  Dashboard bind address (default: 127.0.0.1:8091)")
	fmt.Println("  --api <url>         Baseline API base URL (default: http://127.0.0.1:8080)")
	fmt.Println("  --help, -h          Show this help message")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  BASELINE_DASHBOARD_API_URL  Default API URL for dashboard proxy")
	fmt.Println("  BASELINE_API_ADDR           Used to derive API URL when dashboard URL is not set")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  baseline api serve --addr :8080")
	fmt.Println("  baseline dashboard --addr 127.0.0.1:8091 --api http://127.0.0.1:8080")
}

func renderDashboardHTML(apiBaseURL string) string {
	return strings.ReplaceAll(dashboardHTMLTemplate, "{{API_BASE_URL}}", template.HTMLEscapeString(apiBaseURL))
}

const dashboardHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Baseline Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-ink: #071018;
      --bg-night: #0d1b2a;
      --card: rgba(9, 20, 34, 0.82);
      --card-soft: rgba(17, 35, 58, 0.72);
      --line: rgba(114, 170, 203, 0.35);
      --text: #edf6ff;
      --muted: #a9c2d7;
      --accent: #24c08f;
      --accent-hot: #ff8b3d;
      --danger: #ff5f6d;
      --ok: #20bf55;
      --warn: #f5b700;
      --shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: "Space Grotesk", "Trebuchet MS", sans-serif;
      background:
        radial-gradient(circle at 12% 8%, rgba(36, 192, 143, 0.22), transparent 42%),
        radial-gradient(circle at 90% 18%, rgba(255, 139, 61, 0.20), transparent 36%),
        radial-gradient(circle at 52% 118%, rgba(42, 104, 177, 0.32), transparent 56%),
        linear-gradient(155deg, var(--bg-ink), var(--bg-night));
      animation: fadeIn 520ms ease-out;
    }
    .shell {
      width: min(1180px, 95vw);
      margin: 0 auto;
      padding: 30px 0 48px;
    }
    .hero {
      display: grid;
      gap: 14px;
      margin-bottom: 20px;
      padding: 22px 24px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: linear-gradient(145deg, rgba(13, 31, 47, 0.88), rgba(8, 21, 37, 0.82));
      box-shadow: var(--shadow);
    }
    .title-wrap {
      display: flex;
      gap: 14px;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      font-size: clamp(1.4rem, 1.7rem + 1vw, 2.6rem);
      letter-spacing: 0.02em;
    }
    .tagline {
      color: var(--muted);
      font-size: 0.96rem;
      margin: 0;
    }
    .status-grid {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 12px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.04);
      font-size: 0.83rem;
      color: var(--muted);
    }
    .dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--warn);
      box-shadow: 0 0 12px rgba(245, 183, 0, 0.7);
    }
    .dot.ok { background: var(--ok); box-shadow: 0 0 12px rgba(32, 191, 85, 0.65); }
    .dot.bad { background: var(--danger); box-shadow: 0 0 12px rgba(255, 95, 109, 0.65); }
    .api-line {
      margin: 0;
      color: var(--muted);
      font-size: 0.84rem;
    }
    .mono {
      font-family: "JetBrains Mono", "Courier New", monospace;
      font-size: 0.83rem;
      color: #d8ebff;
      word-break: break-all;
    }
    .controls {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      gap: 10px;
      align-items: stretch;
      margin-bottom: 14px;
    }
    .input {
      width: 100%;
      border-radius: 12px;
      border: 1px solid rgba(125, 164, 190, 0.45);
      background: rgba(0, 8, 16, 0.46);
      color: var(--text);
      padding: 10px 12px;
      font-family: "JetBrains Mono", "Courier New", monospace;
      font-size: 0.83rem;
    }
    .btn {
      border: 1px solid transparent;
      border-radius: 12px;
      cursor: pointer;
      font-family: "Space Grotesk", "Trebuchet MS", sans-serif;
      font-weight: 600;
      letter-spacing: 0.01em;
      padding: 10px 14px;
      transition: transform 120ms ease, box-shadow 120ms ease, background 120ms ease;
    }
    .btn:active { transform: translateY(1px); }
    .btn.save {
      background: linear-gradient(140deg, #1f9d79, #17b089);
      color: #052218;
      box-shadow: 0 8px 24px rgba(25, 176, 137, 0.32);
    }
    .btn.refresh {
      background: linear-gradient(140deg, #f6b03f, #ff8b3d);
      color: #3d1e00;
      box-shadow: 0 8px 24px rgba(255, 139, 61, 0.28);
    }
    .grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      margin-bottom: 16px;
    }
    .metric {
      grid-column: span 2;
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px 14px 16px;
      background: var(--card);
      box-shadow: var(--shadow);
    }
    .metric .label {
      font-size: 0.8rem;
      color: var(--muted);
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.09em;
    }
    .metric .value {
      font-size: clamp(1.2rem, 1.2rem + 1vw, 2.1rem);
      font-weight: 700;
      color: #ffffff;
      line-height: 1.1;
    }
    .panel-grid {
      display: grid;
      gap: 12px;
      grid-template-columns: 1.5fr 1fr;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px 14px 10px;
      background: var(--card-soft);
      box-shadow: var(--shadow);
      min-height: 220px;
    }
    .panel.full {
      grid-column: 1 / -1;
      min-height: 180px;
    }
    .panel h2 {
      margin: 0 0 10px;
      font-size: 1rem;
      letter-spacing: 0.01em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.83rem;
    }
    th, td {
      text-align: left;
      padding: 9px 8px;
      border-bottom: 1px solid rgba(174, 211, 235, 0.14);
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      font-size: 0.72rem;
    }
    .status {
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }
    .status.pass { color: var(--ok); }
    .status.warn { color: var(--warn); }
    .status.fail { color: var(--danger); }
    .status.unknown { color: var(--muted); }
    .list {
      margin: 0;
      padding: 0;
      list-style: none;
      display: grid;
      gap: 8px;
    }
    .list li {
      padding: 8px 10px;
      border: 1px solid rgba(255, 255, 255, 0.09);
      border-radius: 10px;
      background: rgba(8, 20, 34, 0.72);
      font-size: 0.84rem;
      display: flex;
      justify-content: space-between;
      gap: 10px;
    }
    .note {
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 0.78rem;
    }
    .error {
      min-height: 24px;
      margin-top: 8px;
      color: #ffd7c0;
      font-size: 0.84rem;
    }
    @media (max-width: 980px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric { grid-column: span 1; }
      .panel-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 660px) {
      .controls { grid-template-columns: 1fr; }
      .shell { width: min(1180px, 94vw); padding-top: 18px; }
      th:nth-child(4), td:nth-child(4) { display: none; }
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="title-wrap">
        <div>
          <h1>Baseline Dashboard</h1>
          <p class="tagline">Live policy, scan, and audit telemetry for your Baseline API runtime.</p>
        </div>
        <div class="status-grid">
          <span class="pill"><span id="healthDot" class="dot"></span><span id="healthText">API health: pending</span></span>
          <span class="pill"><span id="readyDot" class="dot"></span><span id="readyText">API readiness: pending</span></span>
          <span class="pill"><span id="lastUpdated">Last updated: never</span></span>
        </div>
      </div>
      <p class="api-line">Dashboard proxy target: <span id="apiBase" class="mono">{{API_BASE_URL}}</span></p>
    </section>

    <section class="controls">
      <input id="apiKeyInput" class="input" type="password" placeholder="Paste Baseline API key (stored in this browser only)">
      <button id="saveKeyButton" class="btn save" type="button">Save Key</button>
      <button id="refreshButton" class="btn refresh" type="button">Refresh</button>
    </section>

    <section class="grid">
      <article class="metric"><div class="label">Projects</div><div class="value" id="metricProjects">-</div></article>
      <article class="metric"><div class="label">Scans</div><div class="value" id="metricScans">-</div></article>
      <article class="metric"><div class="label">Failing Scans</div><div class="value" id="metricFailingScans">-</div></article>
      <article class="metric"><div class="label">Blocking Violations</div><div class="value" id="metricBlockingViolations">-</div></article>
      <article class="metric"><div class="label">Tracked Policies</div><div class="value" id="metricPolicies">-</div></article>
      <article class="metric"><div class="label">Recent Events</div><div class="value" id="metricAuditEvents">-</div></article>
    </section>

    <section class="panel-grid">
      <article class="panel">
        <h2>Recent Scans</h2>
        <table>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Status</th>
              <th>Violations</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody id="scansBody">
            <tr><td colspan="4">Waiting for data...</td></tr>
          </tbody>
        </table>
      </article>
      <article class="panel">
        <h2>Top Violations</h2>
        <ul class="list" id="violationsList">
          <li><span>No violation data yet.</span></li>
        </ul>
        <p class="note">Computed from aggregate payloads returned by <span class="mono">GET /v1/dashboard</span>.</p>
      </article>
      <article class="panel full">
        <h2>Latest Audit Events</h2>
        <table>
          <thead>
            <tr>
              <th>Event</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody id="eventsBody">
            <tr><td colspan="2">Waiting for data...</td></tr>
          </tbody>
        </table>
      </article>
    </section>

    <div id="errorText" class="error"></div>
  </main>

  <script>
    (function () {
      var state = {
        apiKey: ""
      };

      var apiKeyInput = document.getElementById("apiKeyInput");
      var saveKeyButton = document.getElementById("saveKeyButton");
      var refreshButton = document.getElementById("refreshButton");
      var errorText = document.getElementById("errorText");
      var scansBody = document.getElementById("scansBody");
      var eventsBody = document.getElementById("eventsBody");
      var violationsList = document.getElementById("violationsList");

      function setDot(dotID, textID, text, mode) {
        var dot = document.getElementById(dotID);
        var label = document.getElementById(textID);
        dot.className = "dot";
        if (mode === "ok") {
          dot.classList.add("ok");
        } else if (mode === "bad") {
          dot.classList.add("bad");
        }
        label.textContent = text;
      }

      function setMetric(id, value) {
        document.getElementById(id).textContent = String(value);
      }

      function formatTime(value) {
        if (!value) {
          return "-";
        }
        var date = new Date(value);
        if (Number.isNaN(date.getTime())) {
          return value;
        }
        return date.toLocaleString();
      }

      function short(value, length) {
        if (!value) {
          return "-";
        }
        if (value.length <= length) {
          return value;
        }
        return value.slice(0, length) + "...";
      }

      function escapeHTML(value) {
        return String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      async function apiGet(path, authRequired) {
        var headers = { Accept: "application/json" };
        if (authRequired && state.apiKey) {
          headers["X-Baseline-API-Key"] = state.apiKey;
        }
        var response = await fetch("/proxy" + path, {
          method: "GET",
          headers: headers
        });

        var text = await response.text();
        var payload = null;
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (_) {
            payload = { raw: text };
          }
        }

        if (!response.ok) {
          var message = "request failed";
          if (payload && payload.error && payload.error.message) {
            message = payload.error.message;
          } else if (payload && payload.raw) {
            message = payload.raw;
          }
          throw new Error(path + ": " + response.status + " " + message);
        }
        return payload || {};
      }

      function renderScans(scans) {
        if (!Array.isArray(scans) || scans.length === 0) {
          scansBody.innerHTML = "<tr><td colspan='4'>No scans found.</td></tr>";
          return;
        }

        var sorted = scans.slice().sort(function (a, b) {
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        });

        scansBody.innerHTML = sorted.slice(0, 12).map(function (scan) {
          var status = String(scan.status || "unknown").toLowerCase();
          var statusClass = ["pass", "fail", "warn"].indexOf(status) >= 0 ? status : "unknown";
          var id = escapeHTML(short(String(scan.id || "-"), 16));
          var violationCount = Array.isArray(scan.violations) ? scan.violations.length : 0;

          return [
            "<tr>",
              "<td class='mono'>", id, "</td>",
              "<td class='status ", statusClass, "'>", escapeHTML(status), "</td>",
              "<td>", String(violationCount), "</td>",
              "<td>", escapeHTML(formatTime(scan.created_at)), "</td>",
            "</tr>"
          ].join("");
        }).join("");
      }

      function renderTopViolations(topViolations) {
        if (!Array.isArray(topViolations) || topViolations.length === 0) {
          violationsList.innerHTML = "<li><span>No violation data yet.</span></li>";
          return;
        }

        var entries = topViolations.slice().sort(function (a, b) {
          return Number(b.count || 0) - Number(a.count || 0);
        });

        if (entries.length === 0) {
          violationsList.innerHTML = "<li><span>No violation data yet.</span></li>";
          return;
        }

        violationsList.innerHTML = entries.slice(0, 8).map(function (entry) {
          return [
            "<li>",
              "<span class='mono'>", escapeHTML(entry.policyID), "</span>",
              "<strong>", String(entry.count), "</strong>",
            "</li>"
          ].join("");
        }).join("");
      }

      function renderEvents(events) {
        if (!Array.isArray(events) || events.length === 0) {
          eventsBody.innerHTML = "<tr><td colspan='2'>No audit events found.</td></tr>";
          return;
        }

        var sorted = events.slice().sort(function (a, b) {
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        });

        eventsBody.innerHTML = sorted.slice(0, 12).map(function (event) {
          return [
            "<tr>",
              "<td>", escapeHTML(String(event.event_type || "-")), "</td>",
              "<td>", escapeHTML(formatTime(event.created_at)), "</td>",
            "</tr>"
          ].join("");
        }).join("");
      }

      function setLastUpdated() {
        document.getElementById("lastUpdated").textContent = "Last updated: " + new Date().toLocaleTimeString();
      }

      function resetProtectedViews() {
        setMetric("metricProjects", "-");
        setMetric("metricScans", "-");
        setMetric("metricFailingScans", "-");
        setMetric("metricBlockingViolations", "-");
        setMetric("metricPolicies", "-");
        setMetric("metricAuditEvents", "-");
        scansBody.innerHTML = "<tr><td colspan='4'>API key required to load scan history.</td></tr>";
        eventsBody.innerHTML = "<tr><td colspan='2'>API key required to load audit events.</td></tr>";
        violationsList.innerHTML = "<li><span>API key required to load violation stats.</span></li>";
      }

      async function refreshDashboard() {
        errorText.textContent = "";

        try {
          var health = await apiGet("/healthz", false);
          if (health && health.status === "ok") {
            setDot("healthDot", "healthText", "API health: ok", "ok");
          } else {
            setDot("healthDot", "healthText", "API health: degraded", "bad");
          }
        } catch (err) {
          setDot("healthDot", "healthText", "API health: unavailable", "bad");
          errorText.textContent = err.message;
        }

        try {
          var ready = await apiGet("/readyz", false);
          if (ready && ready.status === "ready") {
            setDot("readyDot", "readyText", "API readiness: ready", "ok");
          } else {
            setDot("readyDot", "readyText", "API readiness: not ready", "bad");
          }
        } catch (err) {
          setDot("readyDot", "readyText", "API readiness: unavailable", "bad");
          if (!errorText.textContent) {
            errorText.textContent = err.message;
          }
        }

        if (!state.apiKey) {
          resetProtectedViews();
          setLastUpdated();
          return;
        }

        try {
          var dashboardResp = await apiGet("/v1/dashboard", true);
          var projectsResp = await apiGet("/v1/projects", true);

          var metrics = dashboardResp.metrics || {};
          var scans = Array.isArray(dashboardResp.recent_scans) ? dashboardResp.recent_scans : [];
          var topViolations = Array.isArray(dashboardResp.top_violations) ? dashboardResp.top_violations : [];
          var events = Array.isArray(dashboardResp.recent_events) ? dashboardResp.recent_events : [];
          var projects = Array.isArray(projectsResp.projects) ? projectsResp.projects : [];

          setMetric("metricProjects", metrics.projects || projects.length);
          setMetric("metricScans", metrics.scans || scans.length);
          setMetric("metricFailingScans", metrics.failing_scans || 0);
          setMetric("metricBlockingViolations", metrics.blocking_violations || 0);
          setMetric("metricPolicies", topViolations.length);
          setMetric("metricAuditEvents", events.length);

          renderScans(scans);
          renderTopViolations(topViolations);
          renderEvents(events);
        } catch (err) {
          errorText.textContent = err.message;
          resetProtectedViews();
        }

        setLastUpdated();
      }

      saveKeyButton.addEventListener("click", function () {
        state.apiKey = apiKeyInput.value.trim();
        refreshDashboard();
      });

      refreshButton.addEventListener("click", function () {
        refreshDashboard();
      });

      apiKeyInput.value = state.apiKey;
      refreshDashboard();
      window.setInterval(refreshDashboard, 30000);
    })();
  </script>
</body>
</html>
`
