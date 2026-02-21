package api

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type openAPISpecDocument struct {
	Paths map[string]map[string]openAPIOperation `yaml:"paths"`
}

type openAPIOperation struct {
	Responses map[string]any `yaml:"responses"`
}

type contractFixture struct {
	projectID   string
	scanID      string
	policyName  string
	ruleset     string
	apiKeyID    string
	githubOwner string
	githubRepo  string
	headSHA     string
}

func TestOpenAPIOperationsReturnDocumentedStatuses(t *testing.T) {
	ghUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":123}`))
	}))
	defer ghUpstream.Close()

	glUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer glUpstream.Close()

	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	cfg.DashboardSessionEnabled = true
	cfg.DashboardSessionRole = RoleAdmin
	cfg.SelfServiceEnabled = true
	cfg.EnrollmentTokens = map[string]Role{
		"enroll-viewer": RoleViewer,
	}
	cfg.GitHubWebhookSecret = "github-secret"
	cfg.GitLabWebhookToken = "gitlab-token"
	cfg.GitHubAPIToken = "gh-api-token"
	cfg.GitHubAPIBaseURL = ghUpstream.URL
	cfg.GitLabAPIToken = "gl-api-token"
	cfg.GitLabAPIBaseURL = glUpstream.URL

	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	fixture := seedContractFixture(t, client, ts.URL)

	// Create dashboard session once so session endpoints can return active responses.
	resp, body := mustRequest(t, client, http.MethodPost, ts.URL+"/v1/auth/session", nil, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("session setup failed, expected 201 got %d body=%s", resp.StatusCode, body)
	}

	spec := loadOpenAPISpec(t)
	paths := sortedMapKeys(spec.Paths)
	for _, path := range paths {
		ops := spec.Paths[path]
		methods := sortedMapKeys(ops)
		for _, method := range methods {
			op := ops[method]
			allowedStatuses := parseDeclaredResponseCodes(t, path, method, op)
			if len(allowedStatuses) == 0 {
				t.Fatalf("spec operation has no numeric responses: %s %s", strings.ToUpper(method), path)
			}

			urlPath := concretePath(path, fixture)
			payload, headers := contractRequestPayloadAndHeaders(path, method, fixture)

			resp, body = mustRequest(t, client, strings.ToUpper(method), ts.URL+urlPath, payload, headers)
			if _, ok := allowedStatuses[resp.StatusCode]; !ok {
				t.Fatalf(
					"undocumented response status for %s %s: got %d, allowed=%v, body=%s",
					strings.ToUpper(method),
					urlPath,
					resp.StatusCode,
					sortedStatusList(allowedStatuses),
					body,
				)
			}
		}
	}
}

func TestContractResponseShapesForCoreEndpoints(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]Role{
		"admin-key": RoleAdmin,
	}
	server, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	client := &http.Client{}
	fixture := seedContractFixture(t, client, ts.URL)
	headers := map[string]string{
		"Authorization": "Bearer admin-key",
	}

	resp, body := mustRequest(t, client, http.MethodGet, ts.URL+"/v1/dashboard", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "metrics", "recent_scans", "top_violations", "recent_events", "policies")

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans?project_id="+fixture.projectID, nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scans list response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "scans")

	resp, body = mustRequest(t, client, http.MethodPost, ts.URL+"/v1/scans", map[string]any{
		"project_id": fixture.projectID,
		"commit_sha": "shapecheck-commit",
		"status":     "warn",
	}, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("scan create response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "id", "project_id", "commit_sha", "status", "violations", "created_at")

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+fixture.scanID+"/report?format=json", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan json report response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "scan")

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+fixture.scanID+"/report?format=text", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan text report response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "scan_id:") {
		t.Fatalf("text report missing scan_id line: body=%s", body)
	}

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/scans/"+fixture.scanID+"/report?format=sarif", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan sarif report response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "version", "$schema", "runs")

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/policies", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policies response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "policies")

	resp, body = mustRequest(t, client, http.MethodGet, ts.URL+"/v1/audit/events?project_id="+fixture.projectID, nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit events response status mismatch: got %d body=%s", resp.StatusCode, body)
	}
	assertJSONContainsTopLevelKeys(t, body, "events")
}

func seedContractFixture(t *testing.T, client *http.Client, baseURL string) contractFixture {
	t.Helper()

	fixture := contractFixture{
		projectID:   "proj_contract",
		policyName:  "baseline-contract",
		ruleset:     "contract-ruleset-v1",
		githubOwner: "acme",
		githubRepo:  "payments",
		headSHA:     "abc123def",
	}

	resp, body := mustRequest(t, client, http.MethodPost, baseURL+"/v1/projects", map[string]any{
		"id":   fixture.projectID,
		"name": "contract-project",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("project seed failed, expected 201 got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, baseURL+"/v1/scans", map[string]any{
		"project_id": fixture.projectID,
		"commit_sha": fixture.headSHA,
		"status":     "pass",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("scan seed failed, expected 201 got %d body=%s", resp.StatusCode, body)
	}
	var scan ScanSummary
	if err := json.Unmarshal([]byte(body), &scan); err != nil {
		t.Fatalf("scan seed unmarshal failed: %v body=%s", err, body)
	}
	if strings.TrimSpace(scan.ID) == "" {
		t.Fatalf("scan seed returned empty id: body=%s", body)
	}
	fixture.scanID = scan.ID

	resp, body = mustRequest(t, client, http.MethodPost, baseURL+"/v1/policies/"+fixture.policyName+"/versions", map[string]any{
		"version": "v1",
		"content": map[string]any{"rule": "no-secrets"},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("policy seed failed, expected 201 got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, baseURL+"/v1/rulesets", map[string]any{
		"version":      fixture.ruleset,
		"policy_names": []string{fixture.policyName},
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ruleset seed failed, expected 201 got %d body=%s", resp.StatusCode, body)
	}

	resp, body = mustRequest(t, client, http.MethodPost, baseURL+"/v1/api-keys", map[string]any{
		"name": "contract-managed-key",
		"role": "viewer",
	}, map[string]string{
		"Authorization": "Bearer admin-key",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("api key seed failed, expected 201 got %d body=%s", resp.StatusCode, body)
	}
	var keyResp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &keyResp); err != nil {
		t.Fatalf("api key seed unmarshal failed: %v body=%s", err, body)
	}
	if strings.TrimSpace(keyResp.ID) == "" {
		t.Fatalf("api key seed returned empty id: body=%s", body)
	}
	fixture.apiKeyID = keyResp.ID

	return fixture
}

func loadOpenAPISpec(t *testing.T) openAPISpecDocument {
	t.Helper()
	var spec openAPISpecDocument
	if err := yaml.Unmarshal(openAPISpecYAML, &spec); err != nil {
		t.Fatalf("failed to parse embedded openapi document: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("openapi document has no paths")
	}
	return spec
}

func parseDeclaredResponseCodes(t *testing.T, path, method string, op openAPIOperation) map[int]struct{} {
	t.Helper()
	out := map[int]struct{}{}
	for raw := range op.Responses {
		code, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		out[code] = struct{}{}
	}
	return out
}

func concretePath(path string, fixture contractFixture) string {
	result := path
	replacements := map[string]string{
		"{id}":         fixture.apiKeyID,
		"{project_id}": fixture.projectID,
		"{scan_id}":    fixture.scanID,
		"{name}":       fixture.policyName,
		"{version}":    fixture.ruleset,
	}
	for token, value := range replacements {
		result = strings.ReplaceAll(result, token, value)
	}
	if strings.HasSuffix(result, "/report") {
		result += "?format=json"
	}
	return result
}

func contractRequestPayloadAndHeaders(path, method string, fixture contractFixture) (any, map[string]string) {
	headers := map[string]string{}
	if strings.HasPrefix(path, "/v1/") {
		headers["Authorization"] = "Bearer admin-key"
	}

	method = strings.ToUpper(method)
	switch {
	case path == "/v1/auth/session" && method == http.MethodDelete:
		headers["X-Baseline-CSRF"] = "1"
		return nil, headers
	case path == "/v1/auth/register" && method == http.MethodPost:
		return map[string]any{"enrollment_token": "enroll-viewer"}, headers
	case path == "/v1/api-keys" && method == http.MethodPost:
		return map[string]any{"name": "contract-ephemeral", "role": "viewer"}, headers
	case path == "/v1/integrations/github/webhook" && method == http.MethodPost:
		// Missing signature is valid contract behavior (403) and proves route wiring.
		return map[string]any{"action": "opened", "pull_request": map[string]any{"number": 1}}, headers
	case path == "/v1/integrations/gitlab/webhook" && method == http.MethodPost:
		// Missing token is valid contract behavior (403) and proves route wiring.
		return map[string]any{"object_kind": "merge_request"}, headers
	case path == "/v1/integrations/github/check-runs" && method == http.MethodPost:
		return map[string]any{
			"owner":      fixture.githubOwner,
			"repository": fixture.githubRepo,
			"head_sha":   fixture.headSHA,
			"name":       "baseline/enforce",
			"status":     "completed",
			"conclusion": "success",
		}, headers
	case path == "/v1/integrations/gitlab/statuses" && method == http.MethodPost:
		return map[string]any{
			"project_id": fixture.githubOwner + "/" + fixture.githubRepo,
			"sha":        fixture.headSHA,
			"state":      "success",
			"name":       "baseline/enforce",
		}, headers
	case path == "/v1/projects" && method == http.MethodPost:
		return map[string]any{"name": "contract-created-project"}, headers
	case path == "/v1/scans" && method == http.MethodPost:
		return map[string]any{"project_id": fixture.projectID, "status": "pass"}, headers
	case path == "/v1/policies/{name}/versions" && method == http.MethodPost:
		return map[string]any{
			"version": "v-contract-" + strconv.FormatInt(time.Now().UnixNano(), 10),
			"content": map[string]any{"rule": "contract"},
		}, headers
	case path == "/v1/rulesets" && method == http.MethodPost:
		return map[string]any{
			"version":      "ruleset-contract-" + strconv.FormatInt(time.Now().UnixNano(), 10),
			"policy_names": []string{fixture.policyName},
		}, headers
	default:
		return nil, headers
	}
}

func sortedMapKeys[T any](in map[string]T) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedStatusList(in map[int]struct{}) []int {
	out := make([]int, 0, len(in))
	for code := range in {
		out = append(out, code)
	}
	sort.Ints(out)
	return out
}

func assertJSONContainsTopLevelKeys(t *testing.T, raw string, keys ...string) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("invalid JSON payload: %v raw=%s", err, raw)
	}
	for _, key := range keys {
		if _, ok := payload[key]; !ok {
			t.Fatalf("missing top-level key %q in payload: %s", key, raw)
		}
	}
}
