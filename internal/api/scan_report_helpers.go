package api

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func clonePoliciesLocked(src map[string][]PolicyVersion) map[string][]PolicyVersion {
	out := make(map[string][]PolicyVersion, len(src))
	for name, versions := range src {
		out[name] = append([]PolicyVersion(nil), versions...)
	}
	return out
}

func summarizePolicies(policies map[string][]PolicyVersion) []PolicySummary {
	out := make([]PolicySummary, 0, len(policies))
	for name, versions := range policies {
		if len(versions) == 0 {
			continue
		}
		latest := versions[len(versions)-1]
		out = append(out, PolicySummary{
			Name:          name,
			LatestVersion: latest.Version,
			UpdatedAt:     latest.PublishedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func normalizeViolations(in []ScanViolation) []ScanViolation {
	out := make([]ScanViolation, 0, len(in))
	for _, item := range in {
		policyID := strings.TrimSpace(item.PolicyID)
		if policyID == "" {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(item.Severity))
		if severity == "" {
			severity = "block"
		}
		out = append(out, ScanViolation{
			PolicyID: policyID,
			Severity: severity,
			Message:  strings.TrimSpace(item.Message),
		})
	}
	return out
}

func dedupeNonEmpty(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func renderScanTextReport(scan ScanSummary) string {
	lines := []string{
		fmt.Sprintf("scan_id: %s", scan.ID),
		fmt.Sprintf("project_id: %s", scan.ProjectID),
		fmt.Sprintf("commit_sha: %s", scan.CommitSHA),
		fmt.Sprintf("status: %s", scan.Status),
		fmt.Sprintf("created_at: %s", scan.CreatedAt.Format(time.RFC3339)),
		fmt.Sprintf("violations: %d", len(scan.Violations)),
	}
	for _, violation := range scan.Violations {
		lines = append(lines,
			fmt.Sprintf("- [%s] %s (%s)", violation.PolicyID, violation.Message, violation.Severity),
		)
	}
	return strings.Join(lines, "\n") + "\n"
}

func renderScanSARIF(scan ScanSummary) map[string]any {
	results := make([]map[string]any, 0, len(scan.Violations))
	rules := make([]map[string]any, 0, len(scan.Violations))
	ruleSeen := map[string]struct{}{}

	for _, violation := range scan.Violations {
		if _, ok := ruleSeen[violation.PolicyID]; !ok {
			ruleSeen[violation.PolicyID] = struct{}{}
			rules = append(rules, map[string]any{
				"id": violation.PolicyID,
				"shortDescription": map[string]any{
					"text": violation.PolicyID + " policy violation",
				},
				"properties": map[string]any{
					"severity": violation.Severity,
				},
			})
		}

		results = append(results, map[string]any{
			"ruleId": violation.PolicyID,
			"level":  sarifLevelFromSeverity(violation.Severity),
			"message": map[string]any{
				"text": violation.Message,
			},
		})
	}

	return map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "Baseline API",
						"informationUri": "https://github.com/baseline/baseline",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}
}

func sarifLevelFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "block":
		return "error"
	case "warn":
		return "warning"
	default:
		return "note"
	}
}
