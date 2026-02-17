(function () {
  var storageKey = "baseline_api_dashboard_key";
  var state = {
    apiKey: localStorage.getItem(storageKey) || "",
    sessionEnabled: false,
  };

  var els = {
    healthPill: document.getElementById("healthPill"),
    readyPill: document.getElementById("readyPill"),
    authPill: document.getElementById("authPill"),
    lastUpdated: document.getElementById("lastUpdated"),
    sessionInfo: document.getElementById("sessionInfo"),
    errorText: document.getElementById("errorText"),
    apiKeyInput: document.getElementById("apiKeyInput"),
    saveKeyBtn: document.getElementById("saveKeyBtn"),
    clearKeyBtn: document.getElementById("clearKeyBtn"),
    startSessionBtn: document.getElementById("startSessionBtn"),
    endSessionBtn: document.getElementById("endSessionBtn"),
    metricProjects: document.getElementById("metricProjects"),
    metricScans: document.getElementById("metricScans"),
    metricFailing: document.getElementById("metricFailing"),
    metricBlocking: document.getElementById("metricBlocking"),
    scansBody: document.getElementById("scansBody"),
    violationsList: document.getElementById("violationsList"),
    eventsBody: document.getElementById("eventsBody"),
    projectsBody: document.getElementById("projectsBody"),
    projectForm: document.getElementById("projectForm"),
    projectName: document.getElementById("projectName"),
    projectBranch: document.getElementById("projectBranch"),
    projectPolicySet: document.getElementById("projectPolicySet"),
  };

  function setPill(el, text, mode) {
    if (!el) return;
    el.classList.remove("ok", "bad", "pending");
    if (mode) {
      el.classList.add(mode);
    }
    el.textContent = text;
  }

  function setError(message) {
    if (!els.errorText) return;
    els.errorText.textContent = message || "";
  }

  function setMetric(el, value) {
    if (!el) return;
    el.textContent = String(value);
  }

  function formatDate(value) {
    if (!value) return "-";
    var parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return value;
    }
    return parsed.toLocaleString();
  }

  function short(value, size) {
    var text = String(value || "");
    if (text.length <= size) {
      return text;
    }
    return text.slice(0, size) + "...";
  }

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  async function request(path, method, body, requiresAuth) {
    var headers = { Accept: "application/json" };
    if (body) {
      headers["Content-Type"] = "application/json";
    }
    if (requiresAuth && state.apiKey) {
      headers.Authorization = "Bearer " + state.apiKey;
    }

    var response = await fetch(path, {
      method: method || "GET",
      headers: headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    var text = await response.text();
    var payload = {};
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
      var error = new Error(path + ": " + response.status + " " + message);
      error.statusCode = response.status;
      throw error;
    }

    return payload;
  }

  function renderScans(scans) {
    if (!Array.isArray(scans) || scans.length === 0) {
      els.scansBody.innerHTML = "<tr><td colspan='4'>No scans found.</td></tr>";
      return;
    }

    var sorted = scans.slice().sort(function (a, b) {
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

    els.scansBody.innerHTML = sorted.slice(0, 12).map(function (scan) {
      var status = String(scan.status || "unknown").toLowerCase();
      var statusClass = ["pass", "fail", "warn"].indexOf(status) >= 0 ? status : "unknown";
      var violationCount = Array.isArray(scan.violations) ? scan.violations.length : 0;
      return [
        "<tr>",
        "<td class='mono'>", escapeHTML(short(scan.id || "-", 16)), "</td>",
        "<td class='status ", statusClass, "'>", escapeHTML(status), "</td>",
        "<td>", String(violationCount), "</td>",
        "<td>", escapeHTML(formatDate(scan.created_at)), "</td>",
        "</tr>",
      ].join("");
    }).join("");
  }

  function renderTopViolations(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
      els.violationsList.innerHTML = "<li>No violation data.</li>";
      return;
    }

    var sorted = entries.slice().sort(function (a, b) {
      return Number(b.count || 0) - Number(a.count || 0);
    });

    els.violationsList.innerHTML = sorted.slice(0, 10).map(function (entry) {
      return [
        "<li>",
        "<span class='mono'>", escapeHTML(entry.policy_id || "-"), "</span>",
        "<strong>", String(entry.count || 0), "</strong>",
        "</li>",
      ].join("");
    }).join("");
  }

  function renderEvents(events) {
    if (!Array.isArray(events) || events.length === 0) {
      els.eventsBody.innerHTML = "<tr><td colspan='2'>No events found.</td></tr>";
      return;
    }

    var sorted = events.slice().sort(function (a, b) {
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

    els.eventsBody.innerHTML = sorted.slice(0, 12).map(function (event) {
      return [
        "<tr>",
        "<td>", escapeHTML(String(event.event_type || "-")), "</td>",
        "<td>", escapeHTML(formatDate(event.created_at)), "</td>",
        "</tr>",
      ].join("");
    }).join("");
  }

  function renderProjects(projects) {
    if (!Array.isArray(projects) || projects.length === 0) {
      els.projectsBody.innerHTML = "<tr><td colspan='3'>No projects found.</td></tr>";
      return;
    }

    els.projectsBody.innerHTML = projects.map(function (project) {
      return [
        "<tr>",
        "<td>", escapeHTML(String(project.name || "-")), "</td>",
        "<td class='mono'>", escapeHTML(String(project.default_branch || "-")), "</td>",
        "<td class='mono'>", escapeHTML(String(project.policy_set || "-")), "</td>",
        "</tr>",
      ].join("");
    }).join("");
  }

  function resetProtectedData(message) {
    setMetric(els.metricProjects, "-");
    setMetric(els.metricScans, "-");
    setMetric(els.metricFailing, "-");
    setMetric(els.metricBlocking, "-");
    els.scansBody.innerHTML = "<tr><td colspan='4'>" + escapeHTML(message) + "</td></tr>";
    els.eventsBody.innerHTML = "<tr><td colspan='2'>" + escapeHTML(message) + "</td></tr>";
    els.projectsBody.innerHTML = "<tr><td colspan='3'>" + escapeHTML(message) + "</td></tr>";
    els.violationsList.innerHTML = "<li>" + escapeHTML(message) + "</li>";
  }

  async function refreshServerStatus() {
    try {
      var health = await request("/healthz", "GET", null, false);
      setPill(
        els.healthPill,
        health && health.status === "ok" ? "Health: ok" : "Health: degraded",
        health && health.status === "ok" ? "ok" : "bad"
      );
    } catch (_) {
      setPill(els.healthPill, "Health: unavailable", "bad");
    }

    try {
      var ready = await request("/readyz", "GET", null, false);
      setPill(
        els.readyPill,
        ready && ready.status === "ready" ? "Ready: ready" : "Ready: not ready",
        ready && ready.status === "ready" ? "ok" : "bad"
      );
    } catch (_) {
      setPill(els.readyPill, "Ready: unavailable", "bad");
    }
  }

  async function refreshSessionState() {
    try {
      var session = await request("/v1/auth/session", "GET", null, false);
      state.sessionEnabled = true;
      els.sessionInfo.textContent = "Session: active as " + (session.user || "unknown") + " (" + (session.role || "viewer") + ")";
      setPill(els.authPill, "Auth: session", "ok");
    } catch (err) {
      if (err.statusCode === 403) {
        state.sessionEnabled = false;
        els.sessionInfo.textContent = "Session: disabled";
      } else if (err.statusCode === 401) {
        state.sessionEnabled = true;
        els.sessionInfo.textContent = "Session: not active";
      } else {
        els.sessionInfo.textContent = "Session: unavailable";
      }

      if (state.apiKey) {
        setPill(els.authPill, "Auth: api_key", "ok");
      } else {
        setPill(els.authPill, "Auth: required", "pending");
      }
    }
  }

  async function refreshProtectedData() {
    if (!state.apiKey && !state.sessionEnabled) {
      resetProtectedData("Provide API key or session.");
      return;
    }

    try {
      var summary = await request("/v1/dashboard", "GET", null, true);
      var projectsResp = await request("/v1/projects", "GET", null, true);

      var metrics = summary.metrics || {};
      var scans = Array.isArray(summary.recent_scans) ? summary.recent_scans : [];
      var top = Array.isArray(summary.top_violations) ? summary.top_violations : [];
      var events = Array.isArray(summary.recent_events) ? summary.recent_events : [];
      var projects = Array.isArray(projectsResp.projects) ? projectsResp.projects : [];

      setMetric(els.metricProjects, metrics.projects || projects.length || 0);
      setMetric(els.metricScans, metrics.scans || scans.length || 0);
      setMetric(els.metricFailing, metrics.failing_scans || 0);
      setMetric(els.metricBlocking, metrics.blocking_violations || 0);

      renderScans(scans);
      renderTopViolations(top);
      renderEvents(events);
      renderProjects(projects);
      setError("");
    } catch (err) {
      if (err.statusCode === 401) {
        resetProtectedData("Auth failed. Refresh credentials.");
      } else {
        resetProtectedData("Unable to load protected data.");
      }
      setError(err.message);
    }
  }

  function setLastUpdated() {
    if (!els.lastUpdated) return;
    els.lastUpdated.textContent = "Last updated: " + new Date().toLocaleTimeString();
  }

  async function refreshAll() {
    await refreshServerStatus();
    await refreshSessionState();
    await refreshProtectedData();
    setLastUpdated();
  }

  async function startSession() {
    setError("");
    try {
      var session = await request("/v1/auth/session", "POST", {}, false);
      state.sessionEnabled = true;
      setPill(els.authPill, "Auth: session", "ok");
      els.sessionInfo.textContent = "Session: active as " + (session.user || "unknown") + " (" + (session.role || "viewer") + ")";
      await refreshProtectedData();
      setLastUpdated();
    } catch (err) {
      setError(err.message);
    }
  }

  async function endSession() {
    setError("");
    try {
      await request("/v1/auth/session", "DELETE", null, false);
      await refreshAll();
    } catch (err) {
      setError(err.message);
    }
  }

  async function createProject(event) {
    event.preventDefault();
    setError("");

    var name = (els.projectName.value || "").trim();
    var branch = (els.projectBranch.value || "").trim();
    var policySet = (els.projectPolicySet.value || "").trim();

    if (!name) {
      setError("Project name is required.");
      return;
    }

    try {
      await request("/v1/projects", "POST", {
        name: name,
        default_branch: branch,
        policy_set: policySet,
      }, true);
      els.projectName.value = "";
      await refreshAll();
    } catch (err) {
      setError(err.message);
    }
  }

  els.apiKeyInput.value = state.apiKey;
  els.saveKeyBtn.addEventListener("click", function () {
    state.apiKey = (els.apiKeyInput.value || "").trim();
    if (state.apiKey) {
      localStorage.setItem(storageKey, state.apiKey);
    } else {
      localStorage.removeItem(storageKey);
    }
    refreshAll();
  });

  els.clearKeyBtn.addEventListener("click", function () {
    state.apiKey = "";
    els.apiKeyInput.value = "";
    localStorage.removeItem(storageKey);
    refreshAll();
  });

  els.startSessionBtn.addEventListener("click", startSession);
  els.endSessionBtn.addEventListener("click", endSession);
  els.projectForm.addEventListener("submit", createProject);

  refreshAll();
  window.setInterval(refreshAll, 30000);
})();
