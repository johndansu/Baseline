(function () {
  "use strict";

  var DASHBOARD_API_BASE_KEY = "baseline.dashboard.apiBaseUrl";
  var authState = { authenticated: false };
  var lastRequestTime = {};
  var RATE_LIMIT_DELAY = 750;

  function normalizeBaseUrl(raw) {
    var value = String(raw || "").trim();
    if (!value) return "";
    return value.replace(/\/+$/, "");
  }

  function safeQueryParam(name) {
    try {
      var params = new URLSearchParams(window.location.search || "");
      return String(params.get(name) || "").trim();
    } catch (_) {
      return "";
    }
  }

  function readStoredAPIBaseUrl() {
    try {
      return String(localStorage.getItem(DASHBOARD_API_BASE_KEY) || "").trim();
    } catch (_) {
      return "";
    }
  }

  function saveAPIBaseUrl(value) {
    try {
      if (value) localStorage.setItem(DASHBOARD_API_BASE_KEY, value);
    } catch (_) {
      // no-op
    }
  }

  function defaultAPIBaseUrl() {
    try {
      var loc = window.location;
      if (loc && (loc.protocol === "http:" || loc.protocol === "https:")) {
        var host = String(loc.hostname || "").toLowerCase();
        var isLocalHost = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
        if (isLocalHost && String(loc.port || "") && String(loc.port) !== "8080") {
          return "http://127.0.0.1:8080";
        }
        if (isLocalHost && String(loc.pathname || "").indexOf("/frontend/") !== -1) {
          return "http://127.0.0.1:8080";
        }
        return normalizeBaseUrl(loc.origin);
      }
    } catch (_) {
      // no-op
    }
    return "http://127.0.0.1:8080";
  }

  function currentAPIBaseUrl() {
    var fromQuery = normalizeBaseUrl(safeQueryParam("api"));
    if (fromQuery) {
      saveAPIBaseUrl(fromQuery);
      return fromQuery;
    }
    var fromStorage = normalizeBaseUrl(readStoredAPIBaseUrl());
    if (fromStorage) return fromStorage;
    return defaultAPIBaseUrl();
  }

  function safeReturnTo() {
    var next = safeQueryParam("return_to");
    if (!next) return "/";
    if (next.charAt(0) === "/" && next.indexOf("//") !== 0) {
      return next;
    }
    try {
      var parsed = new URL(next);
      var protocol = (parsed.protocol || "").toLowerCase();
      var host = (parsed.hostname || "").toLowerCase();
      if (protocol !== "http:" && protocol !== "https:") return "/";
      if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]") {
        return parsed.toString();
      }
    } catch (_) {
      return "/";
    }
    return "/";
  }

  function buildOIDCLoginURL(mode, loginHint) {
    var base = currentAPIBaseUrl();
    var url = base + "/v1/auth/oidc/login?return_to=" + encodeURIComponent(safeReturnTo());
    if (mode === "signup") {
      url += "&mode=signup";
    }
    if (loginHint) {
      url += "&login_hint=" + encodeURIComponent(loginHint);
    }
    return url;
  }

  function ensureStatusNode(form) {
    if (!form) return null;
    var node = form.parentElement ? form.parentElement.querySelector(".auth-redirect-note") : null;
    if (node) return node;
    node = document.createElement("p");
    node.className = "auth-redirect-note";
    node.style.marginTop = "10px";
    node.style.fontSize = "0.85rem";
    node.style.color = "rgba(255,255,255,0.75)";
    node.textContent = "This page uses backend OIDC login. Credentials are entered on your hosted identity provider.";
    if (form.parentElement) {
      form.parentElement.appendChild(node);
    }
    return node;
  }

  function setStatus(form, text, isError) {
    var node = ensureStatusNode(form);
    if (!node) return;
    node.textContent = text;
    node.style.color = isError ? "#fecaca" : "rgba(255,255,255,0.8)";
  }

  function getFormData(form) {
    if (!form) return {};
    var formData = {};
    var inputs = form.querySelectorAll("input");
    Array.prototype.forEach.call(inputs, function (input) {
      if (input.name) {
        formData[input.name] = String(input.value || "").trim();
      }
    });
    return formData;
  }

  function disableNativeValidation(form) {
    if (!form) return;
    form.setAttribute("novalidate", "novalidate");
    var controls = form.querySelectorAll("input, select, textarea");
    Array.prototype.forEach.call(controls, function (el) {
      if (el && el.hasAttribute && el.hasAttribute("required")) {
        el.removeAttribute("required");
      }
    });
  }

  function redirectToOIDC(mode, loginHint) {
    window.location.assign(buildOIDCLoginURL(mode, loginHint));
  }

  function bindAuthForm(form, mode) {
    if (!form) return;
    disableNativeValidation(form);

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var submitButton = form.querySelector("button[type='submit']");
      if (submitButton) submitButton.disabled = true;

      var formData = getFormData(form);
      var loginHint = formData.email || "";
      setStatus(form, mode === "signup" ? "Redirecting to sign up..." : "Redirecting to sign in...", false);

      try {
        redirectToOIDC(mode, loginHint);
      } catch (_) {
        setStatus(form, "Unable to start sign-in. Check API base URL and try again.", true);
        if (submitButton) submitButton.disabled = false;
      }
    });
  }

  function bindOAuthButtons() {
    var googleBtn = document.getElementById("googleSignInBtn");
    var githubBtn = document.getElementById("githubSignInBtn");
    var form = document.querySelector(".signin-form form") || document.querySelector(".signup-form form");

    function oauthHandler(event) {
      event.preventDefault();
      var email = "";
      if (form) {
        var emailInput = form.querySelector("input[type='email']");
        email = emailInput ? String(emailInput.value || "").trim() : "";
        setStatus(form, "Redirecting to hosted login...", false);
      }
      redirectToOIDC("signin", email);
    }

    if (googleBtn) googleBtn.addEventListener("click", oauthHandler);
    if (githubBtn) githubBtn.addEventListener("click", oauthHandler);
  }

  function bindPasswordResetLinks() {
    var resetLinks = document.querySelectorAll("a[href='#']");
    Array.prototype.forEach.call(resetLinks, function (link) {
      if (String(link.textContent || "").toLowerCase().indexOf("forgot password") === -1) return;
      link.addEventListener("click", function (e) {
        e.preventDefault();
        var form = document.querySelector(".signin-form form");
        setStatus(form, "Password reset is handled by your hosted identity provider on the sign-in page.", false);
      });
    });
  }

  function apiFetch(path, options) {
    var base = currentAPIBaseUrl();
    return fetch(base + path, Object.assign({ credentials: "include" }, options || {}));
  }

  function setAuthenticatedUI(me) {
    authState.authenticated = !!(me && me.authenticated);
    authState.me = me || null;

    var authPill = document.getElementById("authPill");
    if (authPill) {
      if (authState.authenticated) {
        authPill.textContent = "Auth: " + (me.auth_source || "session");
        authPill.className = "pill ok";
      } else {
        authPill.textContent = "Auth: required";
        authPill.className = "pill";
      }
    }

    var authOnly = document.querySelectorAll("[data-auth-only]");
    Array.prototype.forEach.call(authOnly, function (el) {
      el.style.display = authState.authenticated ? "" : "none";
    });

    var name = authState.authenticated ? String((me && (me.user || me.email || me.subject)) || "Operator") : "Operator";
    var email = authState.authenticated && me && me.email ? String(me.email) : "user@example.com";

    var userName = document.getElementById("userName");
    var dropdownUserName = document.getElementById("dropdownUserName");
    var dropdownUserEmail = document.getElementById("dropdownUserEmail");
    var userAvatar = document.getElementById("userAvatar");

    if (userName) userName.textContent = name;
    if (dropdownUserName) dropdownUserName.textContent = name;
    if (dropdownUserEmail) dropdownUserEmail.textContent = email;
    if (userAvatar) userAvatar.textContent = (email || name || "O").charAt(0).toUpperCase();
  }

  async function checkAuthStatus() {
    try {
      var res = await apiFetch("/v1/auth/me", { method: "GET" });
      if (!res.ok) {
        setAuthenticatedUI(null);
        return null;
      }
      var me = await res.json();
      setAuthenticatedUI(me);
      return me;
    } catch (_) {
      setAuthenticatedUI(null);
      return null;
    }
  }

  async function logout() {
    try {
      await apiFetch("/v1/auth/session", {
        method: "DELETE",
        headers: { "X-Baseline-CSRF": "1" }
      });
    } catch (_) {
      // no-op
    }

    var base = currentAPIBaseUrl();
    window.location.href = base + "/signin.html?api=" + encodeURIComponent(base) + "&return_to=" + encodeURIComponent("/");
  }

  window.baselineLogout = logout;

  async function authenticatedApiCall(action, apiFunction) {
    var now = Date.now();
    var last = lastRequestTime[action] || 0;
    if (now - last < RATE_LIMIT_DELAY) {
      throw new Error("rate_limited");
    }
    lastRequestTime[action] = now;
    if (!authState.authenticated) {
      await checkAuthStatus();
    }
    return apiFunction();
  }

  window.authenticatedApiCall = authenticatedApiCall;

  function initializeUserDropdown() {
    var userDropdown = document.getElementById("userDropdown");
    var userMenuBtn = document.getElementById("userMenuBtn");
    if (!userDropdown || !userMenuBtn) return;

    userMenuBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      userDropdown.classList.toggle("open");
    });

    document.addEventListener("click", function () {
      userDropdown.classList.remove("open");
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var signinForm = document.querySelector(".signin-form form");
    var signupForm = document.querySelector(".signup-form form");

    bindAuthForm(signinForm, "signin");
    bindAuthForm(signupForm, "signup");
    bindOAuthButtons();
    bindPasswordResetLinks();
    initializeUserDropdown();
    checkAuthStatus();
  });
})();
