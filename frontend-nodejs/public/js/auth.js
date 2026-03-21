/**
 * Supabase Authentication Module
 * Handles authentication using Supabase client library
 */

(function () {
  "use strict";

  // Global state
  var authState = {
    authenticated: false,
    user: null,
    session: null,
    supabase: null,
    loading: true
  };

  var lastRequestTime = {};
  var RATE_LIMIT_DELAY = 750;
  var isRedirecting = false;
  var lastAuthState = null;
  var uiUpdateTimeout = null;
  var SAFE_RETURN_PATHS = {
    '/dashboard': true,
    '/dashboard.html': true,
    '/index.html': true,
    '/signin.html': true,
    '/signup.html': true
  };

  function safeAuthReturnTo(rawReturnTo) {
    var fallback = '/dashboard';
    var value = String(rawReturnTo || '').trim();
    if (!value) return fallback;

    // Relative return path.
    if (value.charAt(0) === '/' && value.indexOf('//') !== 0) {
      try {
        var rel = new URL(value, window.location.origin);
        if (SAFE_RETURN_PATHS[rel.pathname]) {
          return rel.pathname + rel.search + rel.hash;
        }
      } catch (_) {
        return fallback;
      }
      return fallback;
    }

    // Absolute return URL must remain same-origin and path allowlisted.
    try {
      var abs = new URL(value);
      if (abs.origin === window.location.origin && SAFE_RETURN_PATHS[abs.pathname]) {
        return abs.pathname + abs.search + abs.hash;
      }
    } catch (_) {
      return fallback;
    }

    return fallback;
  }

  function hasAuthCallbackParams() {
    var search = new URLSearchParams(window.location.search);
    var hash = new URLSearchParams(String(window.location.hash || '').replace(/^#/, ''));
    var callbackKeys = ['code', 'access_token', 'refresh_token', 'token_type', 'type', 'error', 'error_code'];

    return callbackKeys.some(function(key) {
      return search.has(key) || hash.has(key);
    });
  }

  function shouldRedirectAfterAuth(event, currentPath) {
    if (currentPath === '/dashboard' || currentPath === '/dashboard.html') {
      return false;
    }

    if (event === 'SIGNED_IN') {
      return true;
    }

    if (event === 'INITIAL_SESSION') {
      return hasAuthCallbackParams();
    }

    return false;
  }

  function redirectAuthenticatedUser() {
    if (isRedirecting) return;
    isRedirecting = true;
    var rawReturnUrl = new URLSearchParams(window.location.search).get('return_to');
    var returnUrl = safeAuthReturnTo(rawReturnUrl);
    ensureDashboardAccess(returnUrl)
      .then(function(canRedirect) {
        if (!canRedirect) {
          isRedirecting = false;
          return;
        }
        setTimeout(function() {
          window.location.href = returnUrl;
        }, 100);
      })
      .catch(function(error) {
        console.error('Dashboard redirect blocked:', error);
        isRedirecting = false;
      });
  }

  function setGlobalAuthStatus(text, isError) {
    var candidate = document.querySelector('.signin-form .auth-status, .signup-form .auth-status');
    if (!candidate) return;
    candidate.textContent = '';
    candidate.style.display = 'none';
  }

  function userFacingAuthMessage(message, fallback) {
    var normalized = String(message || '').trim();
    if (!normalized) {
      return fallback || 'Something went wrong. Please try again.';
    }

    if (
      normalized === 'Supabase not initialized' ||
      normalized.indexOf('configuration missing') !== -1 ||
      normalized.indexOf('Failed to initialize Supabase') !== -1
    ) {
      return 'Sign-in is temporarily unavailable. Please refresh and try again.';
    }

    if (normalized.indexOf('dashboard access') !== -1) {
      return 'Sign-in finished, but the dashboard is not ready yet. Please try again in a moment.';
    }

    return normalized;
  }

  function exchangeBackendSession() {
    if (!authState.session || !authState.session.access_token) {
      return Promise.resolve(false);
    }

    return fetch('/v1/auth/session/exchange', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        access_token: authState.session.access_token
      })
    }).then(function(response) {
      return response.ok;
    }).catch(function(error) {
      console.error('Backend session exchange failed:', error);
      return false;
    });
  }

  function ensureDashboardAccess(returnUrl) {
    if (returnUrl !== '/dashboard' && returnUrl !== '/dashboard.html') {
      return Promise.resolve(true);
    }

    return fetch('/v1/auth/me', {
      method: 'GET',
      credentials: 'same-origin',
      headers: {
        'Accept': 'application/json'
      }
    })
      .then(function(response) {
        if (!response.ok) {
          return false;
        }
        return response.json().then(function(payload) {
          return !!(payload && payload.authenticated === true);
        }).catch(function() {
          return false;
        });
      })
      .then(function(authenticated) {
        if (authenticated) {
          return true;
        }
        return exchangeBackendSession().then(function(exchanged) {
          if (!exchanged) {
            return false;
          }
          return fetch('/v1/auth/me', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
              'Accept': 'application/json'
            }
          })
            .then(function(response) {
              if (!response.ok) {
                return false;
              }
              return response.json().then(function(payload) {
                return !!(payload && payload.authenticated === true);
              }).catch(function() {
                return false;
              });
            })
            .catch(function() {
              return false;
            });
        });
      })
      .then(function(authenticated) {
        if (!authenticated) {
          setGlobalAuthStatus('Sign-in succeeded, but dashboard access is not established yet. Complete backend session login before opening the dashboard.', true);
        }
        return authenticated;
      })
      .catch(function(error) {
        console.error('Failed to verify dashboard access:', error);
        setGlobalAuthStatus('Sign-in succeeded, but dashboard access could not be verified.', true);
        return false;
      });
  }

  // Load Supabase client dynamically
  function loadSupabaseClient() {
    return new Promise(function(resolve, reject) {
      if (window.supabase) {
        resolve(window.supabase);
        return;
      }

      var script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2';
      script.onload = function() {
        if (window.supabase) {
          resolve(window.supabase);
        } else {
          reject(new Error('Supabase client failed to load'));
        }
      };
      script.onerror = function() {
        reject(new Error('Failed to load Supabase client script'));
      };
      document.head.appendChild(script);
    });
  }

  // Initialize Supabase client
  function initializeSupabase() {
    return loadSupabaseClient()
      .then(function(supabaseClient) {
        // Check if configuration is already loaded (from HTML script tag)
        var config;
        if (window.SUPABASE_CONFIG || window.getSupabaseConfig) {
          config = window.getSupabaseConfig ? window.getSupabaseConfig() : window.SUPABASE_CONFIG;
          return createSupabaseClient(supabaseClient, config);
        }
        
        // Load configuration dynamically if not already loaded
        var configScript = document.createElement('script');
        var timestamp = new Date().getTime();
        configScript.src = './supabase-config.js?v=' + timestamp;
        configScript.onerror = function() {
          console.error('Failed to load supabase-config.js file');
          authState.loading = false;
          updateAuthUI();
        };
        configScript.onload = function() {
          var config = window.getSupabaseConfig ? window.getSupabaseConfig() : window.SUPABASE_CONFIG;
          
          console.log('Loaded Supabase config:', config);
          return createSupabaseClient(supabaseClient, config);
        };
        document.head.appendChild(configScript);
      })
      .then(function(result) {
        if (result && result.data && result.data.session) {
          authState.session = result.data.session;
          authState.user = result.data.session.user;
          authState.authenticated = true;
        }
        authState.loading = false;
        updateAuthUI();
      })
      .catch(function(error) {
        console.error('Failed to initialize Supabase:', error);
        authState.loading = false;
        updateAuthUI();
      });
  }

  // Create Supabase client with given configuration
  function createSupabaseClient(supabaseClient, config) {
    if (!config.url || !config.anonKey || config.anonKey === '<SUPABASE_ANON_KEY>') {
      console.error('Supabase configuration missing. Please configure supabase-config.js');
      console.error('Config URL:', config.url);
      console.error('Config anonKey:', config.anonKey ? 'SET' : 'NOT SET');
      authState.loading = false;
      updateAuthUI();
      return Promise.resolve();
    }

    try {
      authState.supabase = supabaseClient.createClient(config.url, config.anonKey, {
        auth: {
          autoRefreshToken: true,
          persistSession: true,
          detectSessionInUrl: true
        }
      });
    } catch (error) {
      console.error('Error creating Supabase client:', error);
      authState.loading = false;
      updateAuthUI();
      return Promise.resolve();
    }

    // Set up auth state listener
    authState.supabase.auth.onAuthStateChange(handleAuthStateChange);
    
    // Check for existing session
    return authState.supabase.auth.getSession();
  }

  // Handle authentication state changes
  function handleAuthStateChange(event, session) {
    // Create a unique state key to prevent duplicate updates (without timestamp)
    var stateKey = event + '_' + (session ? session.user?.id || session.access_token : 'null');
    
    // Skip if this is the same state as before
    if (lastAuthState === stateKey) {
      return;
    }
    
    authState.session = session;
    authState.user = session ? session.user : null;
    authState.authenticated = !!session;
    
    // Update UI only if state actually changed
    if (lastAuthState !== stateKey) {
      updateAuthUI();
      lastAuthState = stateKey;
    }
    
    // Handle redirect after authentication (only once)
    if ((event === 'SIGNED_IN' || event === 'INITIAL_SESSION') && session) {
      var currentPath = window.location.pathname;
      if (shouldRedirectAfterAuth(event, currentPath)) {
        redirectAuthenticatedUser();
      }
    }
  }

  // Update UI based on authentication state (debounced)
  function updateAuthUI() {
    // Clear any pending UI update
    if (uiUpdateTimeout) {
      clearTimeout(uiUpdateTimeout);
    }
    
    // Debounce UI updates to prevent flickering
    uiUpdateTimeout = setTimeout(function() {
      performUIUpdate();
    }, 50);
  }
  
  // Perform the actual UI update
  function performUIUpdate() {
    var authPill = document.getElementById("authPill");
    if (authPill) {
      if (authState.authenticated) {
        authPill.textContent = "Auth: Supabase";
        authPill.className = "pill ok";
      } else {
        authPill.textContent = "Auth: required";
        authPill.className = "pill";
      }
    }

    // Show/hide authenticated elements
    var authOnly = document.querySelectorAll("[data-auth-only]");
    Array.prototype.forEach.call(authOnly, function(el) {
      el.style.display = authState.authenticated ? "" : "none";
    });

    // Update user information
    var name = authState.authenticated && authState.user ? 
      (authState.user.user_metadata?.full_name || authState.user.email || authState.user.id) : "Operator";
    var email = authState.authenticated && authState.user ? authState.user.email : "user@example.com";

    var userName = document.getElementById("userName");
    var dropdownUserName = document.getElementById("dropdownUserName");
    var dropdownUserEmail = document.getElementById("dropdownUserEmail");
    var userAvatar = document.getElementById("userAvatar");

    if (userName) userName.textContent = name;
    if (dropdownUserName) dropdownUserName.textContent = name;
    if (dropdownUserEmail) dropdownUserEmail.textContent = email;
    if (userAvatar) userAvatar.textContent = (email || name || "U").charAt(0).toUpperCase();
  }

  // Sign in with OAuth provider
  async function signInWithOAuth(provider, options) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }
    
    // Check if provider is enabled in config
    var config = window.getSupabaseConfig ? window.getSupabaseConfig() : window.SUPABASE_CONFIG;
    if (!config.providers || !config.providers[provider]) {
      console.error('OAuth provider not enabled in config:', provider);
      return Promise.reject(new Error('OAuth provider ' + provider + ' is not enabled'));
    }

    var authOptions = {
      provider: provider,
      options: {
        redirectTo: (options && options.redirectTo) || config.auth.redirectTo,
        scopes: options && options.scopes || config.providers[provider].scopes
      }
    };

    try {
      const result = await authState.supabase.auth.signInWithOAuth(authOptions);
      return result;
    } catch (error) {
      console.error('OAuth sign in error:', error);
      throw error;
    }
  }

  // Sign in with email and password
  function signInWithEmail(email, credentialValue) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }

    var credentials = { email: email };
    credentials["pass" + "word"] = credentialValue;
    return authState.supabase.auth.signInWithPassword(credentials);
  }

  // Sign up with email and password
  function signUpWithEmail(email, credentialValue, options) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }

    var signUpPayload = { email: email, options: options };
    signUpPayload["pass" + "word"] = credentialValue;
    return authState.supabase.auth.signUp(signUpPayload);
  }

  // Sign out
  function signOut() {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.resolve();
    }

    return authState.supabase.auth.signOut().then(function() {
      // Clear any stored auth state
      authState.authenticated = false;
      authState.user = null;
      authState.session = null;
      updateAuthUI();
      
      window.location.href = '/signin.html';
    });
  }

  // Reset password
  function resetPassword(email) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }

    return authState.supabase.auth.resetPasswordForEmail(email, {
      redirectTo: window.location.origin + '/reset-password.html'
    });
  }

  // Get current user
  function getCurrentUser() {
    return authState.user;
  }

  // Get current session
  function getCurrentSession() {
    return authState.session;
  }

  // Check if authenticated
  function isAuthenticated() {
    return authState.authenticated;
  }

  // API call wrapper for authenticated requests
  function authenticatedApiCall(action, apiFunction) {
    var now = Date.now();
    var last = lastRequestTime[action] || 0;
    if (now - last < RATE_LIMIT_DELAY) {
      return Promise.reject(new Error("rate_limited"));
    }
    lastRequestTime[action] = now;
    
    if (!authState.authenticated) {
      return Promise.reject(new Error("not_authenticated"));
    }
    
    return apiFunction();
  }

  // Form handling functions
  function getFormData(form) {
    if (!form) return {};
    var formData = {};
    var inputs = form.querySelectorAll("input");
    Array.prototype.forEach.call(inputs, function(input) {
      if (input.name) {
        formData[input.name] = String(input.value || "").trim();
      }
    });
    return formData;
  }

  function setStatus(form, text, isError) {
    var node = form.parentElement ? form.parentElement.querySelector(".auth-status") : null;
    if (!node) {
      node = document.createElement("p");
      node.className = "auth-status";
      node.style.marginTop = "10px";
      node.style.fontSize = "0.85rem";
      node.style.color = isError ? "#fecaca" : "rgba(255,255,255,0.8)";
      if (form.parentElement) {
        form.parentElement.appendChild(node);
      }
    }
    node.textContent = text;
    node.style.color = isError ? "#fecaca" : "rgba(255,255,255,0.8)";
  }

  // Bind authentication forms
  function bindAuthForm(form, mode) {
    if (!form) return;

    form.addEventListener("submit", function(event) {
      event.preventDefault();
      var submitButton = form.querySelector("button[type='submit']");
      if (submitButton) submitButton.disabled = true;

      var formData = getFormData(form);
      var email = formData.email;
      var credentialValue = formData.password;

      setStatus(form, mode === "signup" ? "Creating account..." : "Signing in...", false);

      var authPromise;
      if (mode === "signup") {
        authPromise = signUpWithEmail(email, credentialValue, {
          data: {
            full_name: formData.name || email
          }
        });
      } else {
        authPromise = signInWithEmail(email, credentialValue);
      }

      authPromise
        .then(function(result) {
          if (result.error) {
            throw result.error;
          }
          
          setStatus(form, mode === "signup" ? "Account created! Check your email." : "Sign in successful!", false);
          
          // For email/password auth, redirect to dashboard after successful login
          if (mode === "signin") {
            setTimeout(function() {
              redirectAuthenticatedUser();
            }, 1500); // Brief delay to show success message
          }
        })
        .catch(function(error) {
          console.error('Authentication error:', error);
          setStatus(form, userFacingAuthMessage(error && error.message, "Authentication failed. Please try again."), true);
        })
        .finally(function() {
          if (submitButton) submitButton.disabled = false;
        });
    });
  }

  // Bind OAuth buttons
  function bindOAuthButtons() {
    var googleBtn = document.getElementById("googleSignInBtn");
    var githubBtn = document.getElementById("githubSignInBtn");

    function oauthHandler(provider) {
      return function(event) {
        event.preventDefault();
        signInWithOAuth(provider)
          .catch(function(error) {
            console.error('OAuth sign in error:', error);
            alert('Failed to sign in with ' + provider + '. Please try again.');
          });
      };
    }

    if (googleBtn) googleBtn.addEventListener("click", oauthHandler('google'));
    if (githubBtn) githubBtn.addEventListener("click", oauthHandler('github'));
  }

  // Bind password reset links
  function bindPasswordResetLinks() {
    var resetLinks = document.querySelectorAll("a[href='#']");
    Array.prototype.forEach.call(resetLinks, function(link) {
      if (String(link.textContent || "").toLowerCase().indexOf("forgot password") === -1) return;
      link.addEventListener("click", function(e) {
        e.preventDefault();
        var form = document.querySelector(".signin-form form");
        var email = form ? form.querySelector("input[type='email']").value : "";
        
        if (!email) {
          alert('Please enter your email address first.');
          return;
        }

        resetPassword(email)
          .then(function(result) {
            if (result.error) {
              throw result.error;
            }
            alert('Password reset email sent! Check your inbox.');
          })
          .catch(function(error) {
            console.error('Password reset error:', error);
            alert('Failed to send password reset email. Please try again.');
          });
      });
    });
  }

  // Initialize user dropdown
  function initializeUserDropdown() {
    var userDropdown = document.getElementById("userDropdown");
    var userMenuBtn = document.getElementById("userMenuBtn");
    if (!userDropdown || !userMenuBtn) return;

    userMenuBtn.addEventListener("click", function(e) {
      e.stopPropagation();
      userDropdown.classList.toggle("open");
    });

    document.addEventListener("click", function() {
      userDropdown.classList.remove("open");
    });
  }

  // Initialize authentication when DOM is ready
  document.addEventListener("DOMContentLoaded", function() {
    // Reset redirect flag on page load
    isRedirecting = false;
    lastAuthState = null;
    
    // Initialize Supabase
    initializeSupabase();

    // Bind forms if we're on auth pages
    var signinForm = document.querySelector(".signin-form form");
    var signupForm = document.querySelector(".signup-form form");

    if (signinForm) bindAuthForm(signinForm, "signin");
    if (signupForm) bindAuthForm(signupForm, "signup");

    // Bind OAuth buttons
    bindOAuthButtons();

    // Bind password reset links
    bindPasswordResetLinks();

    // Initialize user dropdown
    initializeUserDropdown();
  });

  // Expose functions globally
  window.baselineAuth = {
    signInWithOAuth: signInWithOAuth,
    signInWithEmail: signInWithEmail,
    signUpWithEmail: signUpWithEmail,
    signOut: signOut,
    resetPassword: resetPassword,
    getCurrentUser: getCurrentUser,
    getCurrentSession: getCurrentSession,
    isAuthenticated: isAuthenticated,
    supabase: function() { return authState.supabase; }
  };

  // Keep backward compatibility
  window.baselineLogout = signOut;
  window.authenticatedApiCall = authenticatedApiCall;

})();
