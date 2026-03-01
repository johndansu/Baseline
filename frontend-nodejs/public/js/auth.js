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
        // Load configuration
        var configScript = document.createElement('script');
        configScript.src = './supabase-config.js';
        configScript.onload = function() {
          var config = window.getSupabaseConfig ? window.getSupabaseConfig() : window.SUPABASE_CONFIG;
          
          if (!config.url || !config.anonKey) {
            console.error('Supabase configuration missing. Please configure supabase-config.js');
            authState.loading = false;
            updateAuthUI();
            return;
          }

          // Create Supabase client
          authState.supabase = supabaseClient.createClient(config.url, config.anonKey, {
            auth: {
              autoRefreshToken: true,
              persistSession: true,
              detectSessionInUrl: true
            }
          });

          // Set up auth state listener
          authState.supabase.auth.onAuthStateChange(handleAuthStateChange);
          
          // Check for existing session
          return authState.supabase.auth.getSession();
        };
        document.head.appendChild(configScript);
      })
      .then(function(result) {
        if (result && result.data.session) {
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

  // Handle authentication state changes
  function handleAuthStateChange(event, session) {
    console.log('Auth state changed:', event, session);
    
    authState.session = session;
    authState.user = session ? session.user : null;
    authState.authenticated = !!session;
    
    updateAuthUI();
    
    // Handle redirect after authentication
    if (event === 'SIGNED_IN' && session) {
      // Check if we're on the callback page to avoid redirect loops
      if (window.location.pathname !== '/dashboard.html' && window.location.pathname !== '/') {
        var returnUrl = new URLSearchParams(window.location.search).get('return_to') || '/dashboard.html';
        console.log('Redirecting to:', returnUrl);
        window.location.href = returnUrl;
      }
    }
  }

  // Update UI based on authentication state
  function updateAuthUI() {
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
  function signInWithOAuth(provider, options) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }

    var authOptions = {
      provider: provider,
      options: {
        redirectTo: (options && options.redirectTo) || window.location.origin + '/dashboard.html',
        scopes: options && options.scopes
      }
    };

    return authState.supabase.auth.signInWithOAuth(authOptions);
  }

  // Sign in with email and password
  function signInWithEmail(email, password) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }

    return authState.supabase.auth.signInWithPassword({
      email: email,
      password: password
    });
  }

  // Sign up with email and password
  function signUpWithEmail(email, password, options) {
    if (!authState.supabase) {
      console.error('Supabase not initialized');
      return Promise.reject(new Error('Supabase not initialized'));
    }

    return authState.supabase.auth.signUp({
      email: email,
      password: password,
      options: options
    });
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
      var password = formData.password;

      setStatus(form, mode === "signup" ? "Creating account..." : "Signing in...", false);

      var authPromise;
      if (mode === "signup") {
        authPromise = signUpWithEmail(email, password, {
          data: {
            full_name: formData.name || email
          }
        });
      } else {
        authPromise = signInWithEmail(email, password);
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
              window.location.href = '/dashboard.html';
            }, 1500); // Brief delay to show success message
          }
        })
        .catch(function(error) {
          console.error('Authentication error:', error);
          setStatus(form, error.message || "Authentication failed. Please try again.", true);
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
