// Supabase Configuration
// Public values are injected at runtime via /js/runtime-config.js when available.

(function () {
  function cleanValue(value) {
    var normalized = String(value || '').trim();
    if (!normalized) return '';
    if (normalized === '<SUPABASE_ANON_KEY>') return '';
    if (normalized === 'your-anon-key') return '';
    if (normalized === 'https://your-project.supabase.co') return '';
    return normalized;
  }

  function pickConfigValue() {
    for (var i = 0; i < arguments.length; i += 1) {
      var candidate = cleanValue(arguments[i]);
      if (candidate) return candidate;
    }
    return '';
  }

  var env = window.ENV || {};
  var runtime = window.RUNTIME_CONFIG || {};
  var defaultRedirect =
    window.location.origin +
    '/signin.html?return_to=' +
    encodeURIComponent('/dashboard');

  window.SUPABASE_CONFIG = {
    url: pickConfigValue(runtime.SUPABASE_URL, env.SUPABASE_URL) || 'https://twnkjfrpxmdmlcxswizf.supabase.co',
    anonKey: pickConfigValue(runtime.SUPABASE_ANON_KEY, env.SUPABASE_ANON_KEY),
    providers: {
      google: {
        enabled: true,
        scopes: 'email profile'
      },
      github: {
        enabled: true,
        scopes: 'user:email'
      }
    },
    auth: {
      redirectTo: pickConfigValue(runtime.SUPABASE_AUTH_REDIRECT_TO, env.SUPABASE_AUTH_REDIRECT_TO) || defaultRedirect,
      persistSession: true,
      detectSessionInUrl: true,
      flowType: 'pkce'
    }
  };

  window.getSupabaseConfig = function getSupabaseConfig() {
    return Object.assign({}, window.SUPABASE_CONFIG);
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { getSupabaseConfig: window.getSupabaseConfig };
  }
})();
