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

  var env = window.ENV || {};
  var runtime = window.RUNTIME_CONFIG || {};
  var configSource = Object.assign({}, env, runtime);
  var defaultRedirect =
    window.location.origin +
    '/signin.html?return_to=' +
    encodeURIComponent('/dashboard');

  window.SUPABASE_CONFIG = {
    url: cleanValue(configSource.SUPABASE_URL) || 'https://twnkjfrpxmdmlcxswizf.supabase.co',
    anonKey: cleanValue(configSource.SUPABASE_ANON_KEY),
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
      redirectTo: cleanValue(configSource.SUPABASE_AUTH_REDIRECT_TO) || defaultRedirect,
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
