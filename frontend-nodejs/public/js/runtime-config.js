(function () {
  const env = window.ENV || {};

  function cleanValue(value) {
    return typeof value === 'string' ? value.trim() : '';
  }

  window.RUNTIME_CONFIG = Object.assign({}, window.RUNTIME_CONFIG || {}, {
    SUPABASE_URL: cleanValue(env.SUPABASE_URL),
    SUPABASE_ANON_KEY: cleanValue(env.SUPABASE_ANON_KEY),
    SUPABASE_AUTH_REDIRECT_TO: cleanValue(env.SUPABASE_AUTH_REDIRECT_TO),
    BASELINE_API_ORIGIN: cleanValue(env.BASELINE_API_ORIGIN)
  });
})();
