(function () {
  const env = window.ENV || {};

  function cleanValue(value) {
    return typeof value === 'string' ? value.trim() : '';
  }

  const nextConfig = {};
  const values = {
    SUPABASE_URL: cleanValue(env.SUPABASE_URL),
    SUPABASE_ANON_KEY: cleanValue(env.SUPABASE_ANON_KEY),
    SUPABASE_AUTH_REDIRECT_TO: cleanValue(env.SUPABASE_AUTH_REDIRECT_TO),
    BASELINE_API_ORIGIN: cleanValue(env.BASELINE_API_ORIGIN)
  };

  Object.keys(values).forEach((key) => {
    if (values[key]) {
      nextConfig[key] = values[key];
    }
  });

  window.RUNTIME_CONFIG = Object.assign({}, window.RUNTIME_CONFIG || {}, nextConfig);
})();
