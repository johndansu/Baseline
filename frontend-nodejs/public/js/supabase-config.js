// Supabase Configuration
// This file must not contain real secrets. Configure values via deployment/runtime.

window.SUPABASE_CONFIG = {
  // Baseline Auth Supabase project
  url: 'https://twnkjfrpxmdmlcxswizf.supabase.co',
  
  // Public anon key placeholder (replace at deploy/runtime, not in git).
  anonKey: '<SUPABASE_ANON_KEY>',
  
  // OAuth providers configuration
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
  
  // Authentication settings
  auth: {
    // Redirect URL after authentication
    redirectTo: window.location.origin + '/dashboard.html',
    
    // Session settings
    persistSession: true,
    detectSessionInUrl: true,
    
    // Flow type (implicit, pkce, or magic-link)
    flowType: 'pkce'
  }
};

// Helper function to get configuration from environment or defaults
function getSupabaseConfig() {
  // Do not allow runtime URL/query overrides for auth provider configuration.
  // Query-based overrides can redirect credentials to an attacker-controlled tenant.
  return Object.assign({}, window.SUPABASE_CONFIG);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { getSupabaseConfig };
}
