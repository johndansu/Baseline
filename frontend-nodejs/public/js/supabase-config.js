// Supabase Configuration
// This file should be configured with your Supabase project details
// Version: 2026-03-02-v2 - Updated with correct anon key

window.SUPABASE_CONFIG = {
  // Baseline Auth Supabase project
  url: 'https://twnkjfrpxmdmlcxswizf.supabase.co',
  
  // Use the correct anon key from server configuration
  anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR3bmtqZnJweG1kbWxjeHN3aXpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE4MDA4ODMsImV4cCI6MjA4NzM3Njg4M30.czDvd_Ce2ggPxXyWF0zoinTvJuJKk6NweLPWCBK2o0g',
  
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
