// Supabase Configuration
// This file should be configured with your Supabase project details

window.SUPABASE_CONFIG = {
  // Baseline Auth Supabase project
  url: 'https://twnkjfrpxmdmlcxswizf.supabase.co',
  
  // Use the modern publishable key
  anonKey: 'sb_publishable_PYgCh33gXvLETzYbWrhLtA_xbiHBZ6o',
  
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
  // Check for environment variables first (for development)
  if (typeof window !== 'undefined' && window.location) {
    const params = new URLSearchParams(window.location.search);
    
    // Allow override via URL parameters for development
    const url = params.get('supabase_url');
    const key = params.get('supabase_key');
    
    if (url && key) {
      return {
        url: url,
        anonKey: key,
        ...window.SUPABASE_CONFIG
      };
    }
  }
  
  return window.SUPABASE_CONFIG;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { getSupabaseConfig };
}
