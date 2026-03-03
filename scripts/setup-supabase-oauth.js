/**
 * Supabase OAuth Setup Helper
 * This script helps generate the required OAuth configuration for your Supabase project
 */

const SUPABASE_URL = 'https://twnkjfrpxmdmlcxswizf.supabase.co';
const REDIRECT_URI = `${SUPABASE_URL}/auth/v1/callback`;

console.log('🔐 Supabase OAuth Setup Helper');
console.log('==================================\n');

console.log('📋 Project Information:');
console.log(`   Project URL: ${SUPABASE_URL}`);
console.log(`   Callback URL: ${REDIRECT_URI}\n`);

console.log('🔗 OAuth Provider Setup:');
console.log('========================\n');

console.log('1. Google OAuth Setup:');
console.log('   - Go to: https://console.cloud.google.com/auth/clients');
console.log('   - Create new OAuth Client ID');
console.log('   - Application Type: Web application');
console.log('   - Authorized JavaScript origins: http://localhost:3000');
console.log(`   - Authorized redirect URIs: ${REDIRECT_URI}`);
console.log('   - Copy Client ID and Client Secret');
console.log('   - Go to your Supabase Dashboard > Authentication > Providers > Google');
console.log('   - Enable Google provider and add the credentials\n');

console.log('2. GitHub OAuth Setup:');
console.log('   - Go to: https://github.com/settings/applications/new');
console.log('   - Application name: Baseline Auth (Dev)');
console.log('   - Homepage URL: http://localhost:3000');
console.log(`   - Authorization callback URL: ${REDIRECT_URI}`);
console.log('   - Register application');
console.log('   - Copy Client ID and Client Secret');
console.log('   - Go to your Supabase Dashboard > Authentication > Providers > GitHub');
console.log('   - Enable GitHub provider and add the credentials\n');

console.log('3. Local Development Setup:');
console.log('   - Add http://localhost:3000 to authorized origins');
console.log('   - Test with: http://localhost:3000/test-auth.html');
console.log('   - For development, use http://localhost:3000 as Homepage URL');
console.log('   - No custom domain needed for local testing\n');

console.log('🧪 Testing:');
console.log('============');
console.log('   - Open test-auth.html in your browser');
console.log('   - Test email/password signup and signin');
console.log('   - Test OAuth providers (Google/GitHub)');
console.log('   - Verify session management');
console.log('   - Check password reset functionality\n');

console.log('📝 Configuration Files Updated:');
console.log('==============================');
console.log('   ✅ supabase-config.js - Updated with project credentials');
console.log('   ✅ auth.js - Replaced with Supabase implementation');
console.log('   ✅ signin.html - Added Supabase integration');
console.log('   ✅ signup.html - Added Supabase integration');
console.log('   ✅ dashboard.html - Added Supabase integration');
console.log('   ✅ index.html - Added Supabase integration');
console.log('   ✅ test-auth.html - Created comprehensive test page\n');

console.log('🔒 Security Notes:');
console.log('==================');
console.log('   - Never expose service role keys in frontend');
console.log('   - Enable Row Level Security (RLS) on all tables');
console.log('   - Use HTTPS in production');
console.log('   - Configure proper CORS settings');
console.log('   - Enable email verification');
console.log('   - Set up rate limiting\n');

console.log('🚀 Next Steps:');
console.log('===============');
console.log('   1. Configure OAuth providers in Google/GitHub dashboards');
console.log('   2. Enable providers in Supabase Dashboard');
console.log('   3. Test authentication flow');
console.log('   4. Set up Row Level Security policies');
console.log('   5. Configure custom domain (optional)');
console.log('   6. Set up email templates\n');

console.log('📚 Documentation:');
console.log('================');
console.log('   - README-SUPABASE.md: Complete setup guide');
console.log('   - Supabase Docs: https://supabase.com/docs');
console.log('   - Auth Guide: https://supabase.com/docs/guides/auth\n');

// Export configuration for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SUPABASE_URL,
        REDIRECT_URI,
        getOAuthConfig: (provider) => ({
            redirectUri: REDIRECT_URI,
            scopes: provider === 'google' ? 'email profile' : 'user:email',
            provider: provider
        })
    };
}
