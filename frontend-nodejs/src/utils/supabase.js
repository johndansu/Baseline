const { createClient } = require('@supabase/supabase-js');

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL || 'https://your-project.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || 'your-anon-key';

// Create Supabase client
const supabase = createClient(supabaseUrl, supabaseAnonKey);

/**
 * Verify JWT token from Supabase
 * @param {string} token - JWT token to verify
 * @returns {Promise<Object>} User object if valid, null if invalid
 */
async function verifyJWT(token) {
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error) {
      console.error('JWT verification failed:', error.message);
      return null;
    }
    
    return user;
  } catch (error) {
    console.error('JWT verification error:', error);
    return null;
  }
}

/**
 * Extract JWT token from Authorization header
 * @param {string} authHeader - Authorization header value
 * @returns {string|null} JWT token if found, null otherwise
 */
function extractTokenFromHeader(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.substring(7); // Remove 'Bearer ' prefix
}

/**
 * Get user session from Supabase
 * @param {string} accessToken - Access token
 * @returns {Promise<Object>} Session data if valid, null if invalid
 */
async function getUserSession(accessToken) {
  try {
    const { data: { session }, error } = await supabase.auth.getSession(accessToken);
    
    if (error) {
      console.error('Session retrieval failed:', error.message);
      return null;
    }
    
    return session;
  } catch (error) {
    console.error('Session retrieval error:', error);
    return null;
  }
}

/**
 * Refresh access token using refresh token
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} New session data if successful, null if failed
 */
async function refreshAccessToken(refreshToken) {
  try {
    const { data: { session }, error } = await supabase.auth.refreshSession(refreshToken);
    
    if (error) {
      console.error('Token refresh failed:', error.message);
      return null;
    }
    
    return session;
  } catch (error) {
    console.error('Token refresh error:', error);
    return null;
  }
}

module.exports = {
  supabase,
  verifyJWT,
  extractTokenFromHeader,
  getUserSession,
  refreshAccessToken
};
