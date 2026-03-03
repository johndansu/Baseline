const { verifyJWT, extractTokenFromHeader } = require('../utils/supabase');

/**
 * Authentication middleware for protected routes
 * Validates JWT token from Authorization header
 */
function authenticateToken(req, res, next) {
  // Skip authentication for health check and public routes
  const publicRoutes = ['/health', '/api/status', '/signin.html', '/signup.html', '/index.html'];
  if (publicRoutes.includes(req.path) || req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/assets/')) {
    return next();
  }

  // Extract token from Authorization header
  const authHeader = req.headers.authorization;
  const token = extractTokenFromHeader(authHeader);

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid access token in the Authorization header'
    });
  }

  // Verify the token
  verifyJWT(token)
    .then(user => {
      if (!user) {
        return res.status(401).json({
          error: 'Invalid token',
          message: 'The provided access token is invalid or expired'
        });
      }

      // Attach user to request object
      req.user = user;
      req.token = token;
      next();
    })
    .catch(error => {
      console.error('Authentication middleware error:', error);
      res.status(500).json({
        error: 'Authentication error',
        message: 'An error occurred during authentication'
      });
    });
}

/**
 * Optional authentication middleware
 * Attaches user to request if token is present, but doesn't require it
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = extractTokenFromHeader(authHeader);

  if (!token) {
    // No token provided, continue without user context
    return next();
  }

  // Try to verify token but don't fail if invalid
  verifyJWT(token)
    .then(user => {
      if (user) {
        req.user = user;
        req.token = token;
      }
      next();
    })
    .catch(() => {
      // Token verification failed, continue without user context
      next();
    });
}

/**
 * Role-based authorization middleware
 * @param {string[]} allowedRoles - Array of allowed user roles
 */
function authorizeRoles(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Please authenticate to access this resource'
      });
    }

    // Check if user has required role (assuming user metadata contains roles)
    const userRoles = req.user.user_metadata?.roles || [];
    const hasRequiredRole = allowedRoles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: 'You do not have permission to access this resource'
      });
    }

    next();
  };
}

/**
 * API key authentication middleware for server-to-server requests
 */
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      error: 'API key required',
      message: 'Please provide a valid API key in the X-API-Key header'
    });
  }

  // In a real implementation, you would validate against a database
  const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
  
  if (!validApiKeys.includes(apiKey)) {
    return res.status(401).json({
      error: 'Invalid API key',
      message: 'The provided API key is invalid'
    });
  }

  req.apiKey = apiKey;
  next();
}

module.exports = {
  authenticateToken,
  optionalAuth,
  authorizeRoles,
  authenticateApiKey
};
