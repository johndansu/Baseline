const { getUserSession, refreshAccessToken } = require('../utils/supabase');

/**
 * Session management middleware
 * Handles token refresh and session validation
 */
function sessionManager(req, res, next) {
  // Skip session management for public routes
  const publicRoutes = ['/health', '/api/status', '/signin.html', '/signup.html', '/index.html'];
  if (publicRoutes.includes(req.path) || req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/assets/')) {
    return next();
  }

  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return next();
  }

  const accessToken = authHeader.replace('Bearer ', '');
  
  // Check if session is still valid
  getUserSession(accessToken)
    .then(session => {
      if (!session) {
        // Session invalid, try refresh
        return handleTokenRefresh(req, res, next);
      }

      // Check if token is close to expiring (within 5 minutes)
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = session.expires_at;
      const timeUntilExpiry = expiresAt - now;
      
      if (timeUntilExpiry < 300) { // 5 minutes
        // Token expiring soon, refresh it
        return handleTokenRefresh(req, res, next, session.refresh_token);
      }

      // Session is valid, continue
      req.session = session;
      req.user = session.user;
      next();
    })
    .catch(error => {
      console.error('Session management error:', error);
      next();
    });
}

/**
 * Handle token refresh
 */
function handleTokenRefresh(req, res, next, refreshToken) {
  if (!refreshToken) {
    return next();
  }

  refreshAccessToken(refreshToken)
    .then(newSession => {
      if (newSession) {
        // Update request with new token
        req.session = newSession;
        req.user = newSession.user;
        
        // Set new token in response header for client to update
        res.setHeader('X-New-Access-Token', newSession.access_token);
        res.setHeader('X-New-Refresh-Token', newSession.refresh_token);
      }
      next();
    })
    .catch(error => {
      console.error('Token refresh failed in middleware:', error);
      next();
    });
}

/**
 * Rate limiting for auth endpoints
 */
const authRateLimit = new Map();

function rateLimitAuth(req, res, next) {
  const clientId = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 10;

  if (!authRateLimit.has(clientId)) {
    authRateLimit.set(clientId, { requests: 0, resetTime: now + windowMs });
  }

  const clientData = authRateLimit.get(clientId);
  
  // Reset window if expired
  if (now > clientData.resetTime) {
    clientData.requests = 0;
    clientData.resetTime = now + windowMs;
  }

  clientData.requests++;

  // Set rate limit headers
  res.setHeader('X-RateLimit-Limit', maxRequests);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - clientData.requests));
  res.setHeader('X-RateLimit-Reset', new Date(clientData.resetTime).toISOString());

  if (clientData.requests > maxRequests) {
    return res.status(429).json({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter: Math.ceil((clientData.resetTime - now) / 1000)
    });
  }

  next();
}

// Clean up expired rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [clientId, data] of authRateLimit.entries()) {
    if (now > data.resetTime) {
      authRateLimit.delete(clientId);
    }
  }
}, 5 * 60 * 1000); // Clean every 5 minutes

module.exports = {
  sessionManager,
  rateLimitAuth
};
