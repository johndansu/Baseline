const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { authenticateToken } = require('../middleware/auth');
const { cacheMiddleware } = require('../utils/cache');

const router = express.Router();

// Backend configuration
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8080';

/**
 * Create proxy middleware with common configuration
 */
function createProxy(target, pathRewrite) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathRewrite,
    onProxyReq: (proxyReq, req, res) => {
      // Add authentication headers if user is authenticated
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.id);
        proxyReq.setHeader('X-User-Email', req.user.email);
        proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.user_metadata?.roles || []));
      }
      
      // Log outgoing requests
      console.log(`[PROXY] ${req.method} ${req.originalUrl} -> ${target}${proxyReq.path}`);
    },
    onProxyRes: (proxyRes, req, res) => {
      // Log responses
      console.log(`[PROXY] Response ${proxyRes.statusCode} for ${req.method} ${req.originalUrl}`);
    },
    onError: (err, req, res) => {
      console.error(`[PROXY ERROR] ${err.message} for ${req.method} ${req.originalUrl}`);
      
      // Send standardized error response
      if (!res.headersSent) {
        res.status(502).json({
          error: 'Backend service unavailable',
          message: 'Unable to connect to backend service',
          timestamp: new Date().toISOString()
        });
      }
    }
  });
}

// Scan-related routes
router.use('/scans', 
  authenticateToken, // Protect scan routes
  cacheMiddleware(300), // Cache for 5 minutes
  createProxy(`${BACKEND_URL}/api/v1/scans`, {
    '^/api/scans': '/api/v1/scans'
  })
);

// Policy management routes
router.use('/policies', 
  authenticateToken, // Protect policy routes
  cacheMiddleware(600), // Cache for 10 minutes
  createProxy(`${BACKEND_URL}/api/v1/policies`, {
    '^/api/policies': '/api/v1/policies'
  })
);

// Project management routes
router.use('/projects', 
  authenticateToken, // Protect project routes
  cacheMiddleware(900), // Cache for 15 minutes
  createProxy(`${BACKEND_URL}/api/v1/projects`, {
    '^/api/projects': '/api/v1/projects'
  })
);

// User profile routes
router.use('/users', 
  authenticateToken, // Protect user routes
  cacheMiddleware(300), // Cache for 5 minutes
  createProxy(`${BACKEND_URL}/api/v1/users`, {
    '^/api/users': '/api/v1/users'
  })
);

// Audit and activity routes
router.use('/audit', 
  authenticateToken, // Protect audit routes
  cacheMiddleware(1800), // Cache for 30 minutes
  createProxy(`${BACKEND_URL}/api/v1/audit`, {
    '^/api/audit': '/api/v1/audit'
  })
);

// Health check for backend
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'api-proxy',
    backend: BACKEND_URL,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
