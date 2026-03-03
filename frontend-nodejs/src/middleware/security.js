const rateLimit = require('express-rate-limit');
const { auditLogger, securityLogger } = require('./logging');

/**
 * Rate limiting middleware
 */
function createRateLimit(options = {}) {
  const config = {
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
    max: options.max || 100, // limit each IP to 100 requests per windowMs
    message: {
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter: Math.ceil(options.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      securityLogger('RATE_LIMIT_EXCEEDED', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        url: req.originalUrl,
        method: req.method
      });
      
      res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil((options.windowMs || 15 * 60 * 1000) / 1000)
      });
    }
  };

  return rateLimit(config);
}

/**
 * API rate limiting (stricter)
 */
const apiRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // limit each IP to 50 API requests per windowMs
  message: 'API rate limit exceeded'
});

/**
 * Auth rate limiting (very strict)
 */
const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth attempts per windowMs
  message: 'Authentication rate limit exceeded'
});

/**
 * Request size limiter
 */
function requestSizeLimit(options = {}) {
  const maxSize = options.maxSize || '10mb';
  
  return (req, res, next) => {
    const contentLength = req.get('Content-Length');
    
    if (contentLength && parseInt(contentLength) > parseSize(maxSize)) {
      securityLogger('REQUEST_SIZE_EXCEEDED', {
        ip: req.ip,
        url: req.originalUrl,
        contentLength,
        maxSize
      });
      
      return res.status(413).json({
        error: 'Request entity too large',
        message: `Request size exceeds maximum allowed size of ${maxSize}`
      });
    }
    
    next();
  };
}

/**
 * Parse size string to bytes
 */
function parseSize(sizeStr) {
  const units = { b: 1, kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 };
  const match = sizeStr.toLowerCase().match(/^(\d+)(b|kb|mb|gb)$/);
  
  if (!match) return 0;
  
  const [, size, unit] = match;
  return parseInt(size) * (units[unit] || 1);
}

/**
 * IP whitelist middleware
 */
function ipWhitelist(whitelist = []) {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (whitelist.length > 0 && !whitelist.includes(clientIP)) {
      securityLogger('IP_BLOCKED', {
        ip: clientIP,
        url: req.originalUrl,
        userAgent: req.get('User-Agent')
      });
      
      return res.status(403).json({
        error: 'Access denied',
        message: 'Your IP address is not authorized to access this resource'
      });
    }
    
    next();
  };
}

/**
 * Suspicious activity detector
 */
function suspiciousActivityDetector() {
  const suspiciousPatterns = [
    /\.\./,  // Path traversal
    /<script/i,  // XSS attempts
    /union.*select/i,  // SQL injection
    /javascript:/i,  // JavaScript protocol
    /data:.*base64/i  // Data URI attacks
  ];
  
  return (req, res, next) => {
    const url = req.originalUrl;
    const userAgent = req.get('User-Agent') || '';
    
    // Check URL for suspicious patterns
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url)) {
        securityLogger('SUSPICIOUS_URL_DETECTED', {
          ip: req.ip,
          url,
          userAgent,
          pattern: pattern.toString()
        });
        
        return res.status(400).json({
          error: 'Bad request',
          message: 'Invalid request format'
        });
      }
    }
    
    // Check for suspicious user agents
    const suspiciousAgents = [
      /sqlmap/i,
      /nikto/i,
      /nmap/i,
      /masscan/i,
      /burp/i,
      /metasploit/i
    ];
    
    for (const agentPattern of suspiciousAgents) {
      if (agentPattern.test(userAgent)) {
        securityLogger('SUSPICIOUS_USER_AGENT', {
          ip: req.ip,
          url,
          userAgent
        });
        
        return res.status(403).json({
          error: 'Access denied',
          message: 'Automated tools are not allowed'
        });
      }
    }
    
    next();
  };
}

/**
 * Security headers middleware
 */
function securityHeaders() {
  return (req, res, next) => {
    // Additional security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    // Remove server information
    res.removeHeader('X-Powered-By');
    
    next();
  };
}

module.exports = {
  createRateLimit,
  apiRateLimit,
  authRateLimit,
  requestSizeLimit,
  ipWhitelist,
  suspiciousActivityDetector,
  securityHeaders
};
