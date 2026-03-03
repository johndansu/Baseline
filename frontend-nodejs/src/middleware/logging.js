const morgan = require('morgan');

/**
 * Custom logging middleware for API requests and responses
 */
function apiLogger(req, res, next) {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();
  
  // Log request details
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`, {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id || 'anonymous',
    timestamp
  });

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // Log response details
    console.log(`[${timestamp}] ${res.statusCode} ${req.method} ${req.originalUrl} (${duration}ms)`, {
      statusCode: res.statusCode,
      method: req.method,
      url: req.originalUrl,
      duration,
      userId: req.user?.id || 'anonymous',
      contentLength: res.get('Content-Length') || 0
    });

    // Call original end
    originalEnd.call(res, chunk, encoding);
  };

  next();
}

/**
 * Error logging middleware
 */
function errorLogger(err, req, res, next) {
  const timestamp = new Date().toISOString();
  
  console.error(`[${timestamp}] ERROR ${req.method} ${req.originalUrl}`, {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userId: req.user?.id || 'anonymous',
    timestamp
  });

  // Send standardized error response
  if (!res.headersSent) {
    res.status(err.status || 500).json({
      error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
      message: err.message,
      timestamp,
      requestId: req.id || generateRequestId()
    });
  }
}

/**
 * Generate unique request ID
 */
function generateRequestId() {
  return Math.random().toString(36).substr(2, 9);
}

/**
 * Morgan custom format for API logging
 */
const morganFormat = ':method :url :status :response-time ms - :remote-addr - :user-agent';

/**
 * Create morgan middleware with custom format
 */
function createApiLogger() {
  return morgan(morganFormat, {
    stream: {
      write: (message) => {
        console.log(`[API] ${message.trim()}`);
      }
    }
  });
}

/**
 * Audit logging for sensitive operations
 */
function auditLogger(action, details) {
  const timestamp = new Date().toISOString();
  
  console.log(`[AUDIT] ${action}`, {
    action,
    details,
    timestamp,
    level: 'INFO'
  });
}

/**
 * Security event logging
 */
function securityLogger(event, details) {
  const timestamp = new Date().toISOString();
  
  console.log(`[SECURITY] ${event}`, {
    event,
    details,
    timestamp,
    level: 'WARN'
  });
}

module.exports = {
  apiLogger,
  errorLogger,
  createApiLogger,
  auditLogger,
  securityLogger,
  generateRequestId
};
