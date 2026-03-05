const morgan = require('morgan');

function isProduction() {
  return process.env.NODE_ENV === 'production';
}

/**
 * Custom logging middleware for API requests and responses
 */
function apiLogger(req, res, next) {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();
  const requestId = req.id || generateRequestId();
  
  if (!isProduction()) {
    // Verbose request diagnostics are only for non-production debugging.
    console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`, {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id || 'anonymous',
      timestamp,
      requestId
    });
  }

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    if (isProduction()) {
      console.log(`[API] ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms requestId=${requestId}`);
    } else {
      // Verbose response diagnostics are only for non-production debugging.
      console.log(`[${timestamp}] ${res.statusCode} ${req.method} ${req.originalUrl} (${duration}ms)`, {
        statusCode: res.statusCode,
        method: req.method,
        url: req.originalUrl,
        duration,
        userId: req.user?.id || 'anonymous',
        contentLength: res.get('Content-Length') || 0,
        requestId
      });
    }

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
  const requestId = req.id || generateRequestId();
  
  if (isProduction()) {
    console.error(`[${timestamp}] ERROR ${req.method} ${req.originalUrl}`, {
      statusCode: Number.isInteger(err?.status) ? err.status : 500,
      method: req.method,
      url: req.originalUrl,
      userId: req.user?.id || 'anonymous',
      timestamp,
      requestId
    });
  } else {
    console.error(`[${timestamp}] ERROR ${req.method} ${req.originalUrl}`, {
      error: err.message,
      stack: err.stack,
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userId: req.user?.id || 'anonymous',
      timestamp,
      requestId
    });
  }

  // Send standardized error response
  if (!res.headersSent) {
    const statusCode = Number.isInteger(err.status) ? err.status : 500;
    const safeClientMessage =
      typeof err.publicMessage === 'string' && err.publicMessage.length > 0
        ? err.publicMessage
        : statusCode >= 500
          ? 'Internal server error'
          : 'Request failed';

    res.status(statusCode).json({
      error: statusCode >= 500 ? 'internal_error' : 'request_failed',
      message: safeClientMessage,
      timestamp,
      requestId
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
