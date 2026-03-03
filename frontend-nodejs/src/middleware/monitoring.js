const { auditLogger } = require('./logging');

// Metrics storage (in production, this would use a proper metrics system)
const metrics = {
  requests: {
    total: 0,
    success: 0,
    error: 0,
    rateLimit: 0
  },
  responseTime: {
    total: 0,
    count: 0,
    avg: 0
  },
  users: {
    active: 0,
    authenticated: 0,
    anonymous: 0
  },
  api: {
    scans: 0,
    policies: 0,
    projects: 0,
    auth: 0
  },
  errors: {
    total: 0,
    auth: 0,
    server: 0,
    client: 0
  }
};

/**
 * Request metrics middleware
 */
function requestMetrics() {
  return (req, res, next) => {
    const startTime = Date.now();
    
    // Increment total requests
    metrics.requests.total++;
    
    // Track user metrics
    if (req.user) {
      metrics.users.authenticated++;
    } else {
      metrics.users.anonymous++;
    }
    
    // Track API endpoints
    if (req.path.startsWith('/api/')) {
      if (req.path.includes('/scans')) metrics.api.scans++;
      else if (req.path.includes('/policies')) metrics.api.policies++;
      else if (req.path.includes('/projects')) metrics.api.projects++;
      else if (req.path.includes('/auth')) metrics.api.auth++;
    }
    
    // Override res.end to capture metrics
    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
      const responseTime = Date.now() - startTime;
      
      // Update response time metrics
      metrics.responseTime.total += responseTime;
      metrics.responseTime.count++;
      metrics.responseTime.avg = Math.round(metrics.responseTime.total / metrics.responseTime.count);
      
      // Update success/error metrics
      if (res.statusCode >= 200 && res.statusCode < 400) {
        metrics.requests.success++;
      } else {
        metrics.requests.error++;
        metrics.errors.total++;
        
        // Categorize errors
        if (res.statusCode === 401 || res.statusCode === 403) {
          metrics.errors.auth++;
        } else if (res.statusCode >= 500) {
          metrics.errors.server++;
        } else {
          metrics.errors.client++;
        }
      }
      
      // Log slow requests
      if (responseTime > 1000) {
        auditLogger('SLOW_REQUEST', {
          url: req.originalUrl,
          method: req.method,
          responseTime,
          statusCode: res.statusCode,
          userAgent: req.get('User-Agent')
        });
      }
      
      // Call original end
      originalEnd.call(this, chunk, encoding);
    };
    
    next();
  };
}

/**
 * Active user tracking
 */
function activeUsers() {
  const activeUsers = new Set();
  
  return (req, res, next) => {
    if (req.user) {
      activeUsers.add(req.user.id);
      metrics.users.active = activeUsers.size;
    }
    
    next();
  };
}

/**
 * Health check metrics
 */
function healthMetrics() {
  return (req, res, next) => {
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    
    // Calculate health score
    let healthScore = 100;
    
    // Deduct for high error rate
    const errorRate = metrics.requests.total > 0 ? (metrics.errors.total / metrics.requests.total) * 100 : 0;
    if (errorRate > 5) healthScore -= 20;
    if (errorRate > 10) healthScore -= 30;
    
    // Deduct for high response time
    if (metrics.responseTime.avg > 2000) healthScore -= 15;
    if (metrics.responseTime.avg > 5000) healthScore -= 25;
    
    // Deduct for high memory usage
    const memoryUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
    if (memoryUsagePercent > 80) healthScore -= 20;
    if (memoryUsagePercent > 90) healthScore -= 30;
    
    const health = {
      status: healthScore >= 80 ? 'healthy' : healthScore >= 60 ? 'degraded' : 'unhealthy',
      score: Math.max(0, healthScore),
      uptime: Math.floor(uptime),
      memory: {
        used: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
        total: Math.round(memoryUsage.heapTotal / 1024 / 1024), // MB
        percentage: Math.round(memoryUsagePercent)
      },
      metrics: {
        requests: metrics.requests,
        responseTime: {
          average: metrics.responseTime.avg,
          total: metrics.responseTime.total
        },
        users: metrics.users,
        errors: metrics.errors
      }
    };
    
    // Add metrics to response
    req.metrics = health;
    
    next();
  };
}

/**
 * Metrics endpoint
 */
function getMetrics() {
  return {
    ...metrics,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  };
}

/**
 * Reset metrics (for testing or periodic reset)
 */
function resetMetrics() {
  metrics.requests.total = 0;
  metrics.requests.success = 0;
  metrics.requests.error = 0;
  metrics.responseTime.total = 0;
  metrics.responseTime.count = 0;
  metrics.responseTime.avg = 0;
  metrics.users.active = 0;
  metrics.users.authenticated = 0;
  metrics.users.anonymous = 0;
  metrics.api.scans = 0;
  metrics.api.policies = 0;
  metrics.api.projects = 0;
  metrics.api.auth = 0;
  metrics.errors.total = 0;
  metrics.errors.auth = 0;
  metrics.errors.server = 0;
  metrics.errors.client = 0;
  
  auditLogger('METRICS_RESET', { timestamp: new Date().toISOString() });
}

module.exports = {
  requestMetrics,
  activeUsers,
  healthMetrics,
  getMetrics,
  resetMetrics
};
