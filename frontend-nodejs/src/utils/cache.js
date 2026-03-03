const redis = require('redis');

// Redis client configuration
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CACHE_TTL = process.env.CACHE_TTL || 300; // 5 minutes default

let redisClient = null;
let isConnected = false;
let cacheEnabled = true;

/**
 * Initialize Redis connection
 */
async function initRedis() {
  // Check if Redis is disabled
  if (process.env.REDIS_DISABLED === 'true') {
    console.log('[CACHE] Redis caching disabled');
    cacheEnabled = false;
    return true;
  }

  try {
    redisClient = redis.createClient({
      url: REDIS_URL,
      retry_strategy: (options) => {
        if (options.error && options.error.code === 'ECONNREFUSED') {
          console.warn('[CACHE] Redis connection refused - caching disabled');
          cacheEnabled = false;
          return new Error('Redis connection refused');
        }
        return new Error('Redis connection failed');
      }
    });

    redisClient.on('connect', () => {
      console.log('[CACHE] Redis connected successfully');
      isConnected = true;
    });

    redisClient.on('error', (err) => {
      console.error('[CACHE] Redis connection error:', err.message);
      isConnected = false;
      cacheEnabled = false;
    });

    redisClient.on('end', () => {
      console.log('[CACHE] Redis connection ended');
      isConnected = false;
    });

    await redisClient.connect();
    return true;
  } catch (error) {
    console.error('[CACHE] Failed to initialize Redis:', error.message);
    cacheEnabled = false;
    return false;
  }
}

/**
 * Get cached value
 */
async function get(key) {
  if (!cacheEnabled || !isConnected || !redisClient) {
    return null;
  }

  try {
    const value = await redisClient.get(key);
    return value ? JSON.parse(value) : null;
  } catch (error) {
    console.error(`[CACHE] Get error for key ${key}:`, error.message);
    return null;
  }
}

/**
 * Set cached value with TTL
 */
async function set(key, value, ttl = CACHE_TTL) {
  if (!cacheEnabled || !isConnected || !redisClient) {
    return false;
  }

  try {
    await redisClient.setEx(key, ttl, JSON.stringify(value));
    console.log(`[CACHE] Cached key ${key} for ${ttl}s`);
    return true;
  } catch (error) {
    console.error(`[CACHE] Set error for key ${key}:`, error.message);
    return false;
  }
}

/**
 * Delete cached value
 */
async function del(key) {
  if (!isConnected || !redisClient) {
    return false;
  }

  try {
    await redisClient.del(key);
    console.log(`[CACHE] Deleted key ${key}`);
    return true;
  } catch (error) {
    console.error(`[CACHE] Delete error for key ${key}:`, error.message);
    return false;
  }
}

/**
 * Clear all cache
 */
async function clear() {
  if (!isConnected || !redisClient) {
    return false;
  }

  try {
    await redisClient.flushDb();
    console.log('[CACHE] Cleared all cache');
    return true;
  } catch (error) {
    console.error('[CACHE] Clear error:', error.message);
    return false;
  }
}

/**
 * Cache middleware for Express
 */
function cacheMiddleware(ttl = CACHE_TTL) {
  return async (req, res, next) => {
    // Only cache GET requests
    if (req.method !== 'GET') {
      return next();
    }

    const cacheKey = `cache:${req.method}:${req.originalUrl}:${req.user?.id || 'anonymous'}`;
    
    try {
      // Try to get from cache
      const cached = await get(cacheKey);
      if (cached) {
        console.log(`[CACHE] Hit for ${req.originalUrl}`);
        res.set('X-Cache', 'HIT');
        res.set('X-Cache-Key', cacheKey);
        return res.json(cached);
      }

      // Cache miss, continue to next middleware
      console.log(`[CACHE] Miss for ${req.originalUrl}`);
      res.set('X-Cache', 'MISS');
      
      // Override res.json to cache the response
      const originalJson = res.json;
      res.json = function(data) {
        // Cache the response
        set(cacheKey, data, ttl).catch(err => {
          console.error('[CACHE] Failed to cache response:', err.message);
        });
        
        // Call original json method
        return originalJson.call(this, data);
      };

      next();
    } catch (error) {
      console.error('[CACHE] Middleware error:', error.message);
      next();
    }
  };
}

/**
 * Invalidate cache by pattern
 */
async function invalidatePattern(pattern) {
  if (!isConnected || !redisClient) {
    return false;
  }

  try {
    const keys = await redisClient.keys(pattern);
    if (keys.length > 0) {
      await redisClient.del(keys);
      console.log(`[CACHE] Invalidated ${keys.length} keys matching ${pattern}`);
    }
    return true;
  } catch (error) {
    console.error(`[CACHE] Invalidate error for pattern ${pattern}:`, error.message);
    return false;
  }
}

/**
 * Get cache statistics
 */
async function getStats() {
  if (!isConnected || !redisClient) {
    return { connected: false };
  }

  try {
    const info = await redisClient.info('memory');
    const keyspace = await redisClient.dbSize();
    
    return {
      connected: true,
      keysCount: keyspace,
      memoryUsage: info,
      url: REDIS_URL
    };
  } catch (error) {
    console.error('[CACHE] Stats error:', error.message);
    return { connected: false, error: error.message };
  }
}

// Initialize Redis on module load
initRedis();

module.exports = {
  initRedis,
  get,
  set,
  del,
  clear,
  cacheMiddleware,
  invalidatePattern,
  getStats
};
