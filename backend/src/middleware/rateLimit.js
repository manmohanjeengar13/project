/**
 * Rate Limit Middleware
 * Advanced rate limiting with multiple strategies and Redis support
 */

import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Database } from '../core/Database.js';
import { Config } from '../config/environment.js';
import { rateLimitConfig, securityMode } from '../config/security.js';
import { HTTP_STATUS, ERROR_CODES, ATTACK_TYPES, ATTACK_SEVERITY, USER_ROLES } from '../config/constants.js';

const logger = Logger.getInstance();
const cache = Cache.getInstance();
const db = Database.getInstance();

/**
 * Create rate limiter with Redis or Memory store
 */
function createLimiter(options = {}) {
  const {
    windowMs = rateLimitConfig.global.windowMs,
    max = rateLimitConfig.global.max,
    message = rateLimitConfig.global.message,
    keyGenerator = (req) => req.ip,
    skip = (req) => securityMode.isVulnerable || !rateLimitConfig.enabled,
    handler = defaultHandler,
    ...otherOptions
  } = options;

  const limiterConfig = {
    windowMs,
    max,
    message,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator,
    skip,
    handler,
    ...otherOptions
  };

  // Use Redis store if available and enabled
  if (Config.redis.enabled && rateLimitConfig.enabled) {
    try {
      const redis = require('redis');
      const client = redis.createClient({
        socket: {
          host: Config.redis.host,
          port: Config.redis.port
        },
        password: Config.redis.password,
        database: Config.redis.db
      });

      client.connect().catch(err => {
        logger.error('Redis connection failed for rate limiter:', err);
      });

      limiterConfig.store = new RedisStore({
        client,
        prefix: `${Config.redis.prefix}ratelimit:`,
        sendCommand: (...args) => client.sendCommand(args)
      });

      logger.debug('Rate limiter using Redis store');
    } catch (error) {
      logger.warn('Redis not available, using memory store for rate limiter');
    }
  }

  return rateLimit(limiterConfig);
}

/**
 * Default rate limit handler
 */
function defaultHandler(req, res) {
  logger.warn('Rate limit exceeded', {
    ip: req.ip,
    path: req.path,
    userId: req.user?.id,
    limit: req.rateLimit?.limit,
    current: req.rateLimit?.current
  });

  // Log rate limit attack
  logRateLimitAttack(req);

  res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
    success: false,
    error: ERROR_CODES.RATE_LIMIT_EXCEEDED,
    message: 'Too many requests. Please try again later.',
    retryAfter: Math.ceil(req.rateLimit.resetTime.getTime() - Date.now()) / 1000,
    limit: req.rateLimit.limit,
    remaining: 0,
    resetTime: req.rateLimit.resetTime.toISOString()
  });
}

/**
 * Log rate limit attack
 */
async function logRateLimitAttack(req) {
  try {
    await db.execute(
      `INSERT INTO attack_logs (
        attack_type, severity, endpoint, method, 
        ip_address, user_agent, user_id, success, blocked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ATTACK_TYPES.DOS,
        ATTACK_SEVERITY.MEDIUM,
        req.path,
        req.method,
        req.ip,
        req.get('user-agent'),
        req.user?.id || null,
        false,
        true
      ]
    );
  } catch (error) {
    logger.error('Failed to log rate limit attack:', error);
  }
}

/**
 * Global rate limiter
 */
export const rateLimitMiddleware = createLimiter({
  windowMs: rateLimitConfig.global.windowMs,
  max: rateLimitConfig.global.max,
  message: rateLimitConfig.global.message
});

/**
 * API rate limiter
 */
export const apiRateLimit = createLimiter({
  windowMs: rateLimitConfig.api.windowMs,
  max: rateLimitConfig.api.max,
  message: rateLimitConfig.api.message,
  keyGenerator: (req) => {
    // Use user ID if authenticated, otherwise IP
    return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
  }
});

/**
 * Login rate limiter (strict)
 */
export const loginRateLimit = createLimiter({
  windowMs: rateLimitConfig.login.windowMs,
  max: rateLimitConfig.login.max,
  message: rateLimitConfig.login.message,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  keyGenerator: (req) => {
    // Combine IP and username for targeted limiting
    const username = req.body?.username || req.body?.email || '';
    return `login:${req.ip}:${username}`;
  },
  handler: async (req, res) => {
    logger.warn('Login rate limit exceeded', {
      ip: req.ip,
      username: req.body?.username || req.body?.email
    });

    await logRateLimitAttack(req);

    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      error: ERROR_CODES.RATE_LIMIT_EXCEEDED,
      message: 'Too many login attempts. Please try again later.',
      retryAfter: Math.ceil((req.rateLimit.resetTime.getTime() - Date.now()) / 1000)
    });
  }
});

/**
 * Registration rate limiter
 */
export const registrationRateLimit = createLimiter({
  windowMs: rateLimitConfig.register.windowMs,
  max: rateLimitConfig.register.max,
  message: rateLimitConfig.register.message,
  keyGenerator: (req) => `register:${req.ip}`
});

/**
 * Password reset rate limiter
 */
export const passwordResetRateLimit = createLimiter({
  windowMs: rateLimitConfig.passwordReset.windowMs,
  max: rateLimitConfig.passwordReset.max,
  message: rateLimitConfig.passwordReset.message,
  keyGenerator: (req) => {
    const email = req.body?.email || '';
    return `reset:${req.ip}:${email}`;
  }
});

/**
 * Upload rate limiter
 */
export const uploadRateLimit = createLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: securityMode.isVulnerable ? 1000 : 50,
  message: 'Too many uploads. Please try again later.',
  keyGenerator: (req) => req.user ? `upload:user:${req.user.id}` : `upload:ip:${req.ip}`
});

/**
 * Search rate limiter
 */
export const searchRateLimit = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: securityMode.isVulnerable ? 1000 : 30,
  message: 'Too many search requests.',
  keyGenerator: (req) => `search:${req.ip}`
});

/**
 * Comment/Review rate limiter
 */
export const commentRateLimit = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: securityMode.isVulnerable ? 1000 : 10,
  message: 'Too many comments. Please slow down.',
  keyGenerator: (req) => req.user ? `comment:user:${req.user.id}` : `comment:ip:${req.ip}`
});

/**
 * Role-based rate limiting
 */
export const roleBasedRateLimit = (limits = {}) => {
  return createLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: (req) => {
      if (!req.user) {
        return limits.anonymous || limits.default || 10;
      }

      const userRole = req.user.role;
      
      // Role-specific limits
      const roleLimits = {
        [USER_ROLES.SUPER_ADMIN]: 10000,
        [USER_ROLES.ADMIN]: 1000,
        [USER_ROLES.MODERATOR]: 500,
        [USER_ROLES.DEVELOPER]: 200,
        [USER_ROLES.CUSTOMER]: 100,
        ...limits
      };

      return roleLimits[userRole] || limits.default || 100;
    },
    keyGenerator: (req) => {
      return req.user ? `role:${req.user.id}` : `ip:${req.ip}`;
    }
  });
};

/**
 * Endpoint-specific rate limiter factory
 */
export const createEndpointLimiter = (endpoint, max, windowMs = 60000) => {
  return createLimiter({
    windowMs,
    max: securityMode.isVulnerable ? 10000 : max,
    message: `Too many requests to ${endpoint}`,
    keyGenerator: (req) => `${endpoint}:${req.ip}`
  });
};

/**
 * Slow down middleware (progressive delays)
 */
export const slowDown = (options = {}) => {
  const {
    windowMs = 60 * 1000,
    delayAfter = 10,
    delayMs = 500,
    maxDelayMs = 20000,
    skipSuccessfulRequests = false,
    skipFailedRequests = false
  } = options;

  const requests = new Map();

  return async (req, res, next) => {
    if (securityMode.isVulnerable) {
      return next();
    }

    const key = req.ip;
    const now = Date.now();

    // Clean old entries
    for (const [k, v] of requests.entries()) {
      if (now - v.resetTime > windowMs) {
        requests.delete(k);
      }
    }

    // Get or create request counter
    let requestData = requests.get(key);
    if (!requestData || now - requestData.resetTime > windowMs) {
      requestData = {
        count: 0,
        resetTime: now
      };
      requests.set(key, requestData);
    }

    requestData.count++;

    // Calculate delay
    if (requestData.count > delayAfter) {
      const delayCount = requestData.count - delayAfter;
      const delay = Math.min(delayCount * delayMs, maxDelayMs);

      logger.debug(`Slowing down request from ${key}`, {
        count: requestData.count,
        delay
      });

      await new Promise(resolve => setTimeout(resolve, delay));
    }

    next();
  };
};

/**
 * Adaptive rate limiting (adjusts based on server load)
 */
export const adaptiveRateLimit = () => {
  return createLimiter({
    windowMs: 60 * 1000,
    max: (req) => {
      const cpuUsage = process.cpuUsage();
      const memUsage = process.memoryUsage();
      
      // Reduce limits under high load
      const memPercent = memUsage.heapUsed / memUsage.heapTotal;
      
      let baseLimit = 100;
      
      if (memPercent > 0.9) {
        baseLimit = 10; // Severe load
      } else if (memPercent > 0.7) {
        baseLimit = 50; // High load
      } else if (memPercent > 0.5) {
        baseLimit = 75; // Medium load
      }

      return securityMode.isVulnerable ? 10000 : baseLimit;
    },
    keyGenerator: (req) => `adaptive:${req.ip}`
  });
};

/**
 * Burst rate limiting (allows bursts, then strict limiting)
 */
export const burstRateLimit = (burstMax = 50, sustainedMax = 100, windowMs = 60000) => {
  const burstLimiter = createLimiter({
    windowMs: 1000, // 1 second
    max: securityMode.isVulnerable ? 10000 : burstMax,
    message: 'Burst limit exceeded'
  });

  const sustainedLimiter = createLimiter({
    windowMs,
    max: securityMode.isVulnerable ? 10000 : sustainedMax,
    message: 'Sustained rate limit exceeded'
  });

  return [burstLimiter, sustainedLimiter];
};

/**
 * Conditional rate limiting
 */
export const conditionalRateLimit = (condition, limiter) => {
  return (req, res, next) => {
    if (condition(req)) {
      return limiter(req, res, next);
    }
    next();
  };
};

/**
 * Skip rate limit for authenticated users
 */
export const skipRateLimitForAuth = (limiter) => {
  return conditionalRateLimit((req) => !req.user, limiter);
};

/**
 * Get rate limit info
 */
export const getRateLimitInfo = (req, res) => {
  res.json({
    success: true,
    enabled: rateLimitConfig.enabled && !securityMode.isVulnerable,
    mode: securityMode.current,
    limits: {
      global: {
        windowMs: rateLimitConfig.global.windowMs,
        max: rateLimitConfig.global.max
      },
      api: {
        windowMs: rateLimitConfig.api.windowMs,
        max: rateLimitConfig.api.max
      },
      login: {
        windowMs: rateLimitConfig.login.windowMs,
        max: rateLimitConfig.login.max
      }
    },
    current: req.rateLimit || null
  });
};

/**
 * Reset rate limit for IP or user
 */
export const resetRateLimit = async (identifier) => {
  try {
    // If using Redis
    if (Config.redis.enabled) {
      const pattern = `${Config.redis.prefix}ratelimit:*${identifier}*`;
      await cache.deleteByPattern(pattern);
    }

    logger.info(`Rate limit reset for: ${identifier}`);
    return { success: true, message: 'Rate limit reset' };
  } catch (error) {
    logger.error('Failed to reset rate limit:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Get rate limit statistics
 */
export const getRateLimitStats = async () => {
  try {
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total_blocks,
        COUNT(CASE WHEN created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as last_24h,
        COUNT(CASE WHEN created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as last_hour,
        COUNT(DISTINCT ip_address) as unique_ips
       FROM attack_logs
       WHERE attack_type = ?`,
      [ATTACK_TYPES.DOS]
    );

    return stats[0] || {
      total_blocks: 0,
      last_24h: 0,
      last_hour: 0,
      unique_ips: 0
    };
  } catch (error) {
    logger.error('Failed to get rate limit stats:', error);
    return null;
  }
};

export default {
  rateLimitMiddleware,
  apiRateLimit,
  loginRateLimit,
  registrationRateLimit,
  passwordResetRateLimit,
  uploadRateLimit,
  searchRateLimit,
  commentRateLimit,
  roleBasedRateLimit,
  createEndpointLimiter,
  slowDown,
  adaptiveRateLimit,
  burstRateLimit,
  conditionalRateLimit,
  skipRateLimitForAuth,
  getRateLimitInfo,
  resetRateLimit,
  getRateLimitStats
};
