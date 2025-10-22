
/**
 * CSRF Protection Middleware
 * Cross-Site Request Forgery protection with token validation
 */

import crypto from 'crypto';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { csrfConfig, securityMode } from '../config/security.js';
import { HTTP_STATUS, ERROR_CODES, ATTACK_TYPES, ATTACK_SEVERITY } from '../config/constants.js';
import { Database } from '../core/Database.js';

const logger = Logger.getInstance();
const cache = Cache.getInstance();
const db = Database.getInstance();

/**
 * Generate CSRF token
 */
export const generateCsrfToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * CSRF Protection Middleware
 */
export const csrfMiddleware = async (req, res, next) => {
  // Skip if CSRF is disabled or in vulnerable mode
  if (!csrfConfig.enabled || securityMode.isVulnerable) {
    return next();
  }

  // Skip for safe methods
  if (csrfConfig.ignoreMethods.includes(req.method)) {
    return next();
  }

  try {
    // Get token from request
    const token = csrfConfig.value(req);

    if (!token) {
      logger.warn('CSRF token missing', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        userId: req.user?.id
      });

      // Log as potential attack
      await logCsrfAttack(req, 'missing_token');

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'CSRF token missing'
      });
    }

    // Get session token
    const sessionToken = req.session?.csrfToken;

    if (!sessionToken) {
      logger.warn('CSRF session token missing', {
        ip: req.ip,
        path: req.path,
        userId: req.user?.id
      });

      await logCsrfAttack(req, 'missing_session_token');

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'Invalid CSRF token'
      });
    }

    // Validate token (constant-time comparison)
    if (!secureCompare(token, sessionToken)) {
      logger.warn('CSRF token mismatch', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        userId: req.user?.id
      });

      await logCsrfAttack(req, 'token_mismatch');

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'Invalid CSRF token'
      });
    }

    // Token is valid
    logger.debug('CSRF token validated', {
      path: req.path,
      userId: req.user?.id
    });

    next();
  } catch (error) {
    logger.error('CSRF middleware error:', error);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: ERROR_CODES.INTERNAL_ERROR,
      message: 'CSRF validation error'
    });
  }
};

/**
 * Initialize CSRF token for session
 */
export const initCsrfToken = (req, res, next) => {
  if (!csrfConfig.enabled || securityMode.isVulnerable) {
    return next();
  }

  // Generate token if not exists
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateCsrfToken();
    logger.debug('CSRF token generated for session');
  }

  // Make token available in response
  res.locals.csrfToken = req.session.csrfToken;

  // Set token in cookie (optional)
  if (csrfConfig.cookie) {
    res.cookie(csrfConfig.cookie.key, req.session.csrfToken, {
      path: csrfConfig.cookie.path,
      httpOnly: csrfConfig.cookie.httpOnly,
      secure: csrfConfig.cookie.secure,
      sameSite: csrfConfig.cookie.sameSite
    });
  }

  next();
};

/**
 * Get CSRF token endpoint
 */
export const getCsrfToken = (req, res) => {
  if (!csrfConfig.enabled || securityMode.isVulnerable) {
    return res.json({
      success: true,
      token: 'csrf-disabled',
      message: 'CSRF protection is disabled'
    });
  }

  const token = req.session?.csrfToken || generateCsrfToken();
  
  if (!req.session.csrfToken) {
    req.session.csrfToken = token;
  }

  res.json({
    success: true,
    token,
    headerName: 'X-CSRF-Token'
  });
};

/**
 * Refresh CSRF token
 */
export const refreshCsrfToken = (req, res) => {
  if (!csrfConfig.enabled || securityMode.isVulnerable) {
    return res.json({
      success: true,
      token: 'csrf-disabled',
      message: 'CSRF protection is disabled'
    });
  }

  const newToken = generateCsrfToken();
  req.session.csrfToken = newToken;

  logger.debug('CSRF token refreshed', {
    userId: req.user?.id,
    sessionId: req.session?.id
  });

  res.json({
    success: true,
    token: newToken,
    headerName: 'X-CSRF-Token'
  });
};

/**
 * Secure constant-time string comparison
 */
function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(a, 'utf8'),
    Buffer.from(b, 'utf8')
  );
}

/**
 * Log CSRF attack attempt
 */
async function logCsrfAttack(req, reason) {
  try {
    await db.execute(
      `INSERT INTO attack_logs (
        attack_type, severity, endpoint, method, payload,
        ip_address, user_agent, user_id, success, blocked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ATTACK_TYPES.CSRF,
        ATTACK_SEVERITY.HIGH,
        req.path,
        req.method,
        JSON.stringify({ reason, headers: req.headers }),
        req.ip,
        req.get('user-agent'),
        req.user?.id || null,
        false,
        true
      ]
    );

    // Notify via WebSocket if available
    try {
      const { WebSocket } = await import('../core/WebSocket.js');
      const ws = WebSocket.getInstance();
      if (ws.io) {
        await ws.notifyAttack({
          type: ATTACK_TYPES.CSRF,
          severity: ATTACK_SEVERITY.HIGH,
          ip: req.ip,
          path: req.path,
          reason
        });
      }
    } catch (error) {
      // WebSocket not available
    }
  } catch (error) {
    logger.error('Failed to log CSRF attack:', error);
  }
}

/**
 * Validate CSRF token (utility function)
 */
export const validateCsrfToken = (token, sessionToken) => {
  if (!token || !sessionToken) {
    return false;
  }
  return secureCompare(token, sessionToken);
};

/**
 * CSRF protection for specific routes
 */
export const csrfProtect = csrfMiddleware;

/**
 * Skip CSRF for specific routes
 */
export const skipCsrf = (req, res, next) => {
  req.skipCsrf = true;
  next();
};

/**
 * Conditional CSRF protection
 */
export const csrfIf = (condition) => {
  return (req, res, next) => {
    if (condition(req)) {
      return csrfMiddleware(req, res, next);
    }
    next();
  };
};

/**
 * Double Submit Cookie pattern
 */
export const doubleSubmitCookie = async (req, res, next) => {
  if (!csrfConfig.enabled || securityMode.isVulnerable) {
    return next();
  }

  if (csrfConfig.ignoreMethods.includes(req.method)) {
    return next();
  }

  try {
    // Get token from header and cookie
    const headerToken = req.headers['x-csrf-token'];
    const cookieToken = req.cookies['_csrf'];

    if (!headerToken || !cookieToken) {
      await logCsrfAttack(req, 'double_submit_missing');
      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: 'CSRF_TOKEN_MISSING',
        message: 'CSRF token validation failed'
      });
    }

    if (!secureCompare(headerToken, cookieToken)) {
      await logCsrfAttack(req, 'double_submit_mismatch');
      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: 'CSRF_TOKEN_INVALID',
        message: 'CSRF token validation failed'
      });
    }

    next();
  } catch (error) {
    logger.error('Double submit cookie CSRF error:', error);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: ERROR_CODES.INTERNAL_ERROR,
      message: 'CSRF validation error'
    });
  }
};

/**
 * Synchronizer Token pattern (recommended)
 */
export const synchronizerToken = csrfMiddleware;

/**
 * CSRF token rotation (for sensitive operations)
 */
export const rotateCsrfToken = (req, res, next) => {
  if (csrfConfig.enabled && !securityMode.isVulnerable) {
    req.session.csrfToken = generateCsrfToken();
    res.locals.csrfToken = req.session.csrfToken;
    logger.debug('CSRF token rotated');
  }
  next();
};

/**
 * Get CSRF statistics
 */
export const getCsrfStats = async () => {
  try {
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total_attempts,
        COUNT(CASE WHEN created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as last_24h,
        COUNT(CASE WHEN created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as last_hour,
        COUNT(DISTINCT ip_address) as unique_ips
       FROM attack_logs
       WHERE attack_type = ?`,
      [ATTACK_TYPES.CSRF]
    );

    return stats[0] || {
      total_attempts: 0,
      last_24h: 0,
      last_hour: 0,
      unique_ips: 0
    };
  } catch (error) {
    logger.error('Failed to get CSRF stats:', error);
    return null;
  }
};

export default {
  csrfMiddleware,
  initCsrfToken,
  getCsrfToken,
  refreshCsrfToken,
  csrfProtect,
  skipCsrf,
  csrfIf,
  doubleSubmitCookie,
  synchronizerToken,
  rotateCsrfToken,
  validateCsrfToken,
  generateCsrfToken,
  getCsrfStats
};
