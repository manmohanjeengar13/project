/**
 * Attack Detection Middleware
 * Real-time detection and blocking of security attacks
 */

import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { attackDetectionConfig, securityMode } from '../config/security.js';
import { ATTACK_TYPES, ATTACK_SEVERITY, HTTP_STATUS } from '../config/constants.js';

const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

/**
 * Main attack detection middleware
 */
export const attackDetectionMiddleware = async (req, res, next) => {
  if (!attackDetectionConfig.ids.enabled) {
    return next();
  }

  try {
    const detectedAttacks = [];

    // Check for SQL Injection
    const sqliDetected = detectSQLi(req);
    if (sqliDetected.detected) {
      detectedAttacks.push({
        type: ATTACK_TYPES.SQLI_CLASSIC,
        severity: ATTACK_SEVERITY.CRITICAL,
        ...sqliDetected
      });
    }

    // Check for XSS
    const xssDetected = detectXSS(req);
    if (xssDetected.detected) {
      detectedAttacks.push({
        type: ATTACK_TYPES.XSS_REFLECTED,
        severity: ATTACK_SEVERITY.HIGH,
        ...xssDetected
      });
    }

    // Check for Command Injection
    const cmdDetected = detectCommandInjection(req);
    if (cmdDetected.detected) {
      detectedAttacks.push({
        type: ATTACK_TYPES.COMMAND_INJECTION,
        severity: ATTACK_SEVERITY.CRITICAL,
        ...cmdDetected
      });
    }

    // Check for Path Traversal
    const pathDetected = detectPathTraversal(req);
    if (pathDetected.detected) {
      detectedAttacks.push({
        type: ATTACK_TYPES.PATH_TRAVERSAL,
        severity: ATTACK_SEVERITY.HIGH,
        ...pathDetected
      });
    }

    // If attacks detected
    if (detectedAttacks.length > 0) {
      await handleDetectedAttacks(req, res, detectedAttacks);
      
      // In secure mode, block the request
      if (!securityMode.isVulnerable) {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: 'ATTACK_DETECTED',
          message: 'Potential security threat detected',
          attackId: detectedAttacks[0].id
        });
      }
    }

    next();
  } catch (error) {
    logger.error('Attack detection error:', error);
    next();
  }
};

/**
 * Detect SQL Injection patterns
 */
function detectSQLi(req) {
  const patterns = attackDetectionConfig.ids.patterns.sqli;
  const locations = ['query', 'body', 'params'];
  
  for (const location of locations) {
    const data = req[location];
    if (!data) continue;

    const result = scanObject(data, patterns, location);
    if (result) {
      return {
        detected: true,
        location,
        field: result.field,
        payload: result.value,
        pattern: result.pattern.toString()
      };
    }
  }

  return { detected: false };
}

/**
 * Detect XSS patterns
 */
function detectXSS(req) {
  const patterns = attackDetectionConfig.ids.patterns.xss;
  const locations = ['query', 'body', 'params'];
  
  for (const location of locations) {
    const data = req[location];
    if (!data) continue;

    const result = scanObject(data, patterns, location);
    if (result) {
      return {
        detected: true,
        location,
        field: result.field,
        payload: result.value,
        pattern: result.pattern.toString()
      };
    }
  }

  return { detected: false };
}

/**
 * Detect Command Injection patterns
 */
function detectCommandInjection(req) {
  const patterns = attackDetectionConfig.ids.patterns.commandInjection;
  const locations = ['query', 'body', 'params'];
  
  for (const location of locations) {
    const data = req[location];
    if (!data) continue;

    const result = scanObject(data, patterns, location);
    if (result) {
      return {
        detected: true,
        location,
        field: result.field,
        payload: result.value,
        pattern: result.pattern.toString()
      };
    }
  }

  return { detected: false };
}

/**
 * Detect Path Traversal patterns
 */
function detectPathTraversal(req) {
  const patterns = attackDetectionConfig.ids.patterns.pathTraversal;
  const locations = ['query', 'body', 'params'];
  
  for (const location of locations) {
    const data = req[location];
    if (!data) continue;

    const result = scanObject(data, patterns, location);
    if (result) {
      return {
        detected: true,
        location,
        field: result.field,
        payload: result.value,
        pattern: result.pattern.toString()
      };
    }
  }

  return { detected: false };
}

/**
 * Scan object for malicious patterns
 */
function scanObject(obj, patterns, path = '') {
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;

    if (typeof value === 'string') {
      for (const pattern of patterns) {
        if (pattern.test(value)) {
          return {
            field: currentPath,
            value,
            pattern
          };
        }
      }
    } else if (typeof value === 'object' && value !== null) {
      const result = scanObject(value, patterns, currentPath);
      if (result) return result;
    }
  }

  return null;
}

/**
 * Handle detected attacks
 */
async function handleDetectedAttacks(req, res, attacks) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('user-agent');
  const userId = req.user?.id || null;

  for (const attack of attacks) {
    // Log attack
    logger.attack(attack.type, {
      ip,
      userAgent,
      userId,
      path: req.path,
      method: req.method,
      severity: attack.severity,
      payload: attack.payload,
      location: attack.location,
      field: attack.field
    });

    // Store in database
    try {
      const [result] = await db.execute(
        `INSERT INTO attack_logs (
          attack_type, severity, endpoint, method, payload, 
          ip_address, user_agent, user_id, success, blocked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          attack.type,
          attack.severity,
          req.path,
          req.method,
          attack.payload,
          ip,
          userAgent,
          userId,
          false, // Success (attack didn't succeed)
          !securityMode.isVulnerable // Blocked in secure mode
        ]
      );

      attack.id = result.insertId;
    } catch (error) {
      logger.error('Failed to log attack:', error);
    }

    // Update IP attack counter
    const ipKey = CacheKeyBuilder.custom('attack_count:', ip);
    const count = await cache.increment(ipKey, 1);
    
    if (!count) {
      await cache.set(ipKey, 1, 3600); // 1 hour TTL
    }

    // Check if IP should be blocked
    if (count >= attackDetectionConfig.ids.blockThreshold) {
      await blockIP(ip, attackDetectionConfig.ids.blockDuration);
    }

    // Notify via WebSocket if available
    try {
      const { WebSocket } = await import('../core/WebSocket.js');
      const ws = WebSocket.getInstance();
      if (ws.io) {
        await ws.notifyAttack({
          type: attack.type,
          severity: attack.severity,
          ip,
          path: req.path,
          payload: attack.payload
        });
      }
    } catch (error) {
      // WebSocket not available, skip
    }
  }
}

/**
 * Block IP address
 */
async function blockIP(ip, duration) {
  try {
    // Add to blacklist cache
    const key = CacheKeyBuilder.custom('ip_blocked:', ip);
    await cache.set(key, true, duration);

    // Add to database
    await db.execute(
      `INSERT INTO ip_blacklist (ip_address, reason, blocked_until, is_permanent)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE blocked_until = VALUES(blocked_until)`,
      [
        ip,
        'Exceeded attack threshold',
        new Date(Date.now() + duration),
        false
      ]
    );

    logger.warn(`IP blocked: ${ip} for ${duration}ms`);
  } catch (error) {
    logger.error('Failed to block IP:', error);
  }
}

/**
 * Check if IP is blocked
 */
export const checkIPBlacklist = async (req, res, next) => {
  if (!attackDetectionConfig.ipBlacklist.enabled) {
    return next();
  }

  const ip = req.ip || req.connection.remoteAddress;

  // Check whitelist first
  if (attackDetectionConfig.ipBlacklist.whitelist.includes(ip)) {
    return next();
  }

  // Check cache
  const key = CacheKeyBuilder.custom('ip_blocked:', ip);
  const blocked = await cache.get(key);

  if (blocked) {
    logger.warn(`Blocked IP attempted access: ${ip}`);
    return res.status(HTTP_STATUS.FORBIDDEN).json({
      success: false,
      error: 'IP_BLOCKED',
      message: 'Your IP address has been blocked due to suspicious activity'
    });
  }

  // Check database
  try {
    const [rows] = await db.execute(
      `SELECT * FROM ip_blacklist 
       WHERE ip_address = ? 
       AND (is_permanent = 1 OR blocked_until > NOW())
       LIMIT 1`,
      [ip]
    );

    if (rows.length > 0) {
      // Cache the result
      const ttl = rows[0].is_permanent ? 86400 : 
        Math.floor((new Date(rows[0].blocked_until) - Date.now()) / 1000);
      
      await cache.set(key, true, ttl);

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: 'IP_BLOCKED',
        message: 'Your IP address has been blocked'
      });
    }
  } catch (error) {
    logger.error('IP blacklist check error:', error);
  }

  next();
};

/**
 * Honeypot detection
 */
export const honeypotDetection = async (req, res, next) => {
  if (!attackDetectionConfig.honeypot.enabled) {
    return next();
  }

  const honeypotFields = attackDetectionConfig.honeypot.fields;
  
  // Check if any honeypot field is filled
  for (const field of honeypotFields) {
    if (req.body && req.body[field]) {
      // Bot detected
      logger.warn('Honeypot triggered', {
        ip: req.ip,
        field,
        value: req.body[field],
        path: req.path
      });

      // Log as attack
      await db.execute(
        `INSERT INTO attack_logs (
          attack_type, severity, endpoint, payload, 
          ip_address, user_agent, success
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          'honeypot_triggered',
          ATTACK_SEVERITY.MEDIUM,
          req.path,
          JSON.stringify({ field, value: req.body[field] }),
          req.ip,
          req.get('user-agent'),
          false
        ]
      );

      // Redirect to decoy page
      return res.redirect(attackDetectionConfig.honeypot.redirectUrl);
    }
  }

  next();
};

/**
 * Rate-based attack detection
 */
export const detectRateLimitAbuse = async (req, res, next) => {
  const ip = req.ip;
  const key = CacheKeyBuilder.custom('request_count:', ip);
  
  const count = await cache.increment(key, 1);
  
  if (count === 1) {
    await cache.expire(key, 60); // 1 minute window
  }

  // If more than 1000 requests per minute
  if (count > 1000) {
    logger.warn('Potential DoS attack detected', {
      ip,
      count,
      path: req.path
    });

    await db.execute(
      `INSERT INTO attack_logs (
        attack_type, severity, endpoint, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?)`,
      [
        ATTACK_TYPES.DOS,
        ATTACK_SEVERITY.HIGH,
        req.path,
        ip,
        req.get('user-agent')
      ]
    );

    if (!securityMode.isVulnerable) {
      await blockIP(ip, 3600000); // Block for 1 hour
      
      return res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
        success: false,
        error: 'TOO_MANY_REQUESTS',
        message: 'Request rate limit exceeded'
      });
    }
  }

  next();
};

/**
 * User-Agent anomaly detection
 */
export const detectAnomalousUserAgent = (req, res, next) => {
  const userAgent = req.get('user-agent');

  // Suspicious patterns
  const suspiciousPatterns = [
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /masscan/i,
    /nessus/i,
    /openvas/i,
    /metasploit/i,
    /burp/i,
    /acunetix/i,
    /havij/i
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(userAgent)) {
      logger.warn('Suspicious User-Agent detected', {
        userAgent,
        ip: req.ip,
        path: req.path
      });

      if (!securityMode.isVulnerable) {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: 'SUSPICIOUS_REQUEST',
          message: 'Request blocked'
        });
      }

      break;
    }
  }

  next();
};

/**
 * Get attack statistics for IP
 */
export const getIPAttackStats = async (ip) => {
  try {
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total_attacks,
        COUNT(DISTINCT attack_type) as unique_attack_types,
        MAX(created_at) as last_attack,
        SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
       FROM attack_logs
       WHERE ip_address = ?
       AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
      [ip]
    );

    return stats[0] || {
      total_attacks: 0,
      unique_attack_types: 0,
      last_attack: null,
      blocked_count: 0
    };
  } catch (error) {
    logger.error('Failed to get IP stats:', error);
    return null;
  }
};

/**
 * Clear attack counter for IP
 */
export const clearAttackCounter = async (ip) => {
  const key = CacheKeyBuilder.custom('attack_count:', ip);
  await cache.delete(key);
};

/**
 * Unblock IP
 */
export const unblockIP = async (ip) => {
  try {
    // Remove from cache
    const key = CacheKeyBuilder.custom('ip_blocked:', ip);
    await cache.delete(key);

    // Remove from database
    await db.execute(
      'DELETE FROM ip_blacklist WHERE ip_address = ?',
      [ip]
    );

    logger.info(`IP unblocked: ${ip}`);
    return true;
  } catch (error) {
    logger.error('Failed to unblock IP:', error);
    return false;
  }
};

export default {
  attackDetectionMiddleware,
  checkIPBlacklist,
  honeypotDetection,
  detectRateLimitAbuse,
  detectAnomalousUserAgent,
  getIPAttackStats,
  clearAttackCounter,
  unblockIP
};
