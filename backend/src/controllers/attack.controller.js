/**
 * Attack Controller
 * Handles attack detection logs and security monitoring
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache } from '../core/Cache.js';
import { 
  HTTP_STATUS, 
  PAGINATION,
  ATTACK_TYPES,
  ATTACK_SEVERITY 
} from '../config/constants.js';
import { NotFoundError } from '../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get attack logs with filtering
 */
export const getAttackLogs = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      attackType = '',
      severity = '',
      ipAddress = '',
      blocked = '',
      startDate = '',
      endDate = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = [];
    const values = [];

    if (attackType) {
      conditions.push('attack_type = ?');
      values.push(attackType);
    }

    if (severity) {
      conditions.push('severity = ?');
      values.push(severity);
    }

    if (ipAddress) {
      conditions.push('ip_address = ?');
      values.push(ipAddress);
    }

    if (blocked !== '') {
      conditions.push('blocked = ?');
      values.push(blocked === 'true' ? 1 : 0);
    }

    if (startDate) {
      conditions.push('created_at >= ?');
      values.push(startDate);
    }

    if (endDate) {
      conditions.push('created_at <= ?');
      values.push(endDate);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM attack_logs ${whereClause}`,
      values
    );

    // Get logs
    const [logs] = await db.execute(
      `SELECT * FROM attack_logs 
       ${whereClause} 
       ORDER BY created_at DESC 
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: logs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get attack log by ID
 */
export const getAttackById = async (req, res, next) => {
  try {
    const attackId = req.params.id;

    const [attacks] = await db.execute(
      'SELECT * FROM attack_logs WHERE id = ? LIMIT 1',
      [attackId]
    );

    if (attacks.length === 0) {
      throw new NotFoundError('Attack log');
    }

    // Get related attacks from same IP
    const [related] = await db.execute(
      `SELECT * FROM attack_logs 
       WHERE ip_address = ? AND id != ? 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [attacks[0].ip_address, attackId]
    );

    res.json({
      success: true,
      data: {
        attack: attacks[0],
        relatedAttacks: related
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get attack statistics
 */
export const getAttackStatistics = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;
    else if (period === '365d') daysBack = 365;

    const cacheKey = `attack_stats:${period}`;
    let stats = await cache.get(cacheKey);

    if (!stats) {
      // Overall statistics
      const [overview] = await db.execute(
        `SELECT 
          COUNT(*) as total_attacks,
          COUNT(DISTINCT ip_address) as unique_ips,
          COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked_count,
          COUNT(CASE WHEN severity = ? THEN 1 END) as critical_attacks,
          COUNT(CASE WHEN severity = ? THEN 1 END) as high_attacks,
          COUNT(CASE WHEN severity = ? THEN 1 END) as medium_attacks,
          COUNT(CASE WHEN severity = ? THEN 1 END) as low_attacks
         FROM attack_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [
          ATTACK_SEVERITY.CRITICAL,
          ATTACK_SEVERITY.HIGH,
          ATTACK_SEVERITY.MEDIUM,
          ATTACK_SEVERITY.LOW,
          daysBack
        ]
      );

      // Attacks by type
      const [byType] = await db.execute(
        `SELECT attack_type, COUNT(*) as count, 
                COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked
         FROM attack_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY attack_type
         ORDER BY count DESC`,
        [daysBack]
      );

      // Daily attack trends
      const [daily] = await db.execute(
        `SELECT DATE(created_at) as date, 
                COUNT(*) as count,
                COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked,
                COUNT(DISTINCT ip_address) as unique_ips
         FROM attack_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY DATE(created_at)
         ORDER BY date ASC`,
        [daysBack]
      );

      // Top attacking IPs
      const [topIPs] = await db.execute(
        `SELECT ip_address, 
                COUNT(*) as attack_count,
                COUNT(DISTINCT attack_type) as attack_types,
                MAX(created_at) as last_attack
         FROM attack_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY ip_address
         ORDER BY attack_count DESC
         LIMIT 10`,
        [daysBack]
      );

      // Most targeted endpoints
      const [topEndpoints] = await db.execute(
        `SELECT endpoint, 
                COUNT(*) as attack_count,
                COUNT(DISTINCT attack_type) as attack_types
         FROM attack_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND endpoint IS NOT NULL
         GROUP BY endpoint
         ORDER BY attack_count DESC
         LIMIT 10`,
        [daysBack]
      );

      // Attacks by hour (for pattern detection)
      const [byHour] = await db.execute(
        `SELECT HOUR(created_at) as hour, COUNT(*) as count
         FROM attack_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY HOUR(created_at)
         ORDER BY hour ASC`,
        [daysBack]
      );

      stats = {
        overview: overview[0],
        byType,
        daily,
        topIPs,
        topEndpoints,
        byHour,
        period
      };

      // Cache for 5 minutes
      await cache.set(cacheKey, stats, 300);
    }

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get blocked IPs
 */
export const getBlockedIPs = async (req, res, next) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM ip_blacklist 
       WHERE is_permanent = TRUE OR blocked_until > NOW()`
    );

    // Get blocked IPs
    const [blocked] = await db.execute(
      `SELECT * FROM ip_blacklist 
       WHERE is_permanent = TRUE OR blocked_until > NOW()
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: blocked,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Block IP address
 */
export const blockIP = async (req, res, next) => {
  try {
    const { ipAddress, reason, duration = 24, isPermanent = false } = req.body;

    const blockedUntil = isPermanent 
      ? null 
      : new Date(Date.now() + duration * 60 * 60 * 1000);

    await db.execute(
      `INSERT INTO ip_blacklist (
        ip_address, reason, blocked_until, is_permanent, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE 
         reason = VALUES(reason), 
         blocked_until = VALUES(blocked_until),
         is_permanent = VALUES(is_permanent),
         updated_at = NOW()`,
      [ipAddress, reason, blockedUntil, isPermanent ? 1 : 0, req.user.id]
    );

    // Update cache
    const { blockIP: cacheBlock } = await import('../middleware/attackDetection.js');
    await cacheBlock(ipAddress, duration * 60 * 60 * 1000);

    logger.info('IP manually blocked', { 
      ipAddress, 
      reason, 
      duration: isPermanent ? 'permanent' : `${duration}h`,
      adminId: req.user.id 
    });

    res.json({
      success: true,
      message: 'IP address blocked successfully',
      data: {
        ipAddress,
        blockedUntil: isPermanent ? 'permanent' : blockedUntil
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Unblock IP address
 */
export const unblockIP = async (req, res, next) => {
  try {
    const { ipAddress } = req.body;

    await db.execute(
      'DELETE FROM ip_blacklist WHERE ip_address = ?',
      [ipAddress]
    );

    // Clear from cache
    const { unblockIP: cacheUnblock } = await import('../middleware/attackDetection.js');
    await cacheUnblock(ipAddress);

    logger.info('IP unblocked', { ipAddress, adminId: req.user.id });

    res.json({
      success: true,
      message: 'IP address unblocked successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Clear old attack logs
 */
export const clearAttackLogs = async (req, res, next) => {
  try {
    const { olderThan = 90 } = req.body; // days

    const [result] = await db.execute(
      'DELETE FROM attack_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
      [parseInt(olderThan)]
    );

    logger.info('Attack logs cleared', { 
      deleted: result.affectedRows, 
      olderThan: `${olderThan} days`,
      adminId: req.user.id 
    });

    res.json({
      success: true,
      message: `${result.affectedRows} attack logs deleted`
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Export attack logs
 */
export const exportAttackLogs = async (req, res, next) => {
  try {
    const { 
      format = 'json', 
      attackType = '', 
      severity = '',
      startDate = '',
      endDate = '',
      limit = 5000 
    } = req.query;

    const conditions = [];
    const values = [];

    if (attackType) {
      conditions.push('attack_type = ?');
      values.push(attackType);
    }

    if (severity) {
      conditions.push('severity = ?');
      values.push(severity);
    }

    if (startDate) {
      conditions.push('created_at >= ?');
      values.push(startDate);
    }

    if (endDate) {
      conditions.push('created_at <= ?');
      values.push(endDate);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [logs] = await db.execute(
      `SELECT * FROM attack_logs 
       ${whereClause} 
       ORDER BY created_at DESC 
       LIMIT ?`,
      [...values, parseInt(limit)]
    );

    if (format === 'csv') {
      const csv = [
        ['ID', 'Type', 'Severity', 'IP Address', 'Endpoint', 'Method', 'Payload', 'Blocked', 'Timestamp'].join(','),
        ...logs.map(log => [
          log.id,
          log.attack_type,
          log.severity,
          log.ip_address,
          log.endpoint || '',
          log.method || '',
          log.payload ? `"${log.payload.replace(/"/g, '""')}"` : '',
          log.blocked ? 'Yes' : 'No',
          log.created_at
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=attack_logs.csv');
      return res.send(csv);
    }

    res.json({
      success: true,
      data: logs,
      count: logs.length,
      exportedAt: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get attack patterns and insights
 */
export const getAttackPatterns = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;
    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    // Repeated attack patterns from same IP
    const [repeatedAttacks] = await db.execute(
      `SELECT ip_address, attack_type, COUNT(*) as attempt_count,
              MIN(created_at) as first_attempt,
              MAX(created_at) as last_attempt
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY ip_address, attack_type
       HAVING COUNT(*) > 5
       ORDER BY attempt_count DESC
       LIMIT 20`,
      [daysBack]
    );

    // Attack chains (IPs attacking multiple endpoints)
    const [attackChains] = await db.execute(
      `SELECT ip_address, 
              COUNT(DISTINCT endpoint) as endpoints_targeted,
              COUNT(*) as total_attacks,
              GROUP_CONCAT(DISTINCT attack_type) as attack_types
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY ip_address
       HAVING COUNT(DISTINCT endpoint) > 3
       ORDER BY endpoints_targeted DESC
       LIMIT 20`,
      [daysBack]
    );

    // Time-based patterns (attacks at specific times)
    const [timePatterns] = await db.execute(
      `SELECT 
        HOUR(created_at) as hour,
        DAYOFWEEK(created_at) as day_of_week,
        COUNT(*) as attack_count
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY HOUR(created_at), DAYOFWEEK(created_at)
       HAVING COUNT(*) > 10
       ORDER BY attack_count DESC
       LIMIT 20`,
      [daysBack]
    );

    // Escalating attacks (IPs increasing attack frequency)
    const [escalating] = await db.execute(
      `SELECT ip_address,
              COUNT(*) as total_attacks,
              COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) as recent_attacks,
              (COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) / COUNT(*) * 100) as recent_percentage
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY ip_address
       HAVING recent_percentage > 50 AND total_attacks > 10
       ORDER BY recent_attacks DESC
       LIMIT 20`,
      [daysBack]
    );

    res.json({
      success: true,
      data: {
        repeatedAttacks,
        attackChains,
        timePatterns,
        escalating,
        period
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get geographic distribution of attacks (if GeoIP is available)
 */
export const getAttackGeography = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;
    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    // This would use GeoIP data if available
    // For now, return IP-based statistics
    const [byCountry] = await db.execute(
      `SELECT 
        SUBSTRING_INDEX(ip_address, '.', 2) as ip_range,
        COUNT(*) as attack_count,
        COUNT(DISTINCT ip_address) as unique_ips
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY ip_range
       ORDER BY attack_count DESC
       LIMIT 20`,
      [daysBack]
    );

    res.json({
      success: true,
      data: {
        byIPRange: byCountry,
        note: 'Geographic data requires GeoIP integration',
        period
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get attack prevention effectiveness
 */
export const getPreventionEffectiveness = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;
    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    // Block rate by attack type
    const [blockRates] = await db.execute(
      `SELECT attack_type,
              COUNT(*) as total_attempts,
              COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked,
              (COUNT(CASE WHEN blocked = TRUE THEN 1 END) / COUNT(*) * 100) as block_rate
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY attack_type
       ORDER BY total_attempts DESC`,
      [daysBack]
    );

    // Detection time analysis
    const [detectionStats] = await db.execute(
      `SELECT 
        attack_type,
        COUNT(*) as detected,
        AVG(CASE WHEN blocked = TRUE THEN 1 ELSE 0 END) as avg_block_rate
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY attack_type`,
      [daysBack]
    );

    // Overall effectiveness
    const [overall] = await db.execute(
      `SELECT 
        COUNT(*) as total_attacks,
        COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked_attacks,
        (COUNT(CASE WHEN blocked = TRUE THEN 1 END) / COUNT(*) * 100) as overall_block_rate,
        COUNT(DISTINCT ip_address) as unique_attackers,
        COUNT(DISTINCT CASE WHEN blocked = TRUE THEN ip_address END) as blocked_ips
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [daysBack]
    );

    res.json({
      success: true,
      data: {
        blockRates,
        detectionStats,
        overall: overall[0],
        period
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get recent attack activity (real-time)
 */
export const getRecentActivity = async (req, res, next) => {
  try {
    const { minutes = 15, limit = 50 } = req.query;

    const [recent] = await db.execute(
      `SELECT * FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
       ORDER BY created_at DESC
       LIMIT ?`,
      [parseInt(minutes), parseInt(limit)]
    );

    // Quick stats
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked,
        COUNT(DISTINCT ip_address) as unique_ips,
        COUNT(DISTINCT attack_type) as attack_types
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
      [parseInt(minutes)]
    );

    res.json({
      success: true,
      data: {
        attacks: recent,
        summary: stats[0],
        timeWindow: `${minutes} minutes`
      }
    });
  } catch (error) {
    next(error);
  }
};

export default {
  getAttackLogs,
  getAttackById,
  getAttackStatistics,
  getBlockedIPs,
  blockIP,
  unblockIP,
  clearAttackLogs,
  exportAttackLogs,
  getAttackPatterns,
  getAttackGeography,
  getPreventionEffectiveness,
  getRecentActivity
};
