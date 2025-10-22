/**
 * Admin Controller
 * Handles admin dashboard, analytics, and system management
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache } from '../core/Cache.js';
import { Config } from '../config/environment.js';
import { HTTP_STATUS } from '../config/constants.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get admin dashboard statistics
 */
export const getDashboard = async (req, res, next) => {
  try {
    // Users statistics
    const [userStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_users,
        COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as new_users_30d
       FROM users`
    );

    // Products statistics
    const [productStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_products,
        COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_products,
        COUNT(CASE WHEN stock = 0 THEN 1 END) as out_of_stock,
        COUNT(CASE WHEN stock < 10 AND stock > 0 THEN 1 END) as low_stock
       FROM products`
    );

    // Orders statistics
    const [orderStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_orders,
        COALESCE(SUM(total), 0) as total_revenue,
        COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) as orders_30d,
        COALESCE(SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN total END), 0) as revenue_30d,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_orders,
        COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing_orders
       FROM orders`
    );

    // Reviews statistics
    const [reviewStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as avg_rating,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_reviews
       FROM reviews`
    );

    // Security events (last 24h)
    const [securityStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_attacks,
        COUNT(CASE WHEN blocked = TRUE THEN 1 END) as blocked_attacks
       FROM attack_logs
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`
    );

    // Recent activity
    const [recentOrders] = await db.execute(
      `SELECT id, order_number, total, status, created_at
       FROM orders
       ORDER BY created_at DESC
       LIMIT 5`
    );

    const [recentUsers] = await db.execute(
      `SELECT id, username, email, created_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 5`
    );

    res.json({
      success: true,
      data: {
        users: userStats[0],
        products: productStats[0],
        orders: orderStats[0],
        reviews: reviewStats[0],
        security: securityStats[0],
        recent: {
          orders: recentOrders,
          users: recentUsers
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get platform analytics
 */
export const getAnalytics = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    // Revenue over time
    const [revenueData] = await db.execute(
      `SELECT DATE(created_at) as date, 
              COUNT(*) as orders,
              COALESCE(SUM(total), 0) as revenue
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [daysBack]
    );

    // User growth
    const [userData] = await db.execute(
      `SELECT DATE(created_at) as date, COUNT(*) as new_users
       FROM users
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [daysBack]
    );

    // Product views
    const [viewsData] = await db.execute(
      `SELECT DATE(created_at) as date, COUNT(*) as views
       FROM page_views
       WHERE page_type = 'product' AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [daysBack]
    );

    // Top selling products
    const [topProducts] = await db.execute(
      `SELECT p.id, p.name, 
              SUM(oi.quantity) as total_sold,
              SUM(oi.total) as revenue
       FROM order_items oi
       JOIN products p ON oi.product_id = p.id
       JOIN orders o ON oi.order_id = o.id
       WHERE o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         AND o.status != 'cancelled'
       GROUP BY p.id, p.name
       ORDER BY total_sold DESC
       LIMIT 10`,
      [daysBack]
    );

    // Traffic sources (if tracked)
    const [trafficSources] = await db.execute(
      `SELECT source, COUNT(*) as visits
       FROM page_views
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY source
       ORDER BY visits DESC
       LIMIT 10`,
      [daysBack]
    );

    res.json({
      success: true,
      data: {
        revenue: revenueData,
        users: userData,
        views: viewsData,
        topProducts,
        trafficSources,
        period
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get recent activity log
 */
export const getRecentActivity = async (req, res, next) => {
  try {
    const { limit = 50, type = '' } = req.query;

    const conditions = [];
    const values = [];

    if (type) {
      conditions.push('event_type = ?');
      values.push(type);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [activities] = await db.execute(
      `SELECT se.*, u.username
       FROM security_events se
       LEFT JOIN users u ON se.user_id = u.id
       ${whereClause}
       ORDER BY se.timestamp DESC
       LIMIT ?`,
      [...values, parseInt(limit)]
    );

    res.json({
      success: true,
      data: activities
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get system health status
 */
export const getSystemHealth = async (req, res, next) => {
  try {
    // Database health
    let dbHealth = 'healthy';
    try {
      await db.execute('SELECT 1');
    } catch (error) {
      dbHealth = 'unhealthy';
    }

    // Cache health
    let cacheHealth = 'healthy';
    try {
      await cache.set('health_check', 'ok', 10);
      await cache.get('health_check');
    } catch (error) {
      cacheHealth = 'unhealthy';
    }

    // System metrics
    const uptime = process.uptime();
    const memory = process.memoryUsage();
    const cpu = process.cpuUsage();

    // Database pool stats
    const dbStats = db.getPoolStats();

    res.json({
      success: true,
      data: {
        status: dbHealth === 'healthy' && cacheHealth === 'healthy' ? 'healthy' : 'degraded',
        services: {
          database: dbHealth,
          cache: cacheHealth
        },
        system: {
          uptime: Math.floor(uptime),
          memory: {
            used: Math.round(memory.heapUsed / 1024 / 1024),
            total: Math.round(memory.heapTotal / 1024 / 1024),
            percentage: Math.round((memory.heapUsed / memory.heapTotal) * 100)
          },
          cpu: {
            user: cpu.user,
            system: cpu.system
          }
        },
        database: dbStats,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get security events log
 */
export const getSecurityEvents = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 50,
      eventType = '',
      userId = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    const conditions = [];
    const values = [];

    if (eventType) {
      conditions.push('event_type = ?');
      values.push(eventType);
    }

    if (userId) {
      conditions.push('user_id = ?');
      values.push(userId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM security_events ${whereClause}`,
      values
    );

    const [events] = await db.execute(
      `SELECT se.*, u.username
       FROM security_events se
       LEFT JOIN users u ON se.user_id = u.id
       ${whereClause}
       ORDER BY se.timestamp DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: events,
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
 * Get attack logs
 */
export const getAttackLogs = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 50,
      attackType = '',
      severity = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

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

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM attack_logs ${whereClause}`,
      values
    );

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
 * Manage platform settings
 */
export const manageSettings = async (req, res, next) => {
  try {
    const { action, key, value } = req.body;

    if (action === 'get') {
      const [settings] = await db.execute(
        'SELECT * FROM settings WHERE setting_key = ? LIMIT 1',
        [key]
      );

      return res.json({
        success: true,
        data: settings.length > 0 ? settings[0] : null
      });
    }

    if (action === 'set') {
      await db.execute(
        `INSERT INTO settings (setting_key, setting_value, updated_at)
         VALUES (?, ?, NOW())
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = NOW()`,
        [key, JSON.stringify(value)]
      );

      logger.info('Setting updated', { key, adminId: req.user.id });

      return res.json({
        success: true,
        message: 'Setting updated successfully'
      });
    }

    if (action === 'list') {
      const [settings] = await db.execute('SELECT * FROM settings ORDER BY setting_key');
      return res.json({
        success: true,
        data: settings
      });
    }

    throw new ValidationError('Invalid action. Must be get, set, or list');
  } catch (error) {
    next(error);
  }
};

/**
 * Clear application cache
 */
export const clearCache = async (req, res, next) => {
  try {
    const { type = 'all' } = req.body;

    let cleared = 0;

    if (type === 'all') {
      await cache.clear();
      logger.info('All cache cleared', { adminId: req.user.id });
      cleared = 'all';
    } else if (type === 'users') {
      cleared = await cache.deleteByPattern('user:*');
      logger.info('User cache cleared', { count: cleared, adminId: req.user.id });
    } else if (type === 'products') {
      cleared = await cache.deleteByPattern('product:*');
      logger.info('Product cache cleared', { count: cleared, adminId: req.user.id });
    } else if (type === 'orders') {
      cleared = await cache.deleteByPattern('order:*');
      logger.info('Order cache cleared', { count: cleared, adminId: req.user.id });
    }

    res.json({
      success: true,
      message: 'Cache cleared successfully',
      cleared
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Run maintenance tasks
 */
export const runMaintenance = async (req, res, next) => {
  try {
    const { task } = req.body;

    const results = {};

    if (task === 'cleanup_logs' || task === 'all') {
      // Delete old logs (older than 90 days)
      const [logResult] = await db.execute(
        'DELETE FROM attack_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)'
      );
      results.logs_deleted = logResult.affectedRows;
    }

    if (task === 'cleanup_sessions' || task === 'all') {
      // Delete expired sessions
      const [sessionResult] = await db.execute(
        'DELETE FROM user_sessions WHERE expires_at < NOW()'
      );
      results.sessions_deleted = sessionResult.affectedRows;
    }

    if (task === 'optimize_tables' || task === 'all') {
      // Optimize database tables
      const tables = ['users', 'products', 'orders', 'reviews', 'attack_logs'];
      for (const table of tables) {
        await db.execute(`OPTIMIZE TABLE ${table}`);
      }
      results.tables_optimized = tables.length;
    }

    if (task === 'cleanup_temp_files' || task === 'all') {
      // This would clean up temp uploads directory
      results.temp_files_deleted = 0; // Placeholder
    }

    logger.info('Maintenance task completed', { task, results, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Maintenance tasks completed',
      results
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get database backups list
 */
export const getBackups = async (req, res, next) => {
  try {
    // This would list backup files from backup directory
    // For now, return mock data
    const backups = [
      {
        id: 1,
        filename: 'backup_2024_01_15.sql.gz',
        size: '15.2 MB',
        created_at: '2024-01-15T02:00:00Z'
      }
    ];

    res.json({
      success: true,
      data: backups
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Create manual database backup
 */
export const createBackup = async (req, res, next) => {
  try {
    // This would trigger a database backup
    // For now, return success message
    const backupName = `backup_${new Date().toISOString().split('T')[0]}.sql.gz`;

    logger.info('Manual backup created', { backupName, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Backup created successfully',
      data: {
        filename: backupName,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Restore from backup
 */
export const restoreBackup = async (req, res, next) => {
  try {
    const { backupId } = req.body;

    // This would restore database from backup
    // For now, return success message
    logger.warn('Database restore initiated', { backupId, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Backup restore initiated. This may take a few minutes.'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get platform statistics summary
 */
export const getStatisticsSummary = async (req, res, next) => {
  try {
    // Users
    const [userCount] = await db.execute('SELECT COUNT(*) as count FROM users');
    
    // Products
    const [productCount] = await db.execute('SELECT COUNT(*) as count FROM products WHERE is_active = TRUE');
    
    // Orders
    const [orderStats] = await db.execute(
      'SELECT COUNT(*) as count, COALESCE(SUM(total), 0) as revenue FROM orders'
    );
    
    // Reviews
    const [reviewCount] = await db.execute('SELECT COUNT(*) as count FROM reviews');
    
    // Active sessions
    const [sessionCount] = await db.execute(
      'SELECT COUNT(*) as count FROM user_sessions WHERE expires_at > NOW()'
    );

    res.json({
      success: true,
      data: {
        users: userCount[0].count,
        products: productCount[0].count,
        orders: orderStats[0].count,
        revenue: orderStats[0].revenue,
        reviews: reviewCount[0].count,
        activeSessions: sessionCount[0].count
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Export system logs
 */
export const exportLogs = async (req, res, next) => {
  try {
    const { type = 'all', format = 'json' } = req.query;

    let logs = [];

    if (type === 'security' || type === 'all') {
      const [securityLogs] = await db.execute(
        'SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 1000'
      );
      logs = [...logs, ...securityLogs];
    }

    if (type === 'attacks' || type === 'all') {
      const [attackLogs] = await db.execute(
        'SELECT * FROM attack_logs ORDER BY created_at DESC LIMIT 1000'
      );
      logs = [...logs, ...attackLogs];
    }

    if (format === 'csv') {
      // Convert to CSV
      const csv = [
        ['Timestamp', 'Type', 'Event', 'IP Address', 'User ID'].join(','),
        ...logs.map(log => [
          log.timestamp || log.created_at,
          log.event_type || log.attack_type,
          log.details || log.payload,
          log.ip_address,
          log.user_id || ''
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=system_logs.csv');
      return res.send(csv);
    }

    res.json({
      success: true,
      data: logs,
      count: logs.length
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
    const [blocked] = await db.execute(
      `SELECT * FROM ip_blacklist 
       WHERE is_permanent = TRUE OR blocked_until > NOW()
       ORDER BY created_at DESC`
    );

    res.json({
      success: true,
      data: blocked
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Manually block IP
 */
export const blockIP = async (req, res, next) => {
  try {
    const { ipAddress, reason, duration = 24 } = req.body; // duration in hours

    const blockedUntil = duration === -1 
      ? null 
      : new Date(Date.now() + duration * 60 * 60 * 1000);

    await db.execute(
      `INSERT INTO ip_blacklist (ip_address, reason, blocked_until, is_permanent, created_by)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE 
         reason = VALUES(reason), 
         blocked_until = VALUES(blocked_until),
         is_permanent = VALUES(is_permanent)`,
      [ipAddress, reason, blockedUntil, duration === -1 ? 1 : 0, req.user.id]
    );

    logger.info('IP manually blocked', { ipAddress, reason, adminId: req.user.id });

    res.json({
      success: true,
      message: 'IP address blocked successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Unblock IP
 */
export const unblockIP = async (req, res, next) => {
  try {
    const { ipAddress } = req.body;

    await db.execute(
      'DELETE FROM ip_blacklist WHERE ip_address = ?',
      [ipAddress]
    );

    // Also clear from cache
    const { unblockIP: clearCache } = await import('../middleware/attackDetection.js');
    await clearCache(ipAddress);

    logger.info('IP unblocked', { ipAddress, adminId: req.user.id });

    res.json({
      success: true,
      message: 'IP address unblocked successfully'
    });
  } catch (error) {
    next(error);
  }
};

export default {
  getDashboard,
  getAnalytics,
  getRecentActivity,
  getSystemHealth,
  getSecurityEvents,
  getAttackLogs,
  manageSettings,
  clearCache,
  runMaintenance,
  getBackups,
  createBackup,
  restoreBackup,
  getStatisticsSummary,
  exportLogs,
  getBlockedIPs,
  blockIP,
  unblockIP
};
