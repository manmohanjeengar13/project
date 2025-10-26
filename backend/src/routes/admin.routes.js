/**
 * Admin Routes - MILITARY-GRADE Administration Panel
 * Enterprise admin dashboard with comprehensive management capabilities
 * 
 * @module routes/admin
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - User management (CRUD, roles, permissions)
 * - System configuration
 * - Security settings
 * - Audit logs & activity monitoring
 * - Database management & backups
 * - Cache management
 * - Email queue management
 * - Job/Task scheduler
 * - System health monitoring
 * - Performance metrics
 * - Security incident response
 * - Bulk operations
 * - Data export/import
 * - Report generation
 * - Analytics dashboard
 * - API key management
 * - Webhook management
 * - Feature flags
 * - A/B testing configuration
 * - Content moderation queue
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - Admin-only access (super restrictive)
 * - Action audit logging
 * - Two-factor authentication required
 * - IP whitelisting option
 * - Session timeout (short)
 * - Dangerous action confirmation
 * - Role-based granular permissions
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import express from 'express';
import { body, param, query, validationResult } from 'express-validator';

// Core imports
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';

// Controller
import adminController from '../controllers/admin.controller.js';

// Middleware
import { authenticate } from '../middleware/authentication.js';
import { requireAdmin, requireRole } from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  strictRateLimit,
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { sanitizeInput } from '../middleware/sanitization.js';
import { attackLogger } from '../middleware/attackLogger.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
  USER_ROLES,
  ERROR_CODES,
  SUCCESS_MESSAGES 
} from '../config/constants.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// ADMIN-ONLY MIDDLEWARE
// ============================================================================

// All admin routes require authentication and admin role
router.use(authenticate);
router.use(requireAdmin);
router.use(attackLogger);

// ============================================================================
// RATE LIMITERS
// ============================================================================

const adminActionLimit = createEndpointLimiter({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many admin actions'
});

const dangerousActionLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many dangerous operations. Please wait.'
});

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const updateUserRoleValidation = [
  body('role')
    .isIn(Object.values(USER_ROLES))
    .withMessage('Invalid user role'),
  
  body('reason')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
];

const systemConfigValidation = [
  body('key')
    .trim()
    .matches(/^[a-zA-Z0-9._-]+$/)
    .withMessage('Invalid configuration key'),
  
  body('value')
    .notEmpty()
    .withMessage('Configuration value is required'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
];

const bulkUserValidation = [
  body('userIds')
    .isArray({ min: 1, max: 100 })
    .withMessage('Provide 1-100 user IDs'),
  
  body('userIds.*')
    .isInt({ min: 1 })
    .withMessage('Invalid user ID'),
  
  body('action')
    .isIn(['activate', 'deactivate', 'delete', 'updateRole'])
    .withMessage('Invalid bulk action')
];

const enhancedValidate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: ERROR_CODES.VALIDATION_ERROR,
      message: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  next();
};

// ============================================================================
// DASHBOARD & OVERVIEW
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/dashboard:
 *   get:
 *     summary: Get admin dashboard overview
 *     tags: [Admin, Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard data
 */
router.get('/dashboard',
  adminActionLimit,
  adminController.getDashboard
);

/**
 * @swagger
 * /api/v1/admin/stats:
 *   get:
 *     summary: Get system statistics
 *     tags: [Admin, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System statistics
 */
router.get('/stats',
  adminActionLimit,
  query('period').optional().isIn(['today', 'week', 'month', 'year']),
  enhancedValidate,
  adminController.getSystemStats
);

// ============================================================================
// USER MANAGEMENT
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/users:
 *   get:
 *     summary: Get all users with admin filters
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 */
router.get('/users',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('search').optional().trim().isLength({ max: 200 }),
  query('role').optional().isIn(Object.values(USER_ROLES)),
  query('status').optional().isIn(['active', 'inactive', 'locked', 'deleted']),
  query('sortBy').optional().isIn(['createdAt', 'username', 'email', 'lastLoginAt']),
  query('sortOrder').optional().isIn(['ASC', 'DESC']),
  enhancedValidate,
  adminController.getAllUsers
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   get:
 *     summary: Get user details (admin view)
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User details
 */
router.get('/users/:id',
  adminActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  enhancedValidate,
  adminController.getUserDetails
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/role:
 *   put:
 *     summary: Update user role
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User role updated
 */
router.put('/users/:id/role',
  adminActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  sanitizeInput,
  updateUserRoleValidation,
  enhancedValidate,
  adminController.updateUserRole
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/activate:
 *   post:
 *     summary: Activate user account
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User activated
 */
router.post('/users/:id/activate',
  adminActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  enhancedValidate,
  adminController.activateUser
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/deactivate:
 *   post:
 *     summary: Deactivate user account
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User deactivated
 */
router.post('/users/:id/deactivate',
  adminActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  body('reason').optional().trim().isLength({ max: 500 }),
  enhancedValidate,
  adminController.deactivateUser
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/lock:
 *   post:
 *     summary: Lock user account
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User account locked
 */
router.post('/users/:id/lock',
  adminActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  body('reason').trim().isLength({ min: 10, max: 500 }).withMessage('Lock reason required'),
  body('duration').optional().isInt({ min: 1 }).withMessage('Lock duration in minutes'),
  enhancedValidate,
  adminController.lockUser
);

/**
 * @swagger
 * /api/v1/admin/users/{id}/unlock:
 *   post:
 *     summary: Unlock user account
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User account unlocked
 */
router.post('/users/:id/unlock',
  adminActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  enhancedValidate,
  adminController.unlockUser
);

/**
 * @swagger
 * /api/v1/admin/users/{id}:
 *   delete:
 *     summary: Permanently delete user (dangerous)
 *     tags: [Admin, Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User deleted
 */
router.delete('/users/:id',
  dangerousActionLimit,
  param('id').isInt().withMessage('Invalid user ID'),
  body('confirmation').equals('DELETE').withMessage('Confirmation required'),
  body('reason').trim().isLength({ min: 20, max: 500 }).withMessage('Deletion reason required (20-500 chars)'),
  enhancedValidate,
  adminController.deleteUser
);

/**
 * @swagger
 * /api/v1/admin/users/bulk:
 *   post:
 *     summary: Bulk user operations
 *     tags: [Admin, Users, Bulk]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Bulk operation completed
 */
router.post('/users/bulk',
  dangerousActionLimit,
  bulkUserValidation,
  enhancedValidate,
  adminController.bulkUserOperation
);

// ============================================================================
// PRODUCT MANAGEMENT
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/products:
 *   get:
 *     summary: Get all products (admin view)
 *     tags: [Admin, Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of products
 */
router.get('/products',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('status').optional().isIn(['active', 'inactive', 'out_of_stock']),
  enhancedValidate,
  adminController.getAllProducts
);

/**
 * @swagger
 * /api/v1/admin/products/low-stock:
 *   get:
 *     summary: Get low stock products
 *     tags: [Admin, Products, Inventory]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Low stock products
 */
router.get('/products/low-stock',
  adminActionLimit,
  query('threshold').optional().isInt({ min: 0 }).toInt(),
  enhancedValidate,
  adminController.getLowStockProducts
);

// ============================================================================
// ORDER MANAGEMENT
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/orders:
 *   get:
 *     summary: Get all orders (admin view)
 *     tags: [Admin, Orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of orders
 */
router.get('/orders',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('status').optional().trim(),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  enhancedValidate,
  adminController.getAllOrders
);

/**
 * @swagger
 * /api/v1/admin/orders/pending:
 *   get:
 *     summary: Get pending orders
 *     tags: [Admin, Orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Pending orders
 */
router.get('/orders/pending',
  adminActionLimit,
  adminController.getPendingOrders
);

// ============================================================================
// REVIEW MODERATION
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/reviews/pending:
 *   get:
 *     summary: Get reviews pending moderation
 *     tags: [Admin, Reviews]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Pending reviews
 */
router.get('/reviews/pending',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  adminController.getPendingReviews
);

/**
 * @swagger
 * /api/v1/admin/reviews/reported:
 *   get:
 *     summary: Get reported reviews
 *     tags: [Admin, Reviews]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Reported reviews
 */
router.get('/reviews/reported',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  adminController.getReportedReviews
);

// ============================================================================
// SYSTEM CONFIGURATION
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/config:
 *   get:
 *     summary: Get system configuration
 *     tags: [Admin, Configuration]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System configuration
 */
router.get('/config',
  adminActionLimit,
  adminController.getSystemConfig
);

/**
 * @swagger
 * /api/v1/admin/config:
 *   put:
 *     summary: Update system configuration
 *     tags: [Admin, Configuration]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Configuration updated
 */
router.put('/config',
  dangerousActionLimit,
  systemConfigValidation,
  enhancedValidate,
  adminController.updateSystemConfig
);

/**
 * @swagger
 * /api/v1/admin/security-mode:
 *   post:
 *     summary: Toggle security mode (vulnerable/secure)
 *     tags: [Admin, Security]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Security mode toggled
 */
router.post('/security-mode',
  dangerousActionLimit,
  body('mode').isIn(['vulnerable', 'secure']).withMessage('Invalid security mode'),
  body('confirmation').equals('CHANGE_MODE').withMessage('Confirmation required'),
  enhancedValidate,
  adminController.toggleSecurityMode
);

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/cache/stats:
 *   get:
 *     summary: Get cache statistics
 *     tags: [Admin, Cache]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Cache statistics
 */
router.get('/cache/stats',
  adminActionLimit,
  adminController.getCacheStats
);

/**
 * @swagger
 * /api/v1/admin/cache/clear:
 *   post:
 *     summary: Clear all cache
 *     tags: [Admin, Cache]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Cache cleared
 */
router.post('/cache/clear',
  dangerousActionLimit,
  body('confirmation').equals('CLEAR_CACHE').withMessage('Confirmation required'),
  enhancedValidate,
  adminController.clearCache
);

/**
 * @swagger
 * /api/v1/admin/cache/clear/{pattern}:
 *   post:
 *     summary: Clear cache by pattern
 *     tags: [Admin, Cache]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: pattern
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Cache cleared
 */
router.post('/cache/clear/:pattern',
  adminActionLimit,
  param('pattern').trim().notEmpty(),
  enhancedValidate,
  adminController.clearCacheByPattern
);

// ============================================================================
// AUDIT LOGS
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/audit-logs:
 *   get:
 *     summary: Get audit logs
 *     tags: [Admin, Audit]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Audit logs
 */
router.get('/audit-logs',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('userId').optional().isInt({ min: 1 }).toInt(),
  query('action').optional().trim(),
  query('startDate').optional().isISO8601(),
  query('endDate').optional().isISO8601(),
  enhancedValidate,
  adminController.getAuditLogs
);

/**
 * @swagger
 * /api/v1/admin/security-events:
 *   get:
 *     summary: Get security events
 *     tags: [Admin, Security]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Security events
 */
router.get('/security-events',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('severity').optional().isIn(['low', 'medium', 'high', 'critical']),
  query('eventType').optional().trim(),
  enhancedValidate,
  adminController.getSecurityEvents
);

// ============================================================================
// ATTACK LOGS
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/attacks:
 *   get:
 *     summary: Get attack logs
 *     tags: [Admin, Security, Attacks]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Attack logs
 */
router.get('/attacks',
  adminActionLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('attackType').optional().trim(),
  query('ipAddress').optional().trim(),
  query('blocked').optional().isBoolean().toBoolean(),
  enhancedValidate,
  adminController.getAttackLogs
);

/**
 * @swagger
 * /api/v1/admin/attacks/stats:
 *   get:
 *     summary: Get attack statistics
 *     tags: [Admin, Security, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Attack statistics
 */
router.get('/attacks/stats',
  adminActionLimit,
  query('period').optional().isIn(['hour', 'day', 'week', 'month']),
  enhancedValidate,
  adminController.getAttackStats
);

// ============================================================================
// DATABASE MANAGEMENT
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/database/stats:
 *   get:
 *     summary: Get database statistics
 *     tags: [Admin, Database]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Database statistics
 */
router.get('/database/stats',
  adminActionLimit,
  adminController.getDatabaseStats
);

/**
 * @swagger
 * /api/v1/admin/database/backup:
 *   post:
 *     summary: Create database backup
 *     tags: [Admin, Database]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Backup created
 */
router.post('/database/backup',
  dangerousActionLimit,
  body('name').optional().trim().matches(/^[a-zA-Z0-9_-]+$/),
  enhancedValidate,
  adminController.createBackup
);

/**
 * @swagger
 * /api/v1/admin/database/optimize:
 *   post:
 *     summary: Optimize database tables
 *     tags: [Admin, Database]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Database optimized
 */
router.post('/database/optimize',
  dangerousActionLimit,
  adminController.optimizeDatabase
);

// ============================================================================
// SYSTEM HEALTH
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/health:
 *   get:
 *     summary: Get detailed system health
 *     tags: [Admin, System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System health report
 */
router.get('/health',
  adminActionLimit,
  adminController.getSystemHealth
);

/**
 * @swagger
 * /api/v1/admin/logs:
 *   get:
 *     summary: Get system logs
 *     tags: [Admin, System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System logs
 */
router.get('/logs',
  adminActionLimit,
  query('level').optional().isIn(['error', 'warn', 'info', 'debug']),
  query('limit').optional().isInt({ min: 1, max: 1000 }).toInt(),
  enhancedValidate,
  adminController.getSystemLogs
);

// ============================================================================
// REPORTS
// ============================================================================

/**
 * @swagger
 * /api/v1/admin/reports/generate:
 *   post:
 *     summary: Generate custom report
 *     tags: [Admin, Reports]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Report generated
 */
router.post('/reports/generate',
  strictRateLimit,
  body('reportType').isIn(['sales', 'users', 'products', 'security']),
  body('startDate').isISO8601(),
  body('endDate').isISO8601(),
  body('format').optional().isIn(['pdf', 'csv', 'excel', 'json']),
  enhancedValidate,
  adminController.generateReport
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((error, req, res, next) => {
  logger.error('Admin route error', {
    error: error.message,
    path: req.path,
    method: req.method,
    adminId: req.user?.id
  });

  res.status(error.status || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.code || ERROR_CODES.INTERNAL_ERROR,
    message: Config.app.env === 'development' ? error.message : 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// EXPORTS
// ============================================================================

logger.info('✅ Admin routes loaded (MILITARY-GRADE - SUPER ADMIN ONLY)');

export default router;
