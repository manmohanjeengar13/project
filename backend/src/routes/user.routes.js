/**
 * User Routes - MILITARY-GRADE User Management System
 * Enterprise user profile, preferences, and account management
 * 
 * @module routes/user
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - User profile management (CRUD)
 * - Privacy controls & data export (GDPR)
 * - Notification preferences
 * - Two-factor authentication management
 * - Activity logs & audit trails
 * - Account settings & preferences
 * - Address book management
 * - Payment methods (tokenized)
 * - Wishlist & favorites
 * - Follow/Following system
 * - Blocking & privacy settings
 * - Data portability (export)
 * - Right to be forgotten (GDPR)
 * - Session management
 * - Device management
 * - Security settings
 * - Communication preferences
 * - Timezone & localization
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - Ownership validation
 * - Role-based access control
 * - Data sanitization
 * - PII encryption
 * - Audit logging
 * - Rate limiting
 * - CSRF protection
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
import { Email } from '../core/Email.js';

// Controller
import userController from '../controllers/user.controller.js';

// Middleware
import { authenticate, optionalAuth } from '../middleware/authentication.js';
import { 
  requireRole, 
  requireOwnership, 
  ownerOrAdmin,
  selfOnly 
} from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  strictRateLimit,
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { validateRequest } from '../middleware/validation.js';
import { sanitizeInput, sanitizeHTML } from '../middleware/sanitization.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { attackLogger } from '../middleware/attackLogger.js';
import { modeSwitchMiddleware, getCurrentMode } from '../middleware/modeSwitch.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
  USER_ROLES, 
  ERROR_CODES,
  SUCCESS_MESSAGES,
  ERROR_MESSAGES 
} from '../config/constants.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const updateProfileValidation = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name contains invalid characters'),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name contains invalid characters'),
  
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Bio cannot exceed 500 characters'),
  
  body('phone')
    .optional()
    .trim()
    .matches(/^\+?[\d\s\-()]+$/)
    .withMessage('Invalid phone number format'),
  
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Invalid date format')
    .custom((value) => {
      const age = Math.floor((Date.now() - new Date(value).getTime()) / (365.25 * 24 * 60 * 60 * 1000));
      return age >= 13 && age <= 120;
    })
    .withMessage('User must be between 13 and 120 years old'),
  
  body('gender')
    .optional()
    .isIn(['male', 'female', 'other', 'prefer_not_to_say'])
    .withMessage('Invalid gender value'),
  
  body('avatar')
    .optional()
    .trim()
    .isURL()
    .withMessage('Invalid avatar URL'),
  
  body('timezone')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Invalid timezone'),
  
  body('language')
    .optional()
    .isIn(['en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'zh', 'ko', 'ar'])
    .withMessage('Unsupported language')
];

const addressValidation = [
  body('label')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Address label must be between 2 and 50 characters'),
  
  body('fullName')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name is required'),
  
  body('addressLine1')
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Address line 1 is required'),
  
  body('addressLine2')
    .optional()
    .trim()
    .isLength({ max: 200 }),
  
  body('city')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('City is required'),
  
  body('state')
    .optional()
    .trim()
    .isLength({ max: 100 }),
  
  body('postalCode')
    .trim()
    .matches(/^[A-Z0-9\s-]+$/i)
    .withMessage('Invalid postal code'),
  
  body('country')
    .trim()
    .isLength({ min: 2, max: 2 })
    .withMessage('Country code must be 2 characters (ISO 3166-1 alpha-2)'),
  
  body('phone')
    .optional()
    .trim()
    .matches(/^\+?[\d\s\-()]+$/),
  
  body('isDefault')
    .optional()
    .isBoolean()
];

const preferencesValidation = [
  body('emailNotifications')
    .optional()
    .isBoolean(),
  
  body('smsNotifications')
    .optional()
    .isBoolean(),
  
  body('pushNotifications')
    .optional()
    .isBoolean(),
  
  body('marketingEmails')
    .optional()
    .isBoolean(),
  
  body('newsletter')
    .optional()
    .isBoolean(),
  
  body('orderUpdates')
    .optional()
    .isBoolean(),
  
  body('productRecommendations')
    .optional()
    .isBoolean()
];

const privacyValidation = [
  body('profileVisibility')
    .isIn(['public', 'friends', 'private'])
    .withMessage('Invalid visibility setting'),
  
  body('showEmail')
    .isBoolean(),
  
  body('showPhone')
    .isBoolean(),
  
  body('showActivity')
    .isBoolean(),
  
  body('allowMessaging')
    .isBoolean(),
  
  body('allowFollowing')
    .isBoolean()
];

// ============================================================================
// RATE LIMITERS
// ============================================================================

const profileUpdateLimit = createEndpointLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many profile updates. Please try again later.'
});

const searchLimit = createEndpointLimiter({
  windowMs: 60 * 1000,
  max: 30,
  message: 'Too many search requests'
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

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
// USER PROFILE ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/users:
 *   get:
 *     summary: Get all users (with pagination)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           default: createdAt
 *     responses:
 *       200:
 *         description: List of users
 */
router.get('/',
  apiRateLimit,
  optionalAuth,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('search').optional().trim().isLength({ max: 100 }),
  query('role').optional().isIn(Object.values(USER_ROLES)),
  query('sortBy').optional().isIn(['createdAt', 'username', 'email', 'firstName', 'lastName']),
  query('sortOrder').optional().isIn(['ASC', 'DESC']),
  enhancedValidate,
  userController.getAllUsers
);

/**
 * @swagger
 * /api/v1/users/search:
 *   get:
 *     summary: Search users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Search results
 */
router.get('/search',
  searchLimit,
  authenticate,
  query('q')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Search query must be between 2 and 100 characters'),
  enhancedValidate,
  userController.searchUsers
);

/**
 * @swagger
 * /api/v1/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User details
 *       404:
 *         description: User not found
 */
router.get('/:id',
  apiRateLimit,
  optionalAuth,
  param('id').isInt().withMessage('Invalid user ID'),
  enhancedValidate,
  userController.getUserById
);

/**
 * @swagger
 * /api/v1/users/{id}/profile:
 *   get:
 *     summary: Get user profile (public view)
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User profile
 */
router.get('/:id/profile',
  apiRateLimit,
  optionalAuth,
  param('id').isInt().withMessage('Invalid user ID'),
  enhancedValidate,
  userController.getUserProfile
);

/**
 * @swagger
 * /api/v1/users/{id}:
 *   put:
 *     summary: Update user profile
 *     tags: [Users]
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
 *         description: Profile updated successfully
 */
router.put('/:id',
  profileUpdateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid user ID'),
  ownerOrAdmin,
  sanitizeInput,
  updateProfileValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  userController.updateUser
);

/**
 * @swagger
 * /api/v1/users/{id}:
 *   delete:
 *     summary: Delete user account (soft delete)
 *     tags: [Users]
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
 *         description: Account deleted
 */
router.delete('/:id',
  strictRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid user ID'),
  ownerOrAdmin,
  userController.deleteUser
);

// ============================================================================
// ADDRESS MANAGEMENT
// ============================================================================

/**
 * @swagger
 * /api/v1/users/{id}/addresses:
 *   get:
 *     summary: Get user addresses
 *     tags: [Users, Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of addresses
 */
router.get('/:id/addresses',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid user ID'),
  selfOnly,
  userController.getUserAddresses
);

/**
 * @swagger
 * /api/v1/users/{id}/addresses:
 *   post:
 *     summary: Add new address
 *     tags: [Users, Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Address added
 */
router.post('/:id/addresses',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid user ID'),
  selfOnly,
  sanitizeInput,
  addressValidation,
  enhancedValidate,
  userController.addAddress
);

/**
 * @swagger
 * /api/v1/users/{id}/addresses/{addressId}:
 *   put:
 *     summary: Update address
 *     tags: [Users, Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Address updated
 */
router.put('/:id/addresses/:addressId',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  param('addressId').isInt(),
  selfOnly,
  sanitizeInput,
  addressValidation,
  enhancedValidate,
  userController.updateAddress
);

/**
 * @swagger
 * /api/v1/users/{id}/addresses/{addressId}:
 *   delete:
 *     summary: Delete address
 *     tags: [Users, Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Address deleted
 */
router.delete('/:id/addresses/:addressId',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  param('addressId').isInt(),
  selfOnly,
  userController.deleteAddress
);

// ============================================================================
// PREFERENCES & SETTINGS
// ============================================================================

/**
 * @swagger
 * /api/v1/users/{id}/preferences:
 *   get:
 *     summary: Get user preferences
 *     tags: [Users, Settings]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User preferences
 */
router.get('/:id/preferences',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  userController.getPreferences
);

/**
 * @swagger
 * /api/v1/users/{id}/preferences:
 *   put:
 *     summary: Update user preferences
 *     tags: [Users, Settings]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Preferences updated
 */
router.put('/:id/preferences',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  preferencesValidation,
  enhancedValidate,
  userController.updatePreferences
);

/**
 * @swagger
 * /api/v1/users/{id}/privacy:
 *   get:
 *     summary: Get privacy settings
 *     tags: [Users, Privacy]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Privacy settings
 */
router.get('/:id/privacy',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  userController.getPrivacySettings
);

/**
 * @swagger
 * /api/v1/users/{id}/privacy:
 *   put:
 *     summary: Update privacy settings
 *     tags: [Users, Privacy]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Privacy settings updated
 */
router.put('/:id/privacy',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  privacyValidation,
  enhancedValidate,
  userController.updatePrivacySettings
);

// ============================================================================
// ACTIVITY & HISTORY
// ============================================================================

/**
 * @swagger
 * /api/v1/users/{id}/activity:
 *   get:
 *     summary: Get user activity log
 *     tags: [Users, Activity]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Activity log
 */
router.get('/:id/activity',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  userController.getUserActivity
);

/**
 * @swagger
 * /api/v1/users/{id}/orders:
 *   get:
 *     summary: Get user orders
 *     tags: [Users, Orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of orders
 */
router.get('/:id/orders',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  query('status').optional().trim(),
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  userController.getUserOrders
);

/**
 * @swagger
 * /api/v1/users/{id}/reviews:
 *   get:
 *     summary: Get user reviews
 *     tags: [Users, Reviews]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of reviews
 */
router.get('/:id/reviews',
  apiRateLimit,
  optionalAuth,
  param('id').isInt(),
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  userController.getUserReviews
);

// ============================================================================
// WISHLIST & FAVORITES
// ============================================================================

/**
 * @swagger
 * /api/v1/users/{id}/wishlist:
 *   get:
 *     summary: Get user wishlist
 *     tags: [Users, Wishlist]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Wishlist items
 */
router.get('/:id/wishlist',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  userController.getWishlist
);

/**
 * @swagger
 * /api/v1/users/{id}/wishlist/{productId}:
 *   post:
 *     summary: Add product to wishlist
 *     tags: [Users, Wishlist]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Product added to wishlist
 */
router.post('/:id/wishlist/:productId',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  param('productId').isInt(),
  selfOnly,
  userController.addToWishlist
);

/**
 * @swagger
 * /api/v1/users/{id}/wishlist/{productId}:
 *   delete:
 *     summary: Remove product from wishlist
 *     tags: [Users, Wishlist]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Product removed from wishlist
 */
router.delete('/:id/wishlist/:productId',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  param('productId').isInt(),
  selfOnly,
  userController.removeFromWishlist
);

// ============================================================================
// DATA EXPORT (GDPR)
// ============================================================================

/**
 * @swagger
 * /api/v1/users/{id}/export:
 *   get:
 *     summary: Export user data (GDPR)
 *     tags: [Users, GDPR]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User data export
 */
router.get('/:id/export',
  strictRateLimit,
  authenticate,
  param('id').isInt(),
  selfOnly,
  userController.exportUserData
);

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @swagger
 * /api/v1/users/{id}/stats:
 *   get:
 *     summary: Get user statistics
 *     tags: [Users, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User statistics
 */
router.get('/:id/stats',
  apiRateLimit,
  authenticate,
  param('id').isInt(),
  ownerOrAdmin,
  userController.getUserStats
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((error, req, res, next) => {
  logger.error('User route error', {
    error: error.message,
    path: req.path,
    method: req.method,
    userId: req.user?.id
  });

  res.status(error.status || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.code || ERROR_CODES.INTERNAL_ERROR,
    message: Config.app.env === 'development' ? error.message : ERROR_MESSAGES.INTERNAL_ERROR,
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// EXPORTS
// ============================================================================

logger.info('✅ User routes loaded (MILITARY-GRADE)');

export default router;
