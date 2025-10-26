/**
 * Webhook Routes - MILITARY-GRADE Webhook Management System
 * Enterprise webhook integration for event-driven architecture
 * 
 * @module routes/webhook
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - Webhook registration & management
 * - Event subscription system
 * - Webhook signing & verification
 * - Retry mechanism with exponential backoff
 * - Webhook delivery logs
 * - Failed delivery handling
 * - Webhook testing endpoints
 * - Payload transformation
 * - Rate limiting per webhook
 * - Webhook health monitoring
 * - Custom headers support
 * - Secret rotation
 * - Webhook filters
 * - Batch event delivery
 * - Dead letter queue
 * - Webhook analytics
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - HMAC signature verification
 * - Secret key management
 * - SSL/TLS enforcement
 * - Request validation
 * - Rate limiting
 * - IP whitelisting
 * - Timeout protection
 * - Replay attack prevention
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import express from 'express';
import { body, param, query, validationResult } from 'express-validator';
import crypto from 'crypto';

// Core imports
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';

// Controller
import webhookController from '../controllers/webhook.controller.js';

// Middleware
import { authenticate } from '../middleware/authentication.js';
import { ownerOrAdmin, requireAdmin } from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  strictRateLimit,
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { sanitizeInput } from '../middleware/sanitization.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
  ERROR_CODES,
  WEBHOOK_EVENTS 
} from '../config/constants.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// RATE LIMITERS
// ============================================================================

const webhookCreateLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many webhooks created'
});

const webhookTestLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: 'Too many webhook tests'
});

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const createWebhookValidation = [
  body('url')
    .trim()
    .isURL({ protocols: ['https'], require_protocol: true })
    .withMessage('Webhook URL must be HTTPS')
    .isLength({ max: 500 })
    .withMessage('URL too long'),
  
  body('events')
    .isArray({ min: 1 })
    .withMessage('At least one event must be subscribed'),
  
  body('events.*')
    .isIn(Object.values(WEBHOOK_EVENTS))
    .withMessage('Invalid event type'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description too long'),
  
  body('isActive')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('headers')
    .optional()
    .isObject()
    .withMessage('Headers must be an object'),
  
  body('timeout')
    .optional()
    .isInt({ min: 1000, max: 30000 })
    .withMessage('Timeout must be between 1-30 seconds')
    .toInt(),
  
  body('retryConfig')
    .optional()
    .isObject(),
  
  body('retryConfig.maxAttempts')
    .optional()
    .isInt({ min: 0, max: 10 })
    .toInt(),
  
  body('retryConfig.backoffMultiplier')
    .optional()
    .isFloat({ min: 1, max: 5 })
    .toFloat()
];

const updateWebhookValidation = [
  body('url')
    .optional()
    .trim()
    .isURL({ protocols: ['https'], require_protocol: true })
    .isLength({ max: 500 }),
  
  body('events')
    .optional()
    .isArray({ min: 1 }),
  
  body('events.*')
    .optional()
    .isIn(Object.values(WEBHOOK_EVENTS)),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 }),
  
  body('isActive')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('headers')
    .optional()
    .isObject()
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
// WEBHOOK MANAGEMENT ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/webhooks:
 *   get:
 *     summary: Get all user webhooks
 *     tags: [Webhooks]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: isActive
 *         schema:
 *           type: boolean
 *     responses:
 *       200:
 *         description: List of webhooks
 */
router.get('/',
  apiRateLimit,
  authenticate,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('isActive').optional().isBoolean().toBoolean(),
  enhancedValidate,
  webhookController.getAllWebhooks
);

/**
 * @swagger
 * /api/v1/webhooks/{id}:
 *   get:
 *     summary: Get webhook by ID
 *     tags: [Webhooks]
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
 *         description: Webhook details
 */
router.get('/:id',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  enhancedValidate,
  webhookController.getWebhookById
);

/**
 * @swagger
 * /api/v1/webhooks:
 *   post:
 *     summary: Create new webhook
 *     tags: [Webhooks]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Webhook created successfully
 */
router.post('/',
  webhookCreateLimit,
  authenticate,
  sanitizeInput,
  createWebhookValidation,
  enhancedValidate,
  webhookController.createWebhook
);

/**
 * @swagger
 * /api/v1/webhooks/{id}:
 *   put:
 *     summary: Update webhook
 *     tags: [Webhooks]
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
 *         description: Webhook updated successfully
 */
router.put('/:id',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  sanitizeInput,
  updateWebhookValidation,
  enhancedValidate,
  webhookController.updateWebhook
);

/**
 * @swagger
 * /api/v1/webhooks/{id}:
 *   delete:
 *     summary: Delete webhook
 *     tags: [Webhooks]
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
 *         description: Webhook deleted successfully
 */
router.delete('/:id',
  strictRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  enhancedValidate,
  webhookController.deleteWebhook
);

// ============================================================================
// WEBHOOK ACTIVATION/DEACTIVATION
// ============================================================================

/**
 * @swagger
 * /api/v1/webhooks/{id}/activate:
 *   post:
 *     summary: Activate webhook
 *     tags: [Webhooks]
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
 *         description: Webhook activated
 */
router.post('/:id/activate',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  enhancedValidate,
  webhookController.activateWebhook
);

/**
 * @swagger
 * /api/v1/webhooks/{id}/deactivate:
 *   post:
 *     summary: Deactivate webhook
 *     tags: [Webhooks]
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
 *         description: Webhook deactivated
 */
router.post('/:id/deactivate',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  enhancedValidate,
  webhookController.deactivateWebhook
);

// ============================================================================
// WEBHOOK TESTING
// ============================================================================

/**
 * @swagger
 * /api/v1/webhooks/{id}/test:
 *   post:
 *     summary: Test webhook with sample payload
 *     tags: [Webhooks, Testing]
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
 *         description: Test webhook result
 */
router.post('/:id/test',
  webhookTestLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  body('event').optional().isIn(Object.values(WEBHOOK_EVENTS)),
  body('payload').optional().isObject(),
  enhancedValidate,
  webhookController.testWebhook
);

/**
 * @swagger
 * /api/v1/webhooks/{id}/ping:
 *   post:
 *     summary: Ping webhook endpoint
 *     tags: [Webhooks, Testing]
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
 *         description: Ping result
 */
router.post('/:id/ping',
  webhookTestLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid webhook ID'),
  ownerOrAdmin,
  enhancedValidate,
  webhookController.pingWebhook
);

// ============================================================================
// WEBHOOK DELIVERIES & LOGS
// ============================================================================

/**
 * @swagger
 * /api/v1/webhooks/{id}/deliveries:
 *   get:
 *     summary: Get webhook delivery history
 *     tags: [Webhooks, Logs]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [success, failed, pending]
 *     responses:
 *       200:
 *         description: Delivery history
 */
