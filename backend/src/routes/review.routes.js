/**
 * Review Routes - MILITARY-GRADE Review Management System
 * Enterprise product review and rating system with moderation
 * 
 * @module routes/review
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - Product reviews & ratings
 * - Review moderation & approval
 * - Verified purchase badges
 * - Helpful/unhelpful voting
 * - Review replies (seller/admin)
 * - Review images/videos
 * - Review reporting & flagging
 * - Spam detection
 * - Sentiment analysis
 * - Review analytics
 * - Review reminders
 * - Incentivized reviews
 * - Review aggregation
 * - Review syndication
 * - Multi-language reviews
 * - Review templates
 * - Review rewards program
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - XSS prevention in review content
 * - Spam detection algorithms
 * - Rate limiting (prevent review bombing)
 * - Ownership verification
 * - Moderation workflow
 * - Abuse reporting
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
import reviewController from '../controllers/review.controller.js';

// Middleware
import { authenticate, optionalAuth } from '../middleware/authentication.js';
import { requireAdmin, requireModerator, ownerOrAdmin } from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  strictRateLimit,
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { sanitizeInput, sanitizeHTML } from '../middleware/sanitization.js';
import { attackLogger } from '../middleware/attackLogger.js';
import { modeSwitchMiddleware } from '../middleware/modeSwitch.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
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

const createReviewValidation = [
  body('productId')
    .isInt({ min: 1 })
    .withMessage('Valid product ID is required')
    .toInt(),
  
  body('orderId')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Invalid order ID')
    .toInt(),
  
  body('rating')
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5 stars')
    .toInt(),
  
  body('title')
    .trim()
    .isLength({ min: 5, max: 100 })
    .withMessage('Review title must be between 5 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-',.!?()]+$/)
    .withMessage('Review title contains invalid characters'),
  
  body('comment')
    .trim()
    .isLength({ min: 20, max: 2000 })
    .withMessage('Review comment must be between 20 and 2000 characters'),
  
  body('pros')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Pros cannot exceed 500 characters'),
  
  body('cons')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Cons cannot exceed 500 characters'),
  
  body('images')
    .optional()
    .isArray({ max: 5 })
    .withMessage('Maximum 5 images allowed'),
  
  body('images.*')
    .optional()
    .trim()
    .isURL()
    .withMessage('Invalid image URL'),
  
  body('verifiedPurchase')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('recommendToFriend')
    .optional()
    .isBoolean()
    .toBoolean()
];

const updateReviewValidation = [
  body('rating')
    .optional()
    .isInt({ min: 1, max: 5 })
    .toInt(),
  
  body('title')
    .optional()
    .trim()
    .isLength({ min: 5, max: 100 })
    .matches(/^[a-zA-Z0-9\s\-',.!?()]+$/),
  
  body('comment')
    .optional()
    .trim()
    .isLength({ min: 20, max: 2000 }),
  
  body('pros')
    .optional()
    .trim()
    .isLength({ max: 500 }),
  
  body('cons')
    .optional()
    .trim()
    .isLength({ max: 500 })
];

const replyValidation = [
  body('comment')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Reply must be between 10 and 1000 characters')
];

const reportValidation = [
  body('reason')
    .isIn(['spam', 'offensive', 'inappropriate', 'fake', 'other'])
    .withMessage('Invalid report reason'),
  
  body('details')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Details cannot exceed 500 characters')
];

const moderateValidation = [
  body('action')
    .isIn(['approve', 'reject', 'flag', 'delete'])
    .withMessage('Invalid moderation action'),
  
  body('reason')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Reason cannot exceed 500 characters')
];

// ============================================================================
// RATE LIMITERS
// ============================================================================

const reviewCreateLimit = createEndpointLimiter({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 5,
  message: 'Too many reviews submitted. Maximum 5 reviews per day.'
});

const reviewVoteLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50,
  message: 'Too many votes. Please try again later.'
});

const reviewReportLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many reports submitted.'
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
// REVIEW ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/reviews:
 *   get:
 *     summary: Get all reviews (with filtering)
 *     tags: [Reviews]
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
 *         name: productId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: userId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: rating
 *         schema:
 *           type: integer
 *       - in: query
 *         name: verified
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [createdAt, rating, helpful]
 *     responses:
 *       200:
 *         description: List of reviews
 */
router.get('/',
  apiRateLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('productId').optional().isInt({ min: 1 }).toInt(),
  query('userId').optional().isInt({ min: 1 }).toInt(),
  query('rating').optional().isInt({ min: 1, max: 5 }).toInt(),
  query('verified').optional().isBoolean().toBoolean(),
  query('status').optional().isIn(['pending', 'approved', 'rejected']),
  query('sortBy').optional().isIn(['createdAt', 'rating', 'helpful', 'recent']),
  query('sortOrder').optional().isIn(['ASC', 'DESC']),
  enhancedValidate,
  reviewController.getAllReviews
);

/**
 * @swagger
 * /api/v1/reviews/{id}:
 *   get:
 *     summary: Get review by ID
 *     tags: [Reviews]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Review details
 *       404:
 *         description: Review not found
 */
router.get('/:id',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid review ID'),
  enhancedValidate,
  reviewController.getReviewById
);

/**
 * @swagger
 * /api/v1/reviews:
 *   post:
 *     summary: Create new review
 *     tags: [Reviews]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Review created successfully
 */
router.post('/',
  reviewCreateLimit,
  authenticate,
  sanitizeInput,
  sanitizeHTML(['title', 'comment', 'pros', 'cons']),
  createReviewValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  reviewController.createReview
);

/**
 * @swagger
 * /api/v1/reviews/{id}:
 *   put:
 *     summary: Update review
 *     tags: [Reviews]
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
 *         description: Review updated successfully
 */
router.put('/:id',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  ownerOrAdmin,
  sanitizeInput,
  sanitizeHTML(['title', 'comment', 'pros', 'cons']),
  updateReviewValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  reviewController.updateReview
);

/**
 * @swagger
 * /api/v1/reviews/{id}:
 *   delete:
 *     summary: Delete review
 *     tags: [Reviews]
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
 *         description: Review deleted successfully
 */
router.delete('/:id',
  strictRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  ownerOrAdmin,
  reviewController.deleteReview
);

// ============================================================================
// REVIEW VOTING (HELPFUL/UNHELPFUL)
// ============================================================================

/**
 * @swagger
 * /api/v1/reviews/{id}/vote/helpful:
 *   post:
 *     summary: Mark review as helpful
 *     tags: [Reviews, Voting]
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
 *         description: Vote recorded
 */
router.post('/:id/vote/helpful',
  reviewVoteLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  enhancedValidate,
  reviewController.voteHelpful
);

/**
 * @swagger
 * /api/v1/reviews/{id}/vote/unhelpful:
 *   post:
 *     summary: Mark review as unhelpful
 *     tags: [Reviews, Voting]
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
 *         description: Vote recorded
 */
router.post('/:id/vote/unhelpful',
  reviewVoteLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  enhancedValidate,
  reviewController.voteUnhelpful
);

/**
 * @swagger
 * /api/v1/reviews/{id}/vote:
 *   delete:
 *     summary: Remove vote from review
 *     tags: [Reviews, Voting]
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
 *         description: Vote removed
 */
router.delete('/:id/vote',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  enhancedValidate,
  reviewController.removeVote
);

// ============================================================================
// REVIEW REPLIES
// ============================================================================

/**
 * @swagger
 * /api/v1/reviews/{id}/replies:
 *   get:
 *     summary: Get review replies
 *     tags: [Reviews, Replies]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of replies
 */
router.get('/:id/replies',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid review ID'),
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  reviewController.getReviewReplies
);

/**
 * @swagger
 * /api/v1/reviews/{id}/replies:
 *   post:
 *     summary: Reply to review (seller/admin only)
 *     tags: [Reviews, Replies]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Reply added successfully
 */
router.post('/:id/replies',
  apiRateLimit,
  authenticate,
  requireModerator,
  param('id').isInt().withMessage('Invalid review ID'),
  sanitizeInput,
  sanitizeHTML(['comment']),
  replyValidation,
  enhancedValidate,
  reviewController.replyToReview
);

/**
 * @swagger
 * /api/v1/reviews/{id}/replies/{replyId}:
 *   put:
 *     summary: Update reply
 *     tags: [Reviews, Replies]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: replyId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Reply updated
 */
router.put('/:id/replies/:replyId',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  param('replyId').isInt().withMessage('Invalid reply ID'),
  ownerOrAdmin,
  sanitizeInput,
  sanitizeHTML(['comment']),
  replyValidation,
  enhancedValidate,
  reviewController.updateReply
);

/**
 * @swagger
 * /api/v1/reviews/{id}/replies/{replyId}:
 *   delete:
 *     summary: Delete reply
 *     tags: [Reviews, Replies]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: replyId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Reply deleted
 */
router.delete('/:id/replies/:replyId',
  strictRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  param('replyId').isInt().withMessage('Invalid reply ID'),
  ownerOrAdmin,
  enhancedValidate,
  reviewController.deleteReply
);

// ============================================================================
// REVIEW REPORTING
// ============================================================================

/**
 * @swagger
 * /api/v1/reviews/{id}/report:
 *   post:
 *     summary: Report inappropriate review
 *     tags: [Reviews, Moderation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Report submitted successfully
 */
router.post('/:id/report',
  reviewReportLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid review ID'),
  sanitizeInput,
  reportValidation,
  enhancedValidate,
  reviewController.reportReview
);

/**
 * @swagger
 * /api/v1/reviews/{id}/reports:
 *   get:
 *     summary: Get review reports (moderator only)
 *     tags: [Reviews, Moderation]
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
 *         description: List of reports
 */
router.get('/:id/reports',
  apiRateLimit,
  authenticate,
  requireModerator,
  param('id').isInt().withMessage('Invalid review ID'),
  enhancedValidate,
  reviewController.getReviewReports
);

// ============================================================================
// MODERATION ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/reviews/pending:
 *   get:
 *     summary: Get pending reviews (moderator only)
 *     tags: [Reviews, Moderation]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of pending reviews
 */
router.get('/pending/all',
  apiRateLimit,
  authenticate,
  requireModerator,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  enhancedValidate,
  reviewController.getPendingReviews
);

/**
 * @swagger
 * /api/v1/reviews/{id}/moderate:
 *   post:
 *     summary: Moderate review (approve/reject/flag)
 *     tags: [Reviews, Moderation]
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
 *         description: Review moderated successfully
 */
router.post('/:id/moderate',
  strictRateLimit,
  authenticate,
  requireModerator,
  param('id').isInt().withMessage('Invalid review ID'),
  sanitizeInput,
  moderateValidation,
  enhancedValidate,
  reviewController.moderateReview
);

/**
 * @swagger
 * /api/v1/reviews/{id}/approve:
 *   post:
 *     summary: Approve review (moderator only)
 *     tags: [Reviews, Moderation]
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
 *         description: Review approved
 */
router.post('/:id/approve',
  strictRateLimit,
  authenticate,
  requireModerator,
  param('id').isInt().withMessage('Invalid review ID'),
  enhancedValidate,
  reviewController.approveReview
);

/**
 * @swagger
 * /api/v1/reviews/{id}/reject:
 *   post:
 *     summary: Reject review (moderator only)
 *     tags: [Reviews, Moderation]
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
 *         description: Review rejected
 */
router.post('/:id/reject',
  strictRateLimit,
  authenticate,
  requireModerator,
  param('id').isInt().withMessage('Invalid review ID'),
  body('reason').optional().trim().isLength({ max: 500 }),
  enhancedValidate,
  reviewController.rejectReview
);

// ============================================================================
// STATISTICS & ANALYTICS
// ============================================================================

/**
 * @swagger
 * /api/v1/reviews/stats/overview:
 *   get:
 *     summary: Get review statistics
 *     tags: [Reviews, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Review statistics
 */
router.get('/stats/overview',
  apiRateLimit,
  authenticate,
  requireAdmin,
  query('productId').optional().isInt({ min: 1 }).toInt(),
  query('period').optional().isIn(['day', 'week', 'month', 'year']),
  enhancedValidate,
  reviewController.getReviewStats
);

/**
 * @swagger
 * /api/v1/reviews/stats/sentiment:
 *   get:
 *     summary: Get sentiment analysis (admin only)
 *     tags: [Reviews, Analytics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sentiment analysis data
 */
router.get('/stats/sentiment',
  apiRateLimit,
  authenticate,
  requireAdmin,
  query('productId').optional().isInt({ min: 1 }).toInt(),
  enhancedValidate,
  reviewController.getSentimentAnalysis
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((error, req, res, next) => {
  logger.error('Review route error', {
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

logger.info('✅ Review routes loaded (MILITARY-GRADE)');

export default router;
