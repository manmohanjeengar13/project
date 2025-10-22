/**
 * Review Controller
 * Handles product reviews and ratings
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { 
  HTTP_STATUS, 
  USER_ROLES,
  PAGINATION 
} from '../config/constants.js';
import { NotFoundError, ValidationError, AuthorizationError } from '../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Create product review
 */
export const createReview = async (req, res, next) => {
  try {
    const { productId, rating, title, comment } = req.body;
    const userId = req.user.id;

    // Check if user has purchased the product
    const [purchases] = await db.execute(
      `SELECT oi.id FROM order_items oi
       JOIN orders o ON oi.order_id = o.id
       WHERE o.user_id = ? AND oi.product_id = ? AND o.status = 'delivered'
       LIMIT 1`,
      [userId, productId]
    );

    if (purchases.length === 0) {
      throw new ValidationError('You can only review products you have purchased');
    }

    // Check if user already reviewed this product
    const [existing] = await db.execute(
      'SELECT id FROM reviews WHERE user_id = ? AND product_id = ? LIMIT 1',
      [userId, productId]
    );

    if (existing.length > 0) {
      throw new ValidationError('You have already reviewed this product');
    }

    // Create review
    const [result] = await db.execute(
      `INSERT INTO reviews (user_id, product_id, rating, title, comment, is_verified_purchase, created_at)
       VALUES (?, ?, ?, ?, ?, TRUE, NOW())`,
      [userId, productId, rating, title, comment]
    );

    const reviewId = result.insertId;

    // Clear product cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Review created', { reviewId, userId, productId, rating });

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Review submitted successfully',
      data: {
        id: reviewId,
        rating,
        title,
        comment
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get user reviews
 */
export const getReviews = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Get total count
    const [countResult] = await db.execute(
      'SELECT COUNT(*) as total FROM reviews WHERE user_id = ?',
      [userId]
    );

    // Get reviews
    const [reviews] = await db.execute(
      `SELECT r.*, p.name as product_name
       FROM reviews r
       JOIN products p ON r.product_id = p.id
       WHERE r.user_id = ?
       ORDER BY r.created_at DESC
       LIMIT ? OFFSET ?`,
      [userId, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: reviews,
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
 * Update review
 */
export const updateReview = async (req, res, next) => {
  try {
    const reviewId = req.params.id;
    const userId = req.user.id;
    const { rating, title, comment } = req.body;

    // Check if review exists and belongs to user
    const [reviews] = await db.execute(
      'SELECT user_id, product_id FROM reviews WHERE id = ? LIMIT 1',
      [reviewId]
    );

    if (reviews.length === 0) {
      throw new NotFoundError('Review');
    }

    if (reviews[0].user_id !== userId) {
      throw new AuthorizationError('You can only update your own reviews');
    }

    // Build update query
    const updates = [];
    const values = [];

    if (rating !== undefined) {
      updates.push('rating = ?');
      values.push(rating);
    }
    if (title !== undefined) {
      updates.push('title = ?');
      values.push(title);
    }
    if (comment !== undefined) {
      updates.push('comment = ?');
      values.push(comment);
    }

    if (updates.length === 0) {
      throw new ValidationError('No fields to update');
    }

    updates.push('updated_at = NOW()');
    values.push(reviewId);

    await db.execute(
      `UPDATE reviews SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    // Clear product cache
    await cache.delete(CacheKeyBuilder.product(reviews[0].product_id));

    logger.info('Review updated', { reviewId, userId });

    res.json({
      success: true,
      message: 'Review updated successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete review
 */
export const deleteReview = async (req, res, next) => {
  try {
    const reviewId = req.params.id;
    const userId = req.user.id;

    // Check if review exists and belongs to user
    const [reviews] = await db.execute(
      'SELECT user_id, product_id FROM reviews WHERE id = ? LIMIT 1',
      [reviewId]
    );

    if (reviews.length === 0) {
      throw new NotFoundError('Review');
    }

    if (reviews[0].user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.MODERATOR, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only delete your own reviews');
    }

    await db.execute('DELETE FROM reviews WHERE id = ?', [reviewId]);

    // Clear product cache
    await cache.delete(CacheKeyBuilder.product(reviews[0].product_id));

    logger.info('Review deleted', { reviewId, userId });

    res.json({
      success: true,
      message: 'Review deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get review by ID
 */
export const getReviewById = async (req, res, next) => {
  try {
    const reviewId = req.params.id;

    const [reviews] = await db.execute(
      `SELECT r.*, u.username, u.first_name, u.last_name, p.name as product_name
       FROM reviews r
       JOIN users u ON r.user_id = u.id
       JOIN products p ON r.product_id = p.id
       WHERE r.id = ? LIMIT 1`,
      [reviewId]
    );

    if (reviews.length === 0) {
      throw new NotFoundError('Review');
    }

    // Get vote counts
    const [votes] = await db.execute(
      `SELECT 
        COUNT(CASE WHEN is_helpful = TRUE THEN 1 END) as helpful_count,
        COUNT(CASE WHEN is_helpful = FALSE THEN 1 END) as not_helpful_count
       FROM review_votes WHERE review_id = ?`,
      [reviewId]
    );

    const review = { ...reviews[0], ...votes[0] };

    res.json({
      success: true,
      data: review
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Vote on review (helpful/not helpful)
 */
export const voteReview = async (req, res, next) => {
  try {
    const reviewId = req.params.id;
    const userId = req.user.id;
    const { isHelpful } = req.body;

    // Check if review exists
    const [reviews] = await db.execute(
      'SELECT id FROM reviews WHERE id = ? LIMIT 1',
      [reviewId]
    );

    if (reviews.length === 0) {
      throw new NotFoundError('Review');
    }

    // Check if user already voted
    const [existing] = await db.execute(
      'SELECT id FROM review_votes WHERE review_id = ? AND user_id = ? LIMIT 1',
      [reviewId, userId]
    );

    if (existing.length > 0) {
      // Update existing vote
      await db.execute(
        'UPDATE review_votes SET is_helpful = ?, updated_at = NOW() WHERE id = ?',
        [isHelpful ? 1 : 0, existing[0].id]
      );
    } else {
      // Create new vote
      await db.execute(
        'INSERT INTO review_votes (review_id, user_id, is_helpful, created_at) VALUES (?, ?, ?, NOW())',
        [reviewId, userId, isHelpful ? 1 : 0]
      );
    }

    // Get updated vote counts
    const [votes] = await db.execute(
      `SELECT 
        COUNT(CASE WHEN is_helpful = TRUE THEN 1 END) as helpful_count,
        COUNT(CASE WHEN is_helpful = FALSE THEN 1 END) as not_helpful_count
       FROM review_votes WHERE review_id = ?`,
      [reviewId]
    );

    logger.info('Review voted', { reviewId, userId, isHelpful });

    res.json({
      success: true,
      message: 'Vote recorded successfully',
      data: votes[0]
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Report review
 */
export const reportReview = async (req, res, next) => {
  try {
    const reviewId = req.params.id;
    const userId = req.user.id;
    const { reason } = req.body;

    // Check if review exists
    const [reviews] = await db.execute(
      'SELECT id FROM reviews WHERE id = ? LIMIT 1',
      [reviewId]
    );

    if (reviews.length === 0) {
      throw new NotFoundError('Review');
    }

    // Check if user already reported this review
    const [existing] = await db.execute(
      'SELECT id FROM review_reports WHERE review_id = ? AND reported_by = ? LIMIT 1',
      [reviewId, userId]
    );

    if (existing.length > 0) {
      throw new ValidationError('You have already reported this review');
    }

    // Create report
    await db.execute(
      `INSERT INTO review_reports (review_id, reported_by, reason, status, created_at)
       VALUES (?, ?, ?, 'pending', NOW())`,
      [reviewId, userId, reason]
    );

    logger.info('Review reported', { reviewId, userId, reason });

    res.json({
      success: true,
      message: 'Review reported successfully. Our team will review it.'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get all reviews (Admin/Moderator)
 */
export const getAllReviews = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      status = '',
      rating = '',
      productId = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = [];
    const values = [];

    if (status) {
      conditions.push('r.status = ?');
      values.push(status);
    }

    if (rating) {
      conditions.push('r.rating = ?');
      values.push(parseInt(rating));
    }

    if (productId) {
      conditions.push('r.product_id = ?');
      values.push(productId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM reviews r ${whereClause}`,
      values
    );

    // Get reviews
    const [reviews] = await db.execute(
      `SELECT r.*, u.username, p.name as product_name,
              (SELECT COUNT(*) FROM review_votes WHERE review_id = r.id AND is_helpful = TRUE) as helpful_count,
              (SELECT COUNT(*) FROM review_reports WHERE review_id = r.id AND status = 'pending') as report_count
       FROM reviews r
       JOIN users u ON r.user_id = u.id
       JOIN products p ON r.product_id = p.id
       ${whereClause}
       ORDER BY r.created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: reviews,
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
 * Moderate review (Approve/Reject) - Moderator/Admin
 */
export const moderateReview = async (req, res, next) => {
  try {
    const reviewId = req.params.id;
    const { action, reason = '' } = req.body; // action: 'approve' or 'reject'

    if (!['approve', 'reject'].includes(action)) {
      throw new ValidationError('Invalid action. Must be approve or reject');
    }

    const status = action === 'approve' ? 'approved' : 'rejected';

    await db.execute(
      'UPDATE reviews SET status = ?, moderated_by = ?, moderation_notes = ?, updated_at = NOW() WHERE id = ?',
      [status, req.user.id, reason, reviewId]
    );

    // If rejecting, update any pending reports
    if (action === 'reject') {
      await db.execute(
        `UPDATE review_reports SET status = 'resolved', resolved_by = ?, resolved_at = NOW()
         WHERE review_id = ? AND status = 'pending'`,
        [req.user.id, reviewId]
      );
    }

    logger.info('Review moderated', { reviewId, action, moderatorId: req.user.id });

    res.json({
      success: true,
      message: `Review ${action}d successfully`
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get review statistics
 */
export const getReviewStatistics = async (req, res, next) => {
  try {
    // Overall statistics
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as avg_rating,
        COUNT(CASE WHEN rating = 5 THEN 1 END) as five_star,
        COUNT(CASE WHEN rating = 4 THEN 1 END) as four_star,
        COUNT(CASE WHEN rating = 3 THEN 1 END) as three_star,
        COUNT(CASE WHEN rating = 2 THEN 1 END) as two_star,
        COUNT(CASE WHEN rating = 1 THEN 1 END) as one_star,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_reviews,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_reviews,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_reviews
       FROM reviews`
    );

    // Reviews per day (last 7 days)
    const [daily] = await db.execute(
      `SELECT DATE(created_at) as date, COUNT(*) as count, COALESCE(AVG(rating), 0) as avg_rating
       FROM reviews
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
       GROUP BY DATE(created_at)
       ORDER BY date DESC`
    );

    // Most reviewed products
    const [topProducts] = await db.execute(
      `SELECT p.id, p.name, COUNT(r.id) as review_count, COALESCE(AVG(r.rating), 0) as avg_rating
       FROM products p
       JOIN reviews r ON p.id = r.product_id
       GROUP BY p.id, p.name
       ORDER BY review_count DESC
       LIMIT 10`
    );

    // Pending reports
    const [reports] = await db.execute(
      `SELECT COUNT(*) as pending_reports
       FROM review_reports
       WHERE status = 'pending'`
    );

    res.json({
      success: true,
      data: {
        overview: stats[0],
        daily,
        topProducts,
        pendingReports: reports[0].pending_reports
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get pending review reports (Moderator/Admin)
 */
export const getPendingReports = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM review_reports WHERE status = 'pending'`
    );

    // Get reports
    const [reports] = await db.execute(
      `SELECT rr.*, r.rating, r.comment, u.username as reporter_username, p.name as product_name
       FROM review_reports rr
       JOIN reviews r ON rr.review_id = r.id
       JOIN users u ON rr.reported_by = u.id
       JOIN products p ON r.product_id = p.id
       WHERE rr.status = 'pending'
       ORDER BY rr.created_at DESC
       LIMIT ? OFFSET ?`,
      [parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: reports,
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
 * Resolve review report (Moderator/Admin)
 */
export const resolveReport = async (req, res, next) => {
  try {
    const reportId = req.params.id;
    const { action } = req.body; // 'remove_review' or 'dismiss'

    if (!['remove_review', 'dismiss'].includes(action)) {
      throw new ValidationError('Invalid action');
    }

    // Get report
    const [reports] = await db.execute(
      'SELECT review_id FROM review_reports WHERE id = ? LIMIT 1',
      [reportId]
    );

    if (reports.length === 0) {
      throw new NotFoundError('Report');
    }

    if (action === 'remove_review') {
      // Delete the review
      await db.execute('DELETE FROM reviews WHERE id = ?', [reports[0].review_id]);
    }

    // Update report status
    await db.execute(
      'UPDATE review_reports SET status = ?, resolved_by = ?, resolved_at = NOW() WHERE id = ?',
      ['resolved', req.user.id, reportId]
    );

    logger.info('Review report resolved', { reportId, action, moderatorId: req.user.id });

    res.json({
      success: true,
      message: 'Report resolved successfully'
    });
  } catch (error) {
    next(error);
  }
};

export default {
  createReview,
  getReviews,
  updateReview,
  deleteReview,
  getReviewById,
  voteReview,
  reportReview,
  getAllReviews,
  moderateReview,
  getReviewStatistics,
  getPendingReports,
  resolveReport
};
