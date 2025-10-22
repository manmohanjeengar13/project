/**
 * User Controller
 * Handles user profile management and user-related operations
 */

import bcrypt from 'bcrypt';
import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { authConfig } from '../config/security.js';
import { 
  HTTP_STATUS, 
  ERROR_CODES,
  USER_ROLES,
  PAGINATION 
} from '../config/constants.js';
import { AppError, NotFoundError, ValidationError, AuthorizationError } from '../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get user profile
 */
export const getProfile = async (req, res, next) => {
  try {
    const userId = req.params.id || req.user.id;

    // Check authorization
    if (parseInt(userId) !== req.user.id && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only view your own profile');
    }

    // Try cache first
    const cacheKey = CacheKeyBuilder.user(userId);
    let user = await cache.get(cacheKey);

    if (!user) {
      const [users] = await db.execute(
        `SELECT id, username, email, first_name, last_name, phone, address,
                role, is_active, is_email_verified, created_at, updated_at,
                last_login_at
         FROM users 
         WHERE id = ? LIMIT 1`,
        [userId]
      );

      if (users.length === 0) {
        throw new NotFoundError('User');
      }

      user = users[0];
      await cache.set(cacheKey, user, 900); // Cache for 15 minutes
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update user profile
 */
export const updateProfile = async (req, res, next) => {
  try {
    const userId = req.params.id || req.user.id;
    const { firstName, lastName, phone, address, email } = req.body;

    // Check authorization
    if (parseInt(userId) !== req.user.id && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only update your own profile');
    }

    // Check if email is being changed and already exists
    if (email) {
      const [existing] = await db.execute(
        'SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1',
        [email, userId]
      );

      if (existing.length > 0) {
        throw new ValidationError('Email already in use');
      }
    }

    // Build update query dynamically
    const updates = [];
    const values = [];

    if (firstName !== undefined) {
      updates.push('first_name = ?');
      values.push(firstName);
    }
    if (lastName !== undefined) {
      updates.push('last_name = ?');
      values.push(lastName);
    }
    if (phone !== undefined) {
      updates.push('phone = ?');
      values.push(phone);
    }
    if (address !== undefined) {
      updates.push('address = ?');
      values.push(address);
    }
    if (email !== undefined) {
      updates.push('email = ?');
      values.push(email);
      updates.push('is_email_verified = FALSE'); // Require re-verification
    }

    if (updates.length === 0) {
      throw new ValidationError('No fields to update');
    }

    updates.push('updated_at = NOW()');
    values.push(userId);

    await db.execute(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.user(userId));

    // Get updated user
    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, phone, address,
              role, is_active, is_email_verified, created_at, updated_at
       FROM users 
       WHERE id = ? LIMIT 1`,
      [userId]
    );

    logger.info('Profile updated', { userId });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: users[0]
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete user account
 */
export const deleteAccount = async (req, res, next) => {
  try {
    const userId = req.params.id || req.user.id;

    // Check authorization
    if (parseInt(userId) !== req.user.id && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only delete your own account');
    }

    // Soft delete (deactivate) instead of hard delete
    await db.execute(
      'UPDATE users SET is_active = FALSE, updated_at = NOW() WHERE id = ?',
      [userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.user(userId));

    // Clear sessions
    await db.execute('DELETE FROM user_sessions WHERE user_id = ?', [userId]);

    logger.info('User account deleted', { userId });

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get all users (Admin only)
 */
export const getAllUsers = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      search = '',
      role = '',
      isActive = '',
      sortBy = 'created_at',
      sortOrder = 'DESC'
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = [];
    const values = [];

    if (search) {
      conditions.push('(username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)');
      const searchPattern = `%${search}%`;
      values.push(searchPattern, searchPattern, searchPattern, searchPattern);
    }

    if (role) {
      conditions.push('role = ?');
      values.push(role);
    }

    if (isActive !== '') {
      conditions.push('is_active = ?');
      values.push(isActive === 'true' ? 1 : 0);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM users ${whereClause}`,
      values
    );
    const total = countResult[0].total;

    // Get users
    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, role, 
              is_active, is_email_verified, created_at, last_login_at
       FROM users 
       ${whereClause}
       ORDER BY ${sortBy} ${sortOrder}
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get user by ID (Admin only)
 */
export const getUserById = async (req, res, next) => {
  try {
    const userId = req.params.id;

    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, phone, address,
              role, is_active, is_email_verified, failed_login_attempts,
              account_locked_until, created_at, updated_at, last_login_at
       FROM users 
       WHERE id = ? LIMIT 1`,
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User');
    }

    // Get user statistics
    const [orderStats] = await db.execute(
      `SELECT COUNT(*) as total_orders, 
              COALESCE(SUM(total), 0) as total_spent
       FROM orders WHERE user_id = ?`,
      [userId]
    );

    const [reviewStats] = await db.execute(
      'SELECT COUNT(*) as total_reviews FROM reviews WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      data: {
        ...users[0],
        statistics: {
          orders: orderStats[0].total_orders,
          totalSpent: orderStats[0].total_spent,
          reviews: reviewStats[0].total_reviews
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update user role (Admin only)
 */
export const updateUserRole = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    // Validate role
    const validRoles = Object.values(USER_ROLES);
    if (!validRoles.includes(role)) {
      throw new ValidationError('Invalid role');
    }

    // Prevent changing super admin role
    const [users] = await db.execute(
      'SELECT role FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User');
    }

    if (users[0].role === USER_ROLES.SUPER_ADMIN && req.user.role !== USER_ROLES.SUPER_ADMIN) {
      throw new AuthorizationError('Only super admin can modify super admin role');
    }

    // Update role
    await db.execute(
      'UPDATE users SET role = ?, updated_at = NOW() WHERE id = ?',
      [role, userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.user(userId));

    logger.info('User role updated', { userId, newRole: role, adminId: req.user.id });

    res.json({
      success: true,
      message: 'User role updated successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Activate/Deactivate user (Admin only)
 */
export const toggleUserStatus = async (req, res, next) => {
  try {
    const userId = req.params.id;
    const { isActive } = req.body;

    // Prevent deactivating super admin
    const [users] = await db.execute(
      'SELECT role FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User');
    }

    if (users[0].role === USER_ROLES.SUPER_ADMIN) {
      throw new AuthorizationError('Cannot deactivate super admin');
    }

    // Update status
    await db.execute(
      'UPDATE users SET is_active = ?, updated_at = NOW() WHERE id = ?',
      [isActive ? 1 : 0, userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.user(userId));

    // If deactivating, clear all sessions
    if (!isActive) {
      await db.execute('DELETE FROM user_sessions WHERE user_id = ?', [userId]);
    }

    logger.info('User status toggled', { userId, isActive, adminId: req.user.id });

    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Unlock user account (Admin only)
 */
export const unlockAccount = async (req, res, next) => {
  try {
    const userId = req.params.id;

    await db.execute(
      `UPDATE users SET 
        failed_login_attempts = 0, 
        account_locked_until = NULL,
        updated_at = NOW()
       WHERE id = ?`,
      [userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.user(userId));

    logger.info('Account unlocked', { userId, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Account unlocked successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get user activity log
 */
export const getUserActivity = async (req, res, next) => {
  try {
    const userId = req.params.id || req.user.id;
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Check authorization
    if (parseInt(userId) !== req.user.id && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only view your own activity');
    }

    // Get login history
    const [loginHistory] = await db.execute(
      `SELECT ip_address, user_agent, success, timestamp
       FROM login_history
       WHERE user_id = ?
       ORDER BY timestamp DESC
       LIMIT ? OFFSET ?`,
      [userId, parseInt(limit), offset]
    );

    // Get security events
    const [securityEvents] = await db.execute(
      `SELECT event_type, ip_address, user_agent, details, timestamp
       FROM security_events
       WHERE user_id = ?
       ORDER BY timestamp DESC
       LIMIT ? OFFSET ?`,
      [userId, parseInt(limit), offset]
    );

    // Get total count
    const [countResult] = await db.execute(
      'SELECT COUNT(*) as total FROM login_history WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      data: {
        loginHistory,
        securityEvents
      },
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
 * Get user statistics
 */
export const getUserStatistics = async (req, res, next) => {
  try {
    const userId = req.params.id || req.user.id;

    // Check authorization
    if (parseInt(userId) !== req.user.id && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only view your own statistics');
    }

    // Get order statistics
    const [orderStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_orders,
        COALESCE(SUM(total), 0) as total_spent,
        COALESCE(AVG(total), 0) as avg_order_value,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_orders,
        COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_orders
       FROM orders WHERE user_id = ?`,
      [userId]
    );

    // Get review statistics
    const [reviewStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as avg_rating
       FROM reviews WHERE user_id = ?`,
      [userId]
    );

    // Get recent orders
    const [recentOrders] = await db.execute(
      `SELECT id, order_number, total, status, created_at
       FROM orders
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 5`,
      [userId]
    );

    // Get wishlist count
    const [wishlistCount] = await db.execute(
      'SELECT COUNT(*) as count FROM wishlists WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      data: {
        orders: {
          ...orderStats[0],
          recent: recentOrders
        },
        reviews: reviewStats[0],
        wishlist: wishlistCount[0].count
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Search users (Admin only)
 */
export const searchUsers = async (req, res, next) => {
  try {
    const { q, limit = 10 } = req.query;

    if (!q || q.length < 2) {
      return res.json({
        success: true,
        data: []
      });
    }

    const searchPattern = `%${q}%`;

    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, role, is_active
       FROM users
       WHERE (username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)
       AND is_active = TRUE
       LIMIT ?`,
      [searchPattern, searchPattern, searchPattern, searchPattern, parseInt(limit)]
    );

    res.json({
      success: true,
      data: users
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Bulk update users (Admin only)
 */
export const bulkUpdateUsers = async (req, res, next) => {
  try {
    const { userIds, action, value } = req.body;

    if (!Array.isArray(userIds) || userIds.length === 0) {
      throw new ValidationError('User IDs must be a non-empty array');
    }

    const validActions = ['activate', 'deactivate', 'change_role', 'unlock'];
    if (!validActions.includes(action)) {
      throw new ValidationError('Invalid action');
    }

    let query;
    let params;

    switch (action) {
      case 'activate':
        query = 'UPDATE users SET is_active = TRUE, updated_at = NOW() WHERE id IN (?)';
        params = [userIds];
        break;

      case 'deactivate':
        // Prevent deactivating super admins
        const [superAdmins] = await db.execute(
          'SELECT id FROM users WHERE id IN (?) AND role = ?',
          [userIds, USER_ROLES.SUPER_ADMIN]
        );
        if (superAdmins.length > 0) {
          throw new ValidationError('Cannot deactivate super admin users');
        }
        query = 'UPDATE users SET is_active = FALSE, updated_at = NOW() WHERE id IN (?)';
        params = [userIds];
        break;

      case 'change_role':
        if (!value || !Object.values(USER_ROLES).includes(value)) {
          throw new ValidationError('Invalid role');
        }
        query = 'UPDATE users SET role = ?, updated_at = NOW() WHERE id IN (?)';
        params = [value, userIds];
        break;

      case 'unlock':
        query = 'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, updated_at = NOW() WHERE id IN (?)';
        params = [userIds];
        break;
    }

    const [result] = await db.execute(query, params);

    // Clear cache for all affected users
    for (const userId of userIds) {
      await cache.delete(CacheKeyBuilder.user(userId));
    }

    logger.info('Bulk user update', { action, count: result.affectedRows, adminId: req.user.id });

    res.json({
      success: true,
      message: `${result.affectedRows} users updated successfully`
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Export users (Admin only)
 */
export const exportUsers = async (req, res, next) => {
  try {
    const { format = 'json', role = '', isActive = '' } = req.query;

    // Build WHERE clause
    const conditions = [];
    const values = [];

    if (role) {
      conditions.push('role = ?');
      values.push(role);
    }

    if (isActive !== '') {
      conditions.push('is_active = ?');
      values.push(isActive === 'true' ? 1 : 0);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, role, 
              is_active, is_email_verified, created_at
       FROM users 
       ${whereClause}
       ORDER BY created_at DESC`,
      values
    );

    if (format === 'csv') {
      // Generate CSV
      const csv = [
        ['ID', 'Username', 'Email', 'First Name', 'Last Name', 'Role', 'Active', 'Email Verified', 'Created At'].join(','),
        ...users.map(user => [
          user.id,
          user.username,
          user.email,
          user.first_name || '',
          user.last_name || '',
          user.role,
          user.is_active,
          user.is_email_verified,
          user.created_at
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=users.csv');
      return res.send(csv);
    }

    // JSON format
    res.json({
      success: true,
      data: users,
      count: users.length
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get user sessions
 */
export const getUserSessions = async (req, res, next) => {
  try {
    const userId = req.params.id || req.user.id;

    // Check authorization
    if (parseInt(userId) !== req.user.id && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only view your own sessions');
    }

    const [sessions] = await db.execute(
      `SELECT id, ip_address, user_agent, created_at, expires_at
       FROM user_sessions
       WHERE user_id = ? AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json({
      success: true,
      data: sessions
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Revoke user session
 */
export const revokeSession = async (req, res, next) => {
  try {
    const sessionId = req.params.sessionId;
    const userId = req.user.id;

    // Check if session belongs to user
    const [sessions] = await db.execute(
      'SELECT user_id FROM user_sessions WHERE id = ? LIMIT 1',
      [sessionId]
    );

    if (sessions.length === 0) {
      throw new NotFoundError('Session');
    }

    if (sessions[0].user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only revoke your own sessions');
    }

    await db.execute('DELETE FROM user_sessions WHERE id = ?', [sessionId]);

    logger.info('Session revoked', { sessionId, userId });

    res.json({
      success: true,
      message: 'Session revoked successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Revoke all user sessions except current
 */
export const revokeAllSessions = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const currentIp = req.ip;

    await db.execute(
      'DELETE FROM user_sessions WHERE user_id = ? AND ip_address != ?',
      [userId, currentIp]
    );

    logger.info('All sessions revoked', { userId });

    res.json({
      success: true,
      message: 'All other sessions revoked successfully'
    });
  } catch (error) {
    next(error);
  }
};

export default {
  getProfile,
  updateProfile,
  deleteAccount,
  getAllUsers,
  getUserById,
  updateUserRole,
  toggleUserStatus,
  unlockAccount,
  getUserActivity,
  getUserStatistics,
  searchUsers,
  bulkUpdateUsers,
  exportUsers,
  getUserSessions,
  revokeSession,
  revokeAllSessions
};
