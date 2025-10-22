/**
 * User Service
 * Business logic for user management operations
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { USER_ROLES, PAGINATION } from '../config/constants.js';
import { ValidationError, NotFoundError } from '../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get user by ID
 */
export const getUserById = async (userId) => {
  // Try cache first
  const cacheKey = CacheKeyBuilder.user(userId);
  let user = await cache.get(cacheKey);

  if (!user) {
    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, phone, address,
              role, is_active, is_email_verified, created_at, updated_at
       FROM users WHERE id = ? LIMIT 1`,
      [userId]
    );

    if (users.length === 0) {
      throw new NotFoundError('User');
    }

    user = users[0];
    await cache.set(cacheKey, user, 900);
  }

  return user;
};

/**
 * Update user profile
 */
export const updateUserProfile = async (userId, updateData) => {
  const { firstName, lastName, phone, address, email } = updateData;

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

  // Build update query
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
    updates.push('is_email_verified = FALSE');
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

  logger.info('User profile updated', { userId });

  return await getUserById(userId);
};

/**
 * Delete user account (soft delete)
 */
export const deleteUserAccount = async (userId) => {
  await db.execute(
    'UPDATE users SET is_active = FALSE, updated_at = NOW() WHERE id = ?',
    [userId]
  );

  // Clear cache
  await cache.delete(CacheKeyBuilder.user(userId));

  // Clear sessions
  await db.execute('DELETE FROM user_sessions WHERE user_id = ?', [userId]);

  logger.info('User account deleted', { userId });

  return true;
};

/**
 * Get all users with pagination and filtering
 */
export const getAllUsers = async (filters = {}) => {
  const {
    page = PAGINATION.DEFAULT_PAGE,
    limit = PAGINATION.DEFAULT_LIMIT,
    search = '',
    role = '',
    isActive = '',
    sortBy = 'created_at',
    sortOrder = 'DESC'
  } = filters;

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

  return {
    users,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: countResult[0].total,
      pages: Math.ceil(countResult[0].total / parseInt(limit))
    }
  };
};

/**
 * Update user role
 */
export const updateUserRole = async (userId, newRole) => {
  // Validate role
  const validRoles = Object.values(USER_ROLES);
  if (!validRoles.includes(newRole)) {
    throw new ValidationError('Invalid role');
  }

  // Get current user
  const user = await getUserById(userId);

  // Prevent changing super admin role unless by super admin
  if (user.role === USER_ROLES.SUPER_ADMIN) {
    throw new ValidationError('Cannot modify super admin role');
  }

  await db.execute(
    'UPDATE users SET role = ?, updated_at = NOW() WHERE id = ?',
    [newRole, userId]
  );

  // Clear cache
  await cache.delete(CacheKeyBuilder.user(userId));

  logger.info('User role updated', { userId, newRole });

  return true;
};

/**
 * Toggle user status (activate/deactivate)
 */
export const toggleUserStatus = async (userId, isActive) => {
  const user = await getUserById(userId);

  // Prevent deactivating super admin
  if (user.role === USER_ROLES.SUPER_ADMIN) {
    throw new ValidationError('Cannot deactivate super admin');
  }

  await db.execute(
    'UPDATE users SET is_active = ?, updated_at = NOW() WHERE id = ?',
    [isActive ? 1 : 0, userId]
  );

  // Clear cache
  await cache.delete(CacheKeyBuilder.user(userId));

  // If deactivating, clear sessions
  if (!isActive) {
    await db.execute('DELETE FROM user_sessions WHERE user_id = ?', [userId]);
  }

  logger.info('User status toggled', { userId, isActive });

  return true;
};

/**
 * Unlock user account
 */
export const unlockUserAccount = async (userId) => {
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

  logger.info('User account unlocked', { userId });

  return true;
};

/**
 * Get user statistics
 */
export const getUserStatistics = async (userId) => {
  // Order statistics
  const [orderStats] = await db.execute(
    `SELECT 
      COUNT(*) as total_orders,
      COALESCE(SUM(total), 0) as total_spent,
      COALESCE(AVG(total), 0) as avg_order_value,
      COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_orders
     FROM orders WHERE user_id = ?`,
    [userId]
  );

  // Review statistics
  const [reviewStats] = await db.execute(
    `SELECT 
      COUNT(*) as total_reviews,
      COALESCE(AVG(rating), 0) as avg_rating
     FROM reviews WHERE user_id = ?`,
    [userId]
  );

  // Recent orders
  const [recentOrders] = await db.execute(
    `SELECT id, order_number, total, status, created_at
     FROM orders
     WHERE user_id = ?
     ORDER BY created_at DESC
     LIMIT 5`,
    [userId]
  );

  // Wishlist count
  const [wishlistCount] = await db.execute(
    'SELECT COUNT(*) as count FROM wishlists WHERE user_id = ?',
    [userId]
  );

  return {
    orders: {
      ...orderStats[0],
      recent: recentOrders
    },
    reviews: reviewStats[0],
    wishlist: wishlistCount[0].count
  };
};

/**
 * Get user activity log
 */
export const getUserActivity = async (userId, page = 1, limit = 20) => {
  const offset = (parseInt(page) - 1) * parseInt(limit);

  // Login history
  const [loginHistory] = await db.execute(
    `SELECT ip_address, user_agent, success, timestamp
     FROM login_history
     WHERE user_id = ?
     ORDER BY timestamp DESC
     LIMIT ? OFFSET ?`,
    [userId, parseInt(limit), offset]
  );

  // Security events
  const [securityEvents] = await db.execute(
    `SELECT event_type, ip_address, user_agent, details, timestamp
     FROM security_events
     WHERE user_id = ?
     ORDER BY timestamp DESC
     LIMIT ? OFFSET ?`,
    [userId, parseInt(limit), offset]
  );

  return {
    loginHistory,
    securityEvents
  };
};

/**
 * Search users
 */
export const searchUsers = async (query, limit = 10) => {
  if (!query || query.length < 2) {
    return [];
  }

  const searchPattern = `%${query}%`;

  const [users] = await db.execute(
    `SELECT id, username, email, first_name, last_name, role, is_active
     FROM users
     WHERE (username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)
     AND is_active = TRUE
     LIMIT ?`,
    [searchPattern, searchPattern, searchPattern, searchPattern, parseInt(limit)]
  );

  return users;
};

/**
 * Bulk update users
 */
export const bulkUpdateUsers = async (userIds, action, value) => {
  if (!Array.isArray(userIds) || userIds.length === 0) {
    throw new ValidationError('User IDs must be a non-empty array');
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

    default:
      throw new ValidationError('Invalid action');
  }

  const [result] = await db.execute(query, params);

  // Clear cache for all affected users
  for (const userId of userIds) {
    await cache.delete(CacheKeyBuilder.user(userId));
  }

  logger.info('Bulk user update', { action, count: result.affectedRows });

  return result.affectedRows;
};

/**
 * Get user sessions
 */
export const getUserSessions = async (userId) => {
  const [sessions] = await db.execute(
    `SELECT id, ip_address, user_agent, created_at, expires_at
     FROM user_sessions
     WHERE user_id = ? AND expires_at > NOW()
     ORDER BY created_at DESC`,
    [userId]
  );

  return sessions;
};

/**
 * Revoke user session
 */
export const revokeUserSession = async (sessionId) => {
  await db.execute('DELETE FROM user_sessions WHERE id = ?', [sessionId]);
  logger.info('User session revoked', { sessionId });
  return true;
};

/**
 * Check if username exists
 */
export const usernameExists = async (username, excludeUserId = null) => {
  let query = 'SELECT id FROM users WHERE username = ? LIMIT 1';
  let params = [username];

  if (excludeUserId) {
    query = 'SELECT id FROM users WHERE username = ? AND id != ? LIMIT 1';
    params = [username, excludeUserId];
  }

  const [users] = await db.execute(query, params);
  return users.length > 0;
};

/**
 * Check if email exists
 */
export const emailExists = async (email, excludeUserId = null) => {
  let query = 'SELECT id FROM users WHERE email = ? LIMIT 1';
  let params = [email];

  if (excludeUserId) {
    query = 'SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1';
    params = [email, excludeUserId];
  }

  const [users] = await db.execute(query, params);
  return users.length > 0;
};

export default {
  getUserById,
  updateUserProfile,
  deleteUserAccount,
  getAllUsers,
  updateUserRole,
  toggleUserStatus,
  unlockUserAccount,
  getUserStatistics,
  getUserActivity,
  searchUsers,
  bulkUpdateUsers,
  getUserSessions,
  revokeUserSession,
  usernameExists,
  emailExists
};
