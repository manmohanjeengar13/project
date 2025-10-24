/**
 * Notification Service
 * Enterprise-grade notification management system
 * 
 * Features:
 * - Multi-channel delivery (WebSocket, Email, SMS, Push)
 * - Real-time notifications via WebSocket
 * - Notification preferences per user
 * - Notification templates and categories
 * - Read/unread tracking
 * - Notification history and archiving
 * - Batch notifications
 * - Priority-based delivery
 * - Notification scheduling
 * - Analytics and metrics
 * 
 * @module services/notification
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { WebSocket } from '../core/WebSocket.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { tables } from '../config/database.js';
import { NOTIFICATION_TYPES, PAGINATION } from '../config/constants.js';
import { getEmailService } from './email.service.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();
const ws = WebSocket.getInstance();

/**
 * Notification priorities
 */
export const NOTIFICATION_PRIORITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  URGENT: 'urgent'
};

/**
 * Notification channels
 */
export const NOTIFICATION_CHANNELS = {
  IN_APP: 'in_app',
  EMAIL: 'email',
  SMS: 'sms',
  PUSH: 'push',
  WEBSOCKET: 'websocket'
};

/**
 * Create notification with multi-channel delivery
 * 
 * @param {number} userId - User ID
 * @param {object} notificationData - Notification data
 * @returns {Promise<object>} Created notification
 */
export const createNotification = async (userId, notificationData) => {
  const {
    type,
    title,
    message,
    data = null,
    priority = NOTIFICATION_PRIORITY.MEDIUM,
    channels = [NOTIFICATION_CHANNELS.IN_APP, NOTIFICATION_CHANNELS.WEBSOCKET],
    actionUrl = null,
    expiresAt = null
  } = notificationData;

  try {
    // Check user notification preferences
    const userPreferences = await getUserNotificationPreferences(userId);
    const enabledChannels = filterChannelsByPreferences(channels, type, userPreferences);

    // Create notification record
    const [result] = await db.execute(
      `INSERT INTO ${tables.NOTIFICATIONS} (
        user_id, type, title, message, data,
        priority, action_url, expires_at,
        is_read, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE, NOW())`,
      [
        userId,
        type,
        title,
        message,
        data ? JSON.stringify(data) : null,
        priority,
        actionUrl,
        expiresAt
      ]
    );

    const notificationId = result.insertId;

    const notification = {
      id: notificationId,
      userId,
      type,
      title,
      message,
      data,
      priority,
      actionUrl,
      isRead: false,
      createdAt: new Date()
    };

    // Deliver via enabled channels
    const deliveryPromises = enabledChannels.map(channel => 
      deliverNotification(userId, notification, channel)
    );

    await Promise.allSettled(deliveryPromises);

    // Clear user's notification cache
    await cache.delete(CacheKeyBuilder.userNotifications(userId));

    logger.info('Notification created', {
      notificationId,
      userId,
      type,
      priority,
      channels: enabledChannels
    });

    return notification;
  } catch (error) {
    logger.error('Failed to create notification', { userId, error: error.message });
    throw error;
  }
};

/**
 * Deliver notification via specific channel
 * 
 * @param {number} userId - User ID
 * @param {object} notification - Notification data
 * @param {string} channel - Delivery channel
 */
const deliverNotification = async (userId, notification, channel) => {
  try {
    switch (channel) {
      case NOTIFICATION_CHANNELS.WEBSOCKET:
        // Send via WebSocket for real-time delivery
        if (ws.io) {
          ws.sendToUser(userId, 'notification', notification);
          logger.debug('Notification sent via WebSocket', { userId, notificationId: notification.id });
        }
        break;

      case NOTIFICATION_CHANNELS.EMAIL:
        // Send via email
        const emailService = getEmailService();
        if (emailService) {
          const [users] = await db.execute(
            'SELECT email, username FROM users WHERE id = ?',
            [userId]
          );
          if (users[0]) {
            await emailService.sendEmail(
              users[0].email,
              notification.title,
              'notification',
              {
                username: users[0].username,
                title: notification.title,
                message: notification.message,
                actionUrl: notification.actionUrl
              }
            );
          }
        }
        break;

      case NOTIFICATION_CHANNELS.SMS:
        // Integrate with SMS service (Twilio, etc.)
        logger.debug('SMS notification (not implemented)', { userId, notificationId: notification.id });
        break;

      case NOTIFICATION_CHANNELS.PUSH:
        // Integrate with push notification service (FCM, APNS, etc.)
        logger.debug('Push notification (not implemented)', { userId, notificationId: notification.id });
        break;

      case NOTIFICATION_CHANNELS.IN_APP:
      default:
        // Already stored in database
        logger.debug('In-app notification stored', { userId, notificationId: notification.id });
        break;
    }
  } catch (error) {
    logger.error('Failed to deliver notification', { 
      userId, 
      notificationId: notification.id,
      channel, 
      error: error.message 
    });
  }
};

/**
 * Get user notification preferences
 * 
 * @param {number} userId - User ID
 * @returns {Promise<object>} User preferences
 */
const getUserNotificationPreferences = async (userId) => {
  const cacheKey = CacheKeyBuilder.userPreferences(userId);
  let preferences = await cache.get(cacheKey);

  if (!preferences) {
    const [result] = await db.execute(
      'SELECT preferences FROM user_notification_preferences WHERE user_id = ?',
      [userId]
    );

    if (result[0]) {
      preferences = JSON.parse(result[0].preferences);
    } else {
      // Default preferences
      preferences = {
        order_updates: ['in_app', 'email', 'websocket'],
        promotions: ['in_app'],
        security_alerts: ['in_app', 'email', 'websocket'],
        account_activity: ['in_app', 'email'],
        reviews: ['in_app'],
        system_updates: ['in_app']
      };
    }

    await cache.set(cacheKey, preferences, 3600);
  }

  return preferences;
};

/**
 * Filter channels based on user preferences
 * 
 * @param {array} requestedChannels - Requested channels
 * @param {string} notificationType - Notification type
 * @param {object} userPreferences - User preferences
 * @returns {array} Enabled channels
 */
const filterChannelsByPreferences = (requestedChannels, notificationType, userPreferences) => {
  const preferredChannels = userPreferences[notificationType] || [];
  return requestedChannels.filter(channel => 
    preferredChannels.includes(channel) || channel === NOTIFICATION_CHANNELS.IN_APP
  );
};

/**
 * Get user notifications with pagination
 * 
 * @param {number} userId - User ID
 * @param {object} filters - Filter options
 * @returns {Promise<object>} Notifications and pagination
 */
export const getUserNotifications = async (userId, filters = {}) => {
  const {
    unreadOnly = false,
    type = null,
    priority = null,
    page = PAGINATION.DEFAULT_PAGE,
    limit = PAGINATION.DEFAULT_LIMIT
  } = filters;

  try {
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const conditions = ['user_id = ?', '(expires_at IS NULL OR expires_at > NOW())'];
    const values = [userId];

    if (unreadOnly) {
      conditions.push('is_read = FALSE');
    }

    if (type) {
      conditions.push('type = ?');
      values.push(type);
    }

    if (priority) {
      conditions.push('priority = ?');
      values.push(priority);
    }

    const whereClause = conditions.join(' AND ');

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM ${tables.NOTIFICATIONS} WHERE ${whereClause}`,
      values
    );

    // Get notifications
    const [notifications] = await db.execute(
      `SELECT * FROM ${tables.NOTIFICATIONS}
       WHERE ${whereClause}
       ORDER BY 
         CASE priority
           WHEN 'urgent' THEN 1
           WHEN 'high' THEN 2
           WHEN 'medium' THEN 3
           WHEN 'low' THEN 4
         END,
         created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    // Parse JSON data fields
    const processedNotifications = notifications.map(n => ({
      ...n,
      data: n.data ? JSON.parse(n.data) : null
    }));

    return {
      notifications: processedNotifications,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    };
  } catch (error) {
    logger.error('Failed to get user notifications', { userId, error: error.message });
    throw error;
  }
};

/**
 * Mark notification as read
 * 
 * @param {number} notificationId - Notification ID
 * @param {number} userId - User ID
 * @returns {Promise<boolean>} Success status
 */
export const markAsRead = async (notificationId, userId) => {
  try {
    await db.execute(
      `UPDATE ${tables.NOTIFICATIONS}
       SET is_read = TRUE, read_at = NOW()
       WHERE id = ? AND user_id = ?`,
      [notificationId, userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.userNotifications(userId));

    logger.info('Notification marked as read', { notificationId, userId });
    return true;
  } catch (error) {
    logger.error('Failed to mark notification as read', { notificationId, userId, error });
    return false;
  }
};

/**
 * Mark all notifications as read
 * 
 * @param {number} userId - User ID
 * @returns {Promise<number>} Number of notifications marked
 */
export const markAllAsRead = async (userId) => {
  try {
    const [result] = await db.execute(
      `UPDATE ${tables.NOTIFICATIONS}
       SET is_read = TRUE, read_at = NOW()
       WHERE user_id = ? AND is_read = FALSE`,
      [userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.userNotifications(userId));

    logger.info('All notifications marked as read', { userId, count: result.affectedRows });
    return result.affectedRows;
  } catch (error) {
    logger.error('Failed to mark all as read', { userId, error });
    return 0;
  }
};

/**
 * Delete notification
 * 
 * @param {number} notificationId - Notification ID
 * @param {number} userId - User ID
 * @returns {Promise<boolean>} Success status
 */
export const deleteNotification = async (notificationId, userId) => {
  try {
    await db.execute(
      `DELETE FROM ${tables.NOTIFICATIONS} WHERE id = ? AND user_id = ?`,
      [notificationId, userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.userNotifications(userId));

    logger.info('Notification deleted', { notificationId, userId });
    return true;
  } catch (error) {
    logger.error('Failed to delete notification', { notificationId, userId, error });
    return false;
  }
};

/**
 * Delete all read notifications
 * 
 * @param {number} userId - User ID
 * @returns {Promise<number>} Number of notifications deleted
 */
export const deleteAllRead = async (userId) => {
  try {
    const [result] = await db.execute(
      `DELETE FROM ${tables.NOTIFICATIONS}
       WHERE user_id = ? AND is_read = TRUE`,
      [userId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.userNotifications(userId));

    logger.info('Read notifications deleted', { userId, count: result.affectedRows });
    return result.affectedRows;
  } catch (error) {
    logger.error('Failed to delete read notifications', { userId, error });
    return 0;
  }
};

/**
 * Get unread notification count
 * 
 * @param {number} userId - User ID
 * @returns {Promise<number>} Unread count
 */
export const getUnreadCount = async (userId) => {
  try {
    const cacheKey = `notification:unread_count:${userId}`;
    let count = await cache.get(cacheKey);

    if (count === null) {
      const [result] = await db.execute(
        `SELECT COUNT(*) as count FROM ${tables.NOTIFICATIONS}
         WHERE user_id = ? AND is_read = FALSE
         AND (expires_at IS NULL OR expires_at > NOW())`,
        [userId]
      );

      count = result[0].count;
      await cache.set(cacheKey, count, 300); // Cache for 5 minutes
    }

    return count;
  } catch (error) {
    logger.error('Failed to get unread count', { userId, error });
    return 0;
  }
};

/**
 * Create batch notifications
 * 
 * @param {array} userIds - Array of user IDs
 * @param {object} notificationData - Notification data
 * @returns {Promise<object>} Batch creation result
 */
export const createBatchNotifications = async (userIds, notificationData) => {
  const results = {
    total: userIds.length,
    created: 0,
    failed: 0,
    errors: []
  };

  try {
    // Process in batches to avoid overwhelming the system
    const batchSize = 100;
    for (let i = 0; i < userIds.length; i += batchSize) {
      const batch = userIds.slice(i, i + batchSize);

      const promises = batch.map(async (userId) => {
        try {
          await createNotification(userId, notificationData);
          results.created++;
        } catch (error) {
          results.failed++;
          results.errors.push({ userId, error: error.message });
        }
      });

      await Promise.allSettled(promises);
    }

    logger.info('Batch notifications created', results);
    return results;
  } catch (error) {
    logger.error('Batch notification creation failed', error);
    throw error;
  }
};

/**
 * Update user notification preferences
 * 
 * @param {number} userId - User ID
 * @param {object} preferences - New preferences
 * @returns {Promise<boolean>} Success status
 */
export const updateUserPreferences = async (userId, preferences) => {
  try {
    const [existing] = await db.execute(
      'SELECT id FROM user_notification_preferences WHERE user_id = ?',
      [userId]
    );

    if (existing.length > 0) {
      await db.execute(
        'UPDATE user_notification_preferences SET preferences = ?, updated_at = NOW() WHERE user_id = ?',
        [JSON.stringify(preferences), userId]
      );
    } else {
      await db.execute(
        'INSERT INTO user_notification_preferences (user_id, preferences, created_at) VALUES (?, ?, NOW())',
        [userId, JSON.stringify(preferences)]
      );
    }

    // Clear cache
    await cache.delete(CacheKeyBuilder.userPreferences(userId));

    logger.info('Notification preferences updated', { userId });
    return true;
  } catch (error) {
    logger.error('Failed to update preferences', { userId, error });
    return false;
  }
};

/**
 * Schedule notification for future delivery
 * 
 * @param {number} userId - User ID
 * @param {object} notificationData - Notification data
 * @param {Date} scheduledFor - Schedule time
 * @returns {Promise<number>} Scheduled notification ID
 */
export const scheduleNotification = async (userId, notificationData, scheduledFor) => {
  try {
    const [result] = await db.execute(
      `INSERT INTO scheduled_notifications (
        user_id, type, title, message, data,
        priority, action_url, channels,
        scheduled_for, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
      [
        userId,
        notificationData.type,
        notificationData.title,
        notificationData.message,
        notificationData.data ? JSON.stringify(notificationData.data) : null,
        notificationData.priority || NOTIFICATION_PRIORITY.MEDIUM,
        notificationData.actionUrl || null,
        JSON.stringify(notificationData.channels || [NOTIFICATION_CHANNELS.IN_APP]),
        scheduledFor
      ]
    );

    logger.info('Notification scheduled', { 
      userId, 
      scheduledNotificationId: result.insertId,
      scheduledFor 
    });

    return result.insertId;
  } catch (error) {
    logger.error('Failed to schedule notification', { userId, error });
    throw error;
  }
};

/**
 * Process scheduled notifications
 */
export const processScheduledNotifications = async () => {
  try {
    const [notifications] = await db.execute(
      `SELECT * FROM scheduled_notifications
       WHERE status = 'pending'
       AND scheduled_for <= NOW()
       LIMIT 100`
    );

    for (const notification of notifications) {
      try {
        await createNotification(notification.user_id, {
          type: notification.type,
          title: notification.title,
          message: notification.message,
          data: notification.data ? JSON.parse(notification.data) : null,
          priority: notification.priority,
          actionUrl: notification.action_url,
          channels: JSON.parse(notification.channels)
        });

        await db.execute(
          `UPDATE scheduled_notifications 
           SET status = 'sent', sent_at = NOW()
           WHERE id = ?`,
          [notification.id]
        );
      } catch (error) {
        logger.error('Failed to send scheduled notification', { 
          scheduledNotificationId: notification.id, 
          error 
        });

        await db.execute(
          `UPDATE scheduled_notifications 
           SET status = 'failed', error = ?
           WHERE id = ?`,
          [error.message, notification.id]
        );
      }
    }

    if (notifications.length > 0) {
      logger.info(`Processed ${notifications.length} scheduled notifications`);
    }
  } catch (error) {
    logger.error('Failed to process scheduled notifications', error);
  }
};

/**
 * Get notification statistics
 * 
 * @param {number} userId - User ID (optional)
 * @returns {Promise<object>} Statistics
 */
export const getNotificationStats = async (userId = null) => {
  try {
    const conditions = userId ? 'WHERE user_id = ?' : '';
    const values = userId ? [userId] : [];

    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN is_read = FALSE THEN 1 ELSE 0 END) as unread,
        SUM(CASE WHEN is_read = TRUE THEN 1 ELSE 0 END) as read,
        SUM(CASE WHEN priority = 'urgent' THEN 1 ELSE 0 END) as urgent,
        SUM(CASE WHEN priority = 'high' THEN 1 ELSE 0 END) as high,
        COUNT(DISTINCT type) as types
       FROM ${tables.NOTIFICATIONS}
       ${conditions}`,
      values
    );

    return stats[0];
  } catch (error) {
    logger.error('Failed to get notification stats', { userId, error });
    return null;
  }
};

/**
 * Cleanup expired notifications
 * 
 * @returns {Promise<number>} Number of notifications deleted
 */
export const cleanupExpiredNotifications = async () => {
  try {
    const [result] = await db.execute(
      `DELETE FROM ${tables.NOTIFICATIONS}
       WHERE expires_at IS NOT NULL
       AND expires_at < NOW()`
    );

    logger.info(`Cleaned up ${result.affectedRows} expired notifications`);
    return result.affectedRows;
  } catch (error) {
    logger.error('Failed to cleanup expired notifications', error);
    return 0;
  }
};

/**
 * Predefined notification creators for common events
 */

/**
 * Send order update notification
 */
export const notifyOrderUpdate = async (userId, order, status) => {
  const titles = {
    pending: 'Order Received',
    processing: 'Order Being Processed',
    shipped: 'Order Shipped',
    delivered: 'Order Delivered',
    cancelled: 'Order Cancelled'
  };

  const messages = {
    pending: `Your order ${order.order_number} has been received and is pending processing.`,
    processing: `Your order ${order.order_number} is being processed.`,
    shipped: `Your order ${order.order_number} has been shipped!`,
    delivered: `Your order ${order.order_number} has been delivered.`,
    cancelled: `Your order ${order.order_number} has been cancelled.`
  };

  return createNotification(userId, {
    type: NOTIFICATION_TYPES.ORDER_UPDATE,
    title: titles[status] || 'Order Update',
    message: messages[status] || 'Your order status has been updated.',
    data: {
      orderId: order.id,
      orderNumber: order.order_number,
      status
    },
    priority: status === 'delivered' ? NOTIFICATION_PRIORITY.HIGH : NOTIFICATION_PRIORITY.MEDIUM,
    channels: [NOTIFICATION_CHANNELS.IN_APP, NOTIFICATION_CHANNELS.EMAIL, NOTIFICATION_CHANNELS.WEBSOCKET],
    actionUrl: `/orders/${order.id}`
  });
};

/**
 * Send security alert notification
 */
export const notifySecurityAlert = async (userId, alertType, details) => {
  const titles = {
    login: 'New Login Detected',
    password_change: 'Password Changed',
    email_change: 'Email Address Changed',
    suspicious_activity: 'Suspicious Activity Detected'
  };

  return createNotification(userId, {
    type: NOTIFICATION_TYPES.SECURITY_ALERT,
    title: titles[alertType] || 'Security Alert',
    message: details,
    priority: NOTIFICATION_PRIORITY.URGENT,
    channels: [NOTIFICATION_CHANNELS.IN_APP, NOTIFICATION_CHANNELS.EMAIL, NOTIFICATION_CHANNELS.WEBSOCKET],
    actionUrl: '/account/security'
  });
};

/**
 * Send review request notification
 */
export const notifyReviewRequest = async (userId, order) => {
  return createNotification(userId, {
    type: NOTIFICATION_TYPES.REVIEW_REQUEST,
    title: 'Rate Your Recent Purchase',
    message: `How was your experience with order ${order.order_number}? Share your feedback!`,
    data: {
      orderId: order.id,
      orderNumber: order.order_number
    },
    priority: NOTIFICATION_PRIORITY.LOW,
    channels: [NOTIFICATION_CHANNELS.IN_APP],
    actionUrl: `/orders/${order.id}/review`,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
  });
};

/**
 * Send promotional notification
 */
export const notifyPromotion = async (userId, promotion) => {
  return createNotification(userId, {
    type: NOTIFICATION_TYPES.PROMOTION,
    title: promotion.title,
    message: promotion.message,
    data: {
      promotionId: promotion.id,
      code: promotion.code
    },
    priority: NOTIFICATION_PRIORITY.LOW,
    channels: [NOTIFICATION_CHANNELS.IN_APP],
    actionUrl: promotion.url,
    expiresAt: promotion.expiresAt
  });
};

/**
 * Send system maintenance notification
 */
export const notifySystemMaintenance = async (userIds, maintenance) => {
  return createBatchNotifications(userIds, {
    type: NOTIFICATION_TYPES.SYSTEM_UPDATE,
    title: 'Scheduled Maintenance',
    message: maintenance.message,
    data: {
      maintenanceId: maintenance.id,
      startTime: maintenance.startTime,
      endTime: maintenance.endTime
    },
    priority: NOTIFICATION_PRIORITY.HIGH,
    channels: [NOTIFICATION_CHANNELS.IN_APP, NOTIFICATION_CHANNELS.EMAIL]
  });
};

/**
 * Send account activity notification
 */
export const notifyAccountActivity = async (userId, activity) => {
  const titles = {
    profile_update: 'Profile Updated',
    address_added: 'New Address Added',
    payment_method_added: 'New Payment Method Added',
    wishlist_item_back_in_stock: 'Wishlist Item Back in Stock'
  };

  return createNotification(userId, {
    type: NOTIFICATION_TYPES.ACCOUNT_ACTIVITY,
    title: titles[activity.type] || 'Account Activity',
    message: activity.message,
    data: activity.data,
    priority: NOTIFICATION_PRIORITY.LOW,
    channels: [NOTIFICATION_CHANNELS.IN_APP, NOTIFICATION_CHANNELS.WEBSOCKET]
  });
};

export default {
  createNotification,
  getUserNotifications,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  deleteAllRead,
  getUnreadCount,
  createBatchNotifications,
  updateUserPreferences,
  scheduleNotification,
  processScheduledNotifications,
  getNotificationStats,
  cleanupExpiredNotifications,
  notifyOrderUpdate,
  notifySecurityAlert,
  notifyReviewRequest,
  notifyPromotion,
  notifySystemMaintenance,
  notifyAccountActivity
};
