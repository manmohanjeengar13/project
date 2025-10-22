/**
 * Authentication Controller
 * Handles user registration, login, logout, and password management
 */

import bcrypt from 'bcrypt';
import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Email } from '../core/Email.js';
import { Config } from '../config/environment.js';
import { authConfig, securityMode } from '../config/security.js';
import { 
  generateToken, 
  generateRefreshToken, 
  verifyRefreshToken,
  revokeToken 
} from '../middleware/authentication.js';
import { 
  HTTP_STATUS, 
  ERROR_CODES, 
  SUCCESS_MESSAGES,
  ERROR_MESSAGES,
  SECURITY_EVENTS,
  USER_ROLES 
} from '../config/constants.js';
import { AppError, ValidationError, AuthenticationError } from '../middleware/errorHandler.js';
import crypto from 'crypto';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();
const email = Email.getInstance();

/**
 * Register new user
 */
export const register = async (req, res, next) => {
  try {
    const { username, email: userEmail, password, firstName, lastName } = req.body;

    // Check if username exists
    const [existingUsers] = await db.execute(
      'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1',
      [username, userEmail]
    );

    if (existingUsers.length > 0) {
      throw new ValidationError('Username or email already exists', {
        field: existingUsers[0].username === username ? 'username' : 'email'
      });
    }

    // Hash password
    const saltRounds = authConfig.password.bcryptRounds;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Insert user
    const [result] = await db.execute(
      `INSERT INTO users (
        username, email, password, first_name, last_name, role,
        email_verification_token, email_verification_expires, 
        is_email_verified, is_active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        username,
        userEmail,
        hashedPassword,
        firstName || null,
        lastName || null,
        USER_ROLES.CUSTOMER,
        verificationToken,
        verificationExpiry,
        false,
        true
      ]
    );

    const userId = result.insertId;

    // Log security event
    await logSecurityEvent(userId, SECURITY_EVENTS.LOGIN_SUCCESS, req);

    // Send verification email
    if (Config.email.enabled) {
      await email.sendEmailVerification(
        { email: userEmail, username },
        verificationToken
      );
    }

    logger.info('User registered successfully', { userId, username });

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: SUCCESS_MESSAGES.REGISTRATION_SUCCESS,
      data: {
        id: userId,
        username,
        email: userEmail,
        role: USER_ROLES.CUSTOMER
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Login user
 */
export const login = async (req, res, next) => {
  try {
    const { username, password, rememberMe } = req.body;
    const ip = req.ip;

    // Get user
    const [users] = await db.execute(
      `SELECT id, username, email, password, role, is_active, 
              is_email_verified, failed_login_attempts, account_locked_until
       FROM users 
       WHERE username = ? OR email = ?
       LIMIT 1`,
      [username, username]
    );

    if (users.length === 0) {
      await handleFailedLogin(null, username, ip, req);
      throw new AuthenticationError(ERROR_MESSAGES.INVALID_CREDENTIALS);
    }

    const user = users[0];

    // Check if account is locked
    if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
      logger.warn('Login attempted on locked account', { userId: user.id, username });
      throw new AuthenticationError(ERROR_MESSAGES.ACCOUNT_LOCKED);
    }

    // Check if account is active
    if (!user.is_active) {
      logger.warn('Login attempted on inactive account', { userId: user.id, username });
      throw new AuthenticationError(ERROR_MESSAGES.ACCOUNT_DISABLED);
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      await handleFailedLogin(user.id, username, ip, req);
      throw new AuthenticationError(ERROR_MESSAGES.INVALID_CREDENTIALS);
    }

    // Reset failed login attempts
    await db.execute(
      'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?',
      [user.id]
    );

    // Generate tokens
    const accessToken = generateToken(user, rememberMe ? '7d' : Config.jwt.expiresIn);
    const refreshToken = generateRefreshToken(user);

    // Store refresh token
    await db.execute(
      `INSERT INTO user_sessions (user_id, refresh_token, ip_address, user_agent, expires_at)
       VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))`,
      [user.id, refreshToken, ip, req.get('user-agent')]
    );

    // Set session
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    // Cache user
    await cache.set(CacheKeyBuilder.user(user.id), {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      is_active: user.is_active
    }, 900); // 15 minutes

    // Log login
    await logSecurityEvent(user.id, SECURITY_EVENTS.LOGIN_SUCCESS, req);
    await db.execute(
      `INSERT INTO login_history (user_id, ip_address, user_agent, success, timestamp)
       VALUES (?, ?, ?, ?, NOW())`,
      [user.id, ip, req.get('user-agent'), true]
    );

    logger.info('User logged in successfully', { userId: user.id, username: user.username });

    res.json({
      success: true,
      message: SUCCESS_MESSAGES.LOGIN_SUCCESS,
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: rememberMe ? '7d' : Config.jwt.expiresIn
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Logout user
 */
export const logout = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const token = req.token;

    // Revoke token
    if (token) {
      await revokeToken(token);
    }

    // Delete session from database
    await db.execute(
      'DELETE FROM user_sessions WHERE user_id = ? AND ip_address = ?',
      [userId, req.ip]
    );

    // Clear session
    req.session.destroy((err) => {
      if (err) {
        logger.error('Session destruction error:', err);
      }
    });

    // Clear cache
    await cache.delete(CacheKeyBuilder.user(userId));

    // Log logout
    await logSecurityEvent(userId, SECURITY_EVENTS.LOGOUT, req);

    logger.info('User logged out', { userId });

    res.json({
      success: true,
      message: SUCCESS_MESSAGES.LOGOUT_SUCCESS
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Refresh access token
 */
export const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken: token } = req.body;

    if (!token) {
      throw new ValidationError('Refresh token is required');
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(token);

    // Check if token exists in database
    const [sessions] = await db.execute(
      'SELECT id, user_id FROM user_sessions WHERE refresh_token = ? AND expires_at > NOW() LIMIT 1',
      [token]
    );

    if (sessions.length === 0) {
      throw new AuthenticationError('Invalid or expired refresh token');
    }

    // Get user
    const [users] = await db.execute(
      'SELECT id, username, email, role, is_active FROM users WHERE id = ? LIMIT 1',
      [decoded.userId]
    );

    if (users.length === 0 || !users[0].is_active) {
      throw new AuthenticationError('User not found or inactive');
    }

    const user = users[0];

    // Generate new tokens
    const accessToken = generateToken(user);
    const newRefreshToken = Config.jwt.rotateOnRefresh ? generateRefreshToken(user) : token;

    // Update session if token rotated
    if (Config.jwt.rotateOnRefresh) {
      await db.execute(
        'UPDATE user_sessions SET refresh_token = ?, expires_at = DATE_ADD(NOW(), INTERVAL 7 DAY) WHERE id = ?',
        [newRefreshToken, sessions[0].id]
      );
    }

    logger.info('Token refreshed', { userId: user.id });

    res.json({
      success: true,
      data: {
        accessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get current user
 */
export const getCurrentUser = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, role, 
              is_email_verified, created_at, updated_at
       FROM users 
       WHERE id = ? LIMIT 1`,
      [userId]
    );

    if (users.length === 0) {
      throw new AppError('User not found', HTTP_STATUS.NOT_FOUND);
    }

    res.json({
      success: true,
      data: users[0]
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Change password
 */
export const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Get current password
    const [users] = await db.execute(
      'SELECT password FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    if (users.length === 0) {
      throw new AppError('User not found', HTTP_STATUS.NOT_FOUND);
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, users[0].password);

    if (!passwordMatch) {
      throw new ValidationError('Current password is incorrect');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, authConfig.password.bcryptRounds);

    // Update password
    await db.execute(
      'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
      [hashedPassword, userId]
    );

    // Log security event
    await logSecurityEvent(userId, SECURITY_EVENTS.PASSWORD_CHANGE, req);

    // Send notification email
    if (Config.email.enabled) {
      await email.send({
        to: req.user.email,
        subject: 'Password Changed',
        text: 'Your password has been changed successfully.'
      });
    }

    logger.info('Password changed', { userId });

    res.json({
      success: true,
      message: SUCCESS_MESSAGES.PASSWORD_CHANGED
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Request password reset
 */
export const requestPasswordReset = async (req, res, next) => {
  try {
    const { email: userEmail } = req.body;

    // Get user
    const [users] = await db.execute(
      'SELECT id, username, email FROM users WHERE email = ? LIMIT 1',
      [userEmail]
    );

    // Always return success (don't reveal if email exists)
    if (users.length === 0) {
      logger.warn('Password reset requested for non-existent email', { email: userEmail });
      return res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent'
      });
    }

    const user = users[0];

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store token
    await db.execute(
      'UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?',
      [resetToken, resetExpiry, user.id]
    );

    // Send email
    if (Config.email.enabled) {
      await email.sendPasswordReset(user, resetToken);
    }

    logger.info('Password reset requested', { userId: user.id });

    res.json({
      success: true,
      message: 'If the email exists, a password reset link has been sent'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Reset password
 */
export const resetPassword = async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;

    // Find user with valid token
    const [users] = await db.execute(
      'SELECT id, username, email FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW() LIMIT 1',
      [token]
    );

    if (users.length === 0) {
      throw new ValidationError('Invalid or expired reset token');
    }

    const user = users[0];

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, authConfig.password.bcryptRounds);

    // Update password and clear reset token
    await db.execute(
      `UPDATE users SET 
        password = ?, 
        password_reset_token = NULL, 
        password_reset_expires = NULL,
        updated_at = NOW()
       WHERE id = ?`,
      [hashedPassword, user.id]
    );

    // Log security event
    await logSecurityEvent(user.id, SECURITY_EVENTS.PASSWORD_RESET, req);

    // Send confirmation email
    if (Config.email.enabled) {
      await email.send({
        to: user.email,
        subject: 'Password Reset Successful',
        text: 'Your password has been reset successfully.'
      });
    }

    logger.info('Password reset successfully', { userId: user.id });

    res.json({
      success: true,
      message: SUCCESS_MESSAGES.PASSWORD_RESET
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Verify email
 */
export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.body;

    // Find user with valid token
    const [users] = await db.execute(
      'SELECT id, username, email FROM users WHERE email_verification_token = ? AND email_verification_expires > NOW() LIMIT 1',
      [token]
    );

    if (users.length === 0) {
      throw new ValidationError('Invalid or expired verification token');
    }

    const user = users[0];

    // Update user
    await db.execute(
      `UPDATE users SET 
        is_email_verified = TRUE, 
        email_verification_token = NULL, 
        email_verification_expires = NULL,
        updated_at = NOW()
       WHERE id = ?`,
      [user.id]
    );

    logger.info('Email verified', { userId: user.id });

    res.json({
      success: true,
      message: 'Email verified successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Handle failed login attempt
 */
async function handleFailedLogin(userId, username, ip, req) {
  try {
    // Log failed attempt
    await db.execute(
      `INSERT INTO login_history (user_id, ip_address, user_agent, success, timestamp)
       VALUES (?, ?, ?, ?, NOW())`,
      [userId, ip, req.get('user-agent'), false]
    );

    if (userId && !securityMode.isVulnerable && authConfig.lockout.enabled) {
      // Increment failed attempts
      const [result] = await db.execute(
        'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
        [userId]
      );

      // Check if should lock account
      const [users] = await db.execute(
        'SELECT failed_login_attempts FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (users[0].failed_login_attempts >= authConfig.lockout.maxAttempts) {
        const lockUntil = new Date(Date.now() + authConfig.lockout.durationMinutes * 60 * 1000);
        
        await db.execute(
          'UPDATE users SET account_locked_until = ? WHERE id = ?',
          [lockUntil, userId]
        );

        await logSecurityEvent(userId, SECURITY_EVENTS.ACCOUNT_LOCKED, req);
        logger.warn('Account locked due to failed login attempts', { userId });
      }
    }

    logger.warn('Failed login attempt', { userId, username, ip });
  } catch (error) {
    logger.error('Error handling failed login:', error);
  }
}

/**
 * Log security event
 */
async function logSecurityEvent(userId, event, req) {
  try {
    await db.execute(
      `INSERT INTO security_events (user_id, event_type, ip_address, user_agent, details, timestamp)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [userId, event, req.ip, req.get('user-agent'), null]
    );
  } catch (error) {
    logger.error('Error logging security event:', error);
  }
}

export default {
  register,
  login,
  logout,
  refreshToken,
  getCurrentUser,
  changePassword,
  requestPasswordReset,
  resetPassword,
  verifyEmail
};
