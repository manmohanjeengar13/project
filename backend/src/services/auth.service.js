/**
 * Authentication Service
 * Business logic for authentication operations
 */

import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Email } from '../core/Email.js';
import { Config } from '../config/environment.js';
import { authConfig } from '../config/security.js';
import { 
  generateToken, 
  generateRefreshToken,
  verifyRefreshToken 
} from '../middleware/authentication.js';
import { 
  USER_ROLES, 
  SECURITY_EVENTS,
  ERROR_CODES 
} from '../config/constants.js';
import { ValidationError, AuthenticationError } from '../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();
const email = Email.getInstance();

/**
 * Register new user
 */
export const registerUser = async (userData) => {
  const { username, email: userEmail, password, firstName, lastName } = userData;

  // Check if user already exists
  const existingUser = await findUserByUsernameOrEmail(username, userEmail);
  if (existingUser) {
    throw new ValidationError('Username or email already exists');
  }

  // Hash password
  const hashedPassword = await hashPassword(password);

  // Generate verification token
  const verificationToken = generateVerificationToken();
  const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

  // Create user
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

  // Send verification email
  if (Config.email.enabled) {
    await email.sendEmailVerification(
      { email: userEmail, username },
      verificationToken
    );
  }

  logger.info('User registered', { userId, username });

  return {
    id: userId,
    username,
    email: userEmail,
    role: USER_ROLES.CUSTOMER
  };
};

/**
 * Authenticate user
 */
export const authenticateUser = async (username, password, rememberMe = false) => {
  // Find user
  const user = await findUserByUsernameOrEmail(username, username);
  
  if (!user) {
    throw new AuthenticationError('Invalid credentials');
  }

  // Check if account is locked
  if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
    throw new AuthenticationError('Account is locked. Please try again later.');
  }

  // Check if account is active
  if (!user.is_active) {
    throw new AuthenticationError('Account is disabled');
  }

  // Verify password
  const isPasswordValid = await verifyPassword(password, user.password);
  
  if (!isPasswordValid) {
    await handleFailedLogin(user.id);
    throw new AuthenticationError('Invalid credentials');
  }

  // Reset failed login attempts
  await resetFailedLoginAttempts(user.id);

  // Generate tokens
  const accessToken = generateToken(user, rememberMe ? '7d' : Config.jwt.expiresIn);
  const refreshToken = generateRefreshToken(user);

  // Cache user data
  await cacheUserData(user);

  logger.info('User authenticated', { userId: user.id, username: user.username });

  return {
    user: sanitizeUser(user),
    tokens: {
      accessToken,
      refreshToken,
      expiresIn: rememberMe ? '7d' : Config.jwt.expiresIn
    }
  };
};

/**
 * Refresh access token
 */
export const refreshAccessToken = async (refreshToken) => {
  // Verify refresh token
  const decoded = verifyRefreshToken(refreshToken);

  // Check if token exists in database
  const [sessions] = await db.execute(
    'SELECT user_id FROM user_sessions WHERE refresh_token = ? AND expires_at > NOW() LIMIT 1',
    [refreshToken]
  );

  if (sessions.length === 0) {
    throw new AuthenticationError('Invalid or expired refresh token');
  }

  // Get user
  const user = await findUserById(sessions[0].user_id);
  
  if (!user || !user.is_active) {
    throw new AuthenticationError('User not found or inactive');
  }

  // Generate new tokens
  const accessToken = generateToken(user);
  const newRefreshToken = Config.jwt.rotateOnRefresh ? generateRefreshToken(user) : refreshToken;

  // Update session if rotating
  if (Config.jwt.rotateOnRefresh) {
    await db.execute(
      'UPDATE user_sessions SET refresh_token = ?, expires_at = DATE_ADD(NOW(), INTERVAL 7 DAY) WHERE refresh_token = ?',
      [newRefreshToken, refreshToken]
    );
  }

  logger.info('Token refreshed', { userId: user.id });

  return {
    accessToken,
    refreshToken: newRefreshToken
  };
};

/**
 * Change user password
 */
export const changePassword = async (userId, currentPassword, newPassword) => {
  // Get user
  const user = await findUserById(userId);
  
  if (!user) {
    throw new ValidationError('User not found');
  }

  // Verify current password
  const isPasswordValid = await verifyPassword(currentPassword, user.password);
  
  if (!isPasswordValid) {
    throw new ValidationError('Current password is incorrect');
  }

  // Hash new password
  const hashedPassword = await hashPassword(newPassword);

  // Update password
  await db.execute(
    'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
    [hashedPassword, userId]
  );

  // Clear user cache
  await cache.delete(CacheKeyBuilder.user(userId));

  logger.info('Password changed', { userId });

  return true;
};

/**
 * Request password reset
 */
export const requestPasswordReset = async (userEmail) => {
  const user = await findUserByEmail(userEmail);
  
  // Always return success (don't reveal if email exists)
  if (!user) {
    logger.warn('Password reset requested for non-existent email', { email: userEmail });
    return true;
  }

  // Generate reset token
  const resetToken = generateResetToken();
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

  return true;
};

/**
 * Reset password with token
 */
export const resetPassword = async (token, newPassword) => {
  // Find user with valid token
  const [users] = await db.execute(
    'SELECT id FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW() LIMIT 1',
    [token]
  );

  if (users.length === 0) {
    throw new ValidationError('Invalid or expired reset token');
  }

  const userId = users[0].id;

  // Hash new password
  const hashedPassword = await hashPassword(newPassword);

  // Update password and clear reset token
  await db.execute(
    `UPDATE users SET 
      password = ?, 
      password_reset_token = NULL, 
      password_reset_expires = NULL,
      updated_at = NOW()
     WHERE id = ?`,
    [hashedPassword, userId]
  );

  // Clear cache
  await cache.delete(CacheKeyBuilder.user(userId));

  logger.info('Password reset successfully', { userId });

  return true;
};

/**
 * Verify email address
 */
export const verifyEmail = async (token) => {
  // Find user with valid token
  const [users] = await db.execute(
    'SELECT id FROM users WHERE email_verification_token = ? AND email_verification_expires > NOW() LIMIT 1',
    [token]
  );

  if (users.length === 0) {
    throw new ValidationError('Invalid or expired verification token');
  }

  const userId = users[0].id;

  // Update user
  await db.execute(
    `UPDATE users SET 
      is_email_verified = TRUE, 
      email_verification_token = NULL, 
      email_verification_expires = NULL,
      updated_at = NOW()
     WHERE id = ?`,
    [userId]
  );

  logger.info('Email verified', { userId });

  return true;
};

/**
 * Store refresh token session
 */
export const storeRefreshToken = async (userId, refreshToken, ipAddress, userAgent) => {
  await db.execute(
    `INSERT INTO user_sessions (user_id, refresh_token, ip_address, user_agent, expires_at, created_at)
     VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY), NOW())`,
    [userId, refreshToken, ipAddress, userAgent]
  );
};

/**
 * Revoke refresh token
 */
export const revokeRefreshToken = async (refreshToken) => {
  await db.execute(
    'DELETE FROM user_sessions WHERE refresh_token = ?',
    [refreshToken]
  );
};

/**
 * Revoke all user sessions
 */
export const revokeAllUserSessions = async (userId) => {
  await db.execute(
    'DELETE FROM user_sessions WHERE user_id = ?',
    [userId]
  );
};

/**
 * Helper: Find user by username or email
 */
const findUserByUsernameOrEmail = async (username, email) => {
  const [users] = await db.execute(
    `SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1`,
    [username, email]
  );
  
  return users.length > 0 ? users[0] : null;
};

/**
 * Helper: Find user by ID
 */
const findUserById = async (userId) => {
  // Try cache first
  const cacheKey = CacheKeyBuilder.user(userId);
  let user = await cache.get(cacheKey);

  if (!user) {
    const [users] = await db.execute(
      'SELECT * FROM users WHERE id = ? LIMIT 1',
      [userId]
    );
    
    if (users.length > 0) {
      user = users[0];
      await cache.set(cacheKey, user, 900); // Cache for 15 minutes
    }
  }

  return user;
};

/**
 * Helper: Find user by email
 */
const findUserByEmail = async (email) => {
  const [users] = await db.execute(
    'SELECT * FROM users WHERE email = ? LIMIT 1',
    [email]
  );
  
  return users.length > 0 ? users[0] : null;
};

/**
 * Helper: Hash password
 */
const hashPassword = async (password) => {
  return await bcrypt.hash(password, authConfig.password.bcryptRounds);
};

/**
 * Helper: Verify password
 */
const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

/**
 * Helper: Generate verification token
 */
const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Helper: Generate reset token
 */
const generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Helper: Handle failed login
 */
const handleFailedLogin = async (userId) => {
  if (!authConfig.lockout.enabled) return;

  // Increment failed attempts
  await db.execute(
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

    logger.warn('Account locked due to failed login attempts', { userId });
  }
};

/**
 * Helper: Reset failed login attempts
 */
const resetFailedLoginAttempts = async (userId) => {
  await db.execute(
    'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?',
    [userId]
  );
};

/**
 * Helper: Cache user data
 */
const cacheUserData = async (user) => {
  const cacheKey = CacheKeyBuilder.user(user.id);
  await cache.set(cacheKey, sanitizeUser(user), 900); // 15 minutes
};

/**
 * Helper: Sanitize user object (remove sensitive data)
 */
const sanitizeUser = (user) => {
  const { password, password_reset_token, email_verification_token, ...sanitized } = user;
  return sanitized;
};

/**
 * Validate password strength
 */
export const validatePasswordStrength = (password) => {
  const errors = [];

  if (password.length < authConfig.password.minLength) {
    errors.push(`Password must be at least ${authConfig.password.minLength} characters`);
  }

  if (authConfig.password.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (authConfig.password.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (authConfig.password.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (authConfig.password.requireSpecial && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

export default {
  registerUser,
  authenticateUser,
  refreshAccessToken,
  changePassword,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
  storeRefreshToken,
  revokeRefreshToken,
  revokeAllUserSessions,
  validatePasswordStrength
};
