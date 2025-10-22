/**
 * Authentication Middleware
 * Handles JWT and session-based authentication
 */

import jwt from 'jsonwebtoken';
import { Config } from '../config/environment.js';
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { HTTP_STATUS, ERROR_CODES, ERROR_MESSAGES } from '../config/constants.js';
import { securityMode } from '../config/security.js';

const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

/**
 * Verify JWT token
 */
export const verifyJWT = async (req, res, next) => {
  try {
    // Extract token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'No token provided'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer '

    // Check if token is blacklisted (in secure mode)
    if (!securityMode.isVulnerable) {
      const blacklisted = await cache.get(CacheKeyBuilder.token(token));
      if (blacklisted) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: ERROR_CODES.INVALID_TOKEN,
          message: 'Token has been revoked'
        });
      }
    }

    // Verify token
    const decoded = jwt.verify(token, Config.jwt.secret);

    // Check token expiration
    if (decoded.exp && Date.now() >= decoded.exp * 1000) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.TOKEN_EXPIRED,
        message: 'Token has expired'
      });
    }

    // Get user from cache or database
    const cacheKey = CacheKeyBuilder.user(decoded.userId || decoded.id);
    let user = await cache.get(cacheKey);

    if (!user) {
      const [users] = await db.execute(
        'SELECT id, username, email, role, is_active FROM users WHERE id = ?',
        [decoded.userId || decoded.id]
      );

      if (!users.length) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: ERROR_CODES.UNAUTHORIZED,
          message: 'User not found'
        });
      }

      user = users[0];
      
      // Cache user for 15 minutes
      await cache.set(cacheKey, user, 900);
    }

    // Check if user is active
    if (!user.is_active) {
      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.ACCOUNT_DISABLED,
        message: ERROR_MESSAGES.ACCOUNT_DISABLED
      });
    }

    // Attach user to request
    req.user = user;
    req.token = token;

    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.INVALID_TOKEN,
        message: 'Invalid token'
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.TOKEN_EXPIRED,
        message: 'Token has expired'
      });
    }

    logger.error('JWT verification error:', error);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: ERROR_CODES.INTERNAL_ERROR,
      message: 'Authentication error'
    });
  }
};

/**
 * Verify session authentication
 */
export const verifySession = async (req, res, next) => {
  try {
    if (!req.session || !req.session.user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Not authenticated'
      });
    }

    const userId = req.session.user.id;

    // Get user from cache or database
    const cacheKey = CacheKeyBuilder.user(userId);
    let user = await cache.get(cacheKey);

    if (!user) {
      const [users] = await db.execute(
        'SELECT id, username, email, role, is_active FROM users WHERE id = ?',
        [userId]
      );

      if (!users.length) {
        req.session.destroy();
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: ERROR_CODES.UNAUTHORIZED,
          message: 'User not found'
        });
      }

      user = users[0];
      await cache.set(cacheKey, user, 900);
    }

    // Check if user is active
    if (!user.is_active) {
      req.session.destroy();
      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.ACCOUNT_DISABLED,
        message: ERROR_MESSAGES.ACCOUNT_DISABLED
      });
    }

    // Update session user data
    req.session.user = user;
    req.user = user;

    next();
  } catch (error) {
    logger.error('Session verification error:', error);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: ERROR_CODES.INTERNAL_ERROR,
      message: 'Authentication error'
    });
  }
};

/**
 * Flexible authentication (JWT or Session)
 */
export const authenticate = async (req, res, next) => {
  // Try JWT first
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return verifyJWT(req, res, next);
  }

  // Fallback to session
  if (req.session && req.session.user) {
    return verifySession(req, res, next);
  }

  // No authentication found
  return res.status(HTTP_STATUS.UNAUTHORIZED).json({
    success: false,
    error: ERROR_CODES.UNAUTHORIZED,
    message: 'Authentication required'
  });
};

/**
 * Optional authentication (doesn't fail if not authenticated)
 */
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, Config.jwt.secret);
      
      const [users] = await db.execute(
        'SELECT id, username, email, role, is_active FROM users WHERE id = ?',
        [decoded.userId || decoded.id]
      );

      if (users.length && users[0].is_active) {
        req.user = users[0];
      }
    } else if (req.session && req.session.user) {
      req.user = req.session.user;
    }

    next();
  } catch (error) {
    // Continue even if authentication fails
    next();
  }
};

/**
 * Require login (session-based)
 */
export const requireLogin = async (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      error: ERROR_CODES.UNAUTHORIZED,
      message: 'Login required'
    });
  }

  // Set user on request
  req.user = req.session.user;
  next();
};

/**
 * Check if user is authenticated (doesn't require, just checks)
 */
export const isAuthenticated = (req, res, next) => {
  req.isAuthenticated = !!(
    (req.session && req.session.user) || 
    req.user
  );
  next();
};

/**
 * Revoke JWT token (add to blacklist)
 */
export const revokeToken = async (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) return false;

    // Calculate TTL until token expires
    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    
    if (ttl > 0) {
      await cache.set(CacheKeyBuilder.token(token), true, ttl);
      logger.info('Token revoked', { token: token.substring(0, 20) });
      return true;
    }

    return false;
  } catch (error) {
    logger.error('Token revocation error:', error);
    return false;
  }
};

/**
 * Generate JWT token
 */
export const generateToken = (user, expiresIn = Config.jwt.expiresIn) => {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username,
      role: user.role
    },
    Config.jwt.secret,
    {
      expiresIn,
      issuer: Config.jwt.issuer,
      audience: Config.jwt.audience
    }
  );
};

/**
 * Generate refresh token
 */
export const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      type: 'refresh'
    },
    Config.jwt.refreshSecret,
    {
      expiresIn: Config.jwt.refreshExpiresIn,
      issuer: Config.jwt.issuer,
      audience: Config.jwt.audience
    }
  );
};

/**
 * Verify refresh token
 */
export const verifyRefreshToken = (refreshToken) => {
  try {
    return jwt.verify(refreshToken, Config.jwt.refreshSecret);
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
};

/**
 * Middleware to refresh access token
 */
export const refreshAccessToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: 'REFRESH_TOKEN_REQUIRED',
        message: 'Refresh token is required'
      });
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);

    // Get user
    const [users] = await db.execute(
      'SELECT id, username, email, role, is_active FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (!users.length || !users[0].is_active) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Invalid user'
      });
    }

    const user = users[0];

    // Generate new access token
    const accessToken = generateToken(user);

    // Optionally generate new refresh token (token rotation)
    let newRefreshToken = refreshToken;
    if (Config.jwt.rotateOnRefresh) {
      newRefreshToken = generateRefreshToken(user);
    }

    res.json({
      success: true,
      accessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    logger.error('Token refresh error:', error);
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      error: ERROR_CODES.INVALID_TOKEN,
      message: 'Invalid or expired refresh token'
    });
  }
};

export default {
  verifyJWT,
  verifySession,
  authenticate,
  optionalAuth,
  requireLogin,
  isAuthenticated,
  revokeToken,
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  refreshAccessToken
};
