/**
 * Authorization Middleware
 * Role-based and permission-based access control
 */

import { Logger } from '../core/Logger.js';
import { 
  HTTP_STATUS, 
  ERROR_CODES, 
  USER_ROLES, 
  ROLE_HIERARCHY,
  PERMISSIONS 
} from '../config/constants.js';

const logger = Logger.getInstance();

/**
 * Check if user has required role
 */
export const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Authentication required'
      });
    }

    const userRole = req.user.role;

    if (!allowedRoles.includes(userRole)) {
      logger.warn('Authorization failed', {
        userId: req.user.id,
        userRole,
        requiredRoles: allowedRoles,
        path: req.path
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

/**
 * Require admin role
 */
export const requireAdmin = requireRole(USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN);

/**
 * Require moderator or admin role
 */
export const requireModerator = requireRole(
  USER_ROLES.MODERATOR, 
  USER_ROLES.ADMIN, 
  USER_ROLES.SUPER_ADMIN
);

/**
 * Require minimum role level
 */
export const requireMinRole = (minRole) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Authentication required'
      });
    }

    const userRoleLevel = ROLE_HIERARCHY[req.user.role] || 0;
    const minRoleLevel = ROLE_HIERARCHY[minRole] || 0;

    if (userRoleLevel < minRoleLevel) {
      logger.warn('Authorization failed - insufficient role level', {
        userId: req.user.id,
        userRole: req.user.role,
        userLevel: userRoleLevel,
        requiredLevel: minRoleLevel
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

/**
 * Check if user has specific permission
 */
export const requirePermission = (...requiredPermissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Authentication required'
      });
    }

    // Admin and Super Admin have all permissions
    if ([USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      return next();
    }

    // Check user permissions (would come from database in real app)
    const userPermissions = getUserPermissions(req.user.role);

    const hasPermission = requiredPermissions.every(permission =>
      userPermissions.includes(permission)
    );

    if (!hasPermission) {
      logger.warn('Authorization failed - missing permissions', {
        userId: req.user.id,
        requiredPermissions,
        userPermissions
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

/**
 * Check resource ownership
 */
export const requireOwnership = (resourceIdParam = 'id', userIdField = 'user_id') => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Authentication required'
      });
    }

    // Admins can access any resource
    if ([USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      return next();
    }

    const resourceId = req.params[resourceIdParam];
    const userId = req.user.id;

    // Resource ownership check would be done in the controller
    // This middleware just sets a flag
    req.checkOwnership = {
      resourceId,
      userId,
      userIdField
    };

    next();
  };
};

/**
 * Check if user owns the resource or is admin
 */
export const ownerOrAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      error: ERROR_CODES.UNAUTHORIZED,
      message: 'Authentication required'
    });
  }

  // Set flag for controller to check
  req.requireOwnershipOrAdmin = true;
  next();
};

/**
 * Restrict to self only (user can only access their own data)
 */
export const selfOnly = (userIdParam = 'id') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.UNAUTHORIZED,
        message: 'Authentication required'
      });
    }

    const requestedUserId = parseInt(req.params[userIdParam]);
    const currentUserId = req.user.id;

    // Admins can access any user
    if ([USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      return next();
    }

    if (requestedUserId !== currentUserId) {
      logger.warn('Self-only access denied', {
        userId: currentUserId,
        requestedUserId,
        path: req.path
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: ERROR_CODES.FORBIDDEN,
        message: 'You can only access your own data'
      });
    }

    next();
  };
};

/**
 * Get permissions for a role
 */
function getUserPermissions(role) {
  const rolePermissions = {
    [USER_ROLES.CUSTOMER]: [
      PERMISSIONS.USER_READ,
      PERMISSIONS.PRODUCT_READ,
      PERMISSIONS.ORDER_CREATE,
      PERMISSIONS.ORDER_READ,
      PERMISSIONS.REVIEW_CREATE,
      PERMISSIONS.REVIEW_READ
    ],
    [USER_ROLES.MODERATOR]: [
      PERMISSIONS.USER_READ,
      PERMISSIONS.PRODUCT_READ,
      PERMISSIONS.PRODUCT_UPDATE,
      PERMISSIONS.ORDER_READ,
      PERMISSIONS.ORDER_UPDATE,
      PERMISSIONS.REVIEW_CREATE,
      PERMISSIONS.REVIEW_READ,
      PERMISSIONS.REVIEW_UPDATE,
      PERMISSIONS.REVIEW_DELETE,
      PERMISSIONS.REVIEW_MODERATE
    ],
    [USER_ROLES.ADMIN]: Object.values(PERMISSIONS),
    [USER_ROLES.SUPER_ADMIN]: Object.values(PERMISSIONS)
  };

  return rolePermissions[role] || [];
}

/**
 * Check if request is from same user
 */
export const isSameUser = (req) => {
  if (!req.user) return false;
  
  const userId = req.params.id || req.params.userId || req.body.user_id;
  return parseInt(userId) === req.user.id;
};

/**
 * Check if user is admin
 */
export const isAdmin = (req) => {
  return req.user && [USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role);
};

/**
 * Check if user is moderator or above
 */
export const isModerator = (req) => {
  return req.user && [
    USER_ROLES.MODERATOR,
    USER_ROLES.ADMIN,
    USER_ROLES.SUPER_ADMIN
  ].includes(req.user.role);
};

/**
 * Conditional authorization
 */
export const authorizeIf = (condition, ...middleware) => {
  return (req, res, next) => {
    if (condition(req)) {
      // Apply middleware chain
      let index = 0;
      const runNext = (err) => {
        if (err) return next(err);
        if (index >= middleware.length) return next();
        
        const currentMiddleware = middleware[index++];
        currentMiddleware(req, res, runNext);
      };
      runNext();
    } else {
      next();
    }
  };
};

/**
 * Rate limit by role (different limits for different roles)
 */
export const rateLimitByRole = (limits) => {
  return (req, res, next) => {
    if (!req.user) {
      req.rateLimit = limits.default || limits.anonymous || 100;
    } else {
      req.rateLimit = limits[req.user.role] || limits.default || 100;
    }
    next();
  };
};

export default {
  requireRole,
  requireAdmin,
  requireModerator,
  requireMinRole,
  requirePermission,
  requireOwnership,
  ownerOrAdmin,
  selfOnly,
  isSameUser,
  isAdmin,
  isModerator,
  authorizeIf,
  rateLimitByRole
};
