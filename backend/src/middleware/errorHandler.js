/**
 * Error Handler Middleware
 * Centralized error handling with logging and proper responses
 */

import { Logger } from '../core/Logger.js';
import { Config } from '../config/environment.js';
import { HTTP_STATUS, ERROR_CODES, ENVIRONMENTS } from '../config/constants.js';

const logger = Logger.getInstance();

/**
 * Application Error Class
 */
export class AppError extends Error {
  constructor(message, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errorCode = ERROR_CODES.INTERNAL_ERROR, details = {}) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Validation Error
 */
export class ValidationError extends AppError {
  constructor(message, details = {}) {
    super(message, HTTP_STATUS.BAD_REQUEST, ERROR_CODES.VALIDATION_ERROR, details);
    this.name = 'ValidationError';
  }
}

/**
 * Authentication Error
 */
export class AuthenticationError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, HTTP_STATUS.UNAUTHORIZED, ERROR_CODES.UNAUTHORIZED);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization Error
 */
export class AuthorizationError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super(message, HTTP_STATUS.FORBIDDEN, ERROR_CODES.FORBIDDEN);
    this.name = 'AuthorizationError';
  }
}

/**
 * Not Found Error
 */
export class NotFoundError extends AppError {
  constructor(resource = 'Resource') {
    super(`${resource} not found`, HTTP_STATUS.NOT_FOUND, ERROR_CODES.NOT_FOUND);
    this.name = 'NotFoundError';
  }
}

/**
 * Database Error
 */
export class DatabaseError extends AppError {
  constructor(message = 'Database operation failed', details = {}) {
    super(message, HTTP_STATUS.INTERNAL_SERVER_ERROR, ERROR_CODES.DATABASE_ERROR, details);
    this.name = 'DatabaseError';
  }
}

/**
 * Rate Limit Error
 */
export class RateLimitError extends AppError {
  constructor(message = 'Too many requests') {
    super(message, HTTP_STATUS.TOO_MANY_REQUESTS, ERROR_CODES.RATE_LIMIT_EXCEEDED);
    this.name = 'RateLimitError';
  }
}

/**
 * Attack Detection Error
 */
export class AttackDetectedError extends AppError {
  constructor(attackType, details = {}) {
    super('Potential security threat detected', HTTP_STATUS.FORBIDDEN, ERROR_CODES.ATTACK_DETECTED, { attackType, ...details });
    this.name = 'AttackDetectedError';
  }
}

/**
 * Main Error Handler Middleware
 */
export const errorHandler = (err, req, res, next) => {
  // Log error
  logError(err, req);

  // Handle specific error types
  if (err.name === 'ValidationError' || err.name === 'CastError') {
    return handleValidationError(err, req, res);
  }

  if (err.name === 'JsonWebTokenError') {
    return handleJWTError(err, req, res);
  }

  if (err.name === 'TokenExpiredError') {
    return handleTokenExpiredError(err, req, res);
  }

  if (err.code === 'ER_DUP_ENTRY') {
    return handleDuplicateError(err, req, res);
  }

  if (err.code === 'ER_BAD_FIELD_ERROR') {
    return handleDatabaseFieldError(err, req, res);
  }

  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    return handleConnectionError(err, req, res);
  }

  if (err.statusCode === HTTP_STATUS.TOO_MANY_REQUESTS) {
    return handleRateLimitError(err, req, res);
  }

  // Handle operational errors
  if (err.isOperational) {
    return res.status(err.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: err.errorCode || ERROR_CODES.INTERNAL_ERROR,
      message: err.message,
      ...(err.details && Object.keys(err.details).length > 0 && { details: err.details }),
      timestamp: err.timestamp || new Date().toISOString(),
      ...(Config.app.env === ENVIRONMENTS.DEVELOPMENT && { stack: err.stack })
    });
  }

  // Handle programming/unknown errors
  return handleUnknownError(err, req, res);
};

/**
 * Log error
 */
function logError(err, req) {
  const errorInfo = {
    message: err.message,
    name: err.name,
    code: err.code || err.errorCode,
    statusCode: err.statusCode,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userId: req.user?.id,
    userAgent: req.get('user-agent'),
    body: sanitizeLogData(req.body),
    query: req.query,
    params: req.params
  };

  if (err.statusCode >= 500 || !err.isOperational) {
    logger.error('Application Error:', {
      ...errorInfo,
      stack: err.stack
    });
  } else if (err.statusCode >= 400) {
    logger.warn('Client Error:', errorInfo);
  } else {
    logger.info('Error:', errorInfo);
  }
}

/**
 * Handle validation errors
 */
function handleValidationError(err, req, res) {
  const errors = extractValidationErrors(err);
  
  logger.warn('Validation error', {
    path: req.path,
    errors
  });

  return res.status(HTTP_STATUS.BAD_REQUEST).json({
    success: false,
    error: ERROR_CODES.VALIDATION_ERROR,
    message: 'Validation failed',
    errors,
    timestamp: new Date().toISOString()
  });
}

/**
 * Handle JWT errors
 */
function handleJWTError(err, req, res) {
  return res.status(HTTP_STATUS.UNAUTHORIZED).json({
    success: false,
    error: ERROR_CODES.INVALID_TOKEN,
    message: 'Invalid authentication token',
    timestamp: new Date().toISOString()
  });
}

/**
 * Handle token expired errors
 */
function handleTokenExpiredError(err, req, res) {
  return res.status(HTTP_STATUS.UNAUTHORIZED).json({
    success: false,
    error: ERROR_CODES.TOKEN_EXPIRED,
    message: 'Authentication token has expired',
    timestamp: new Date().toISOString()
  });
}

/**
 * Handle duplicate entry errors
 */
function handleDuplicateError(err, req, res) {
  const field = extractDuplicateField(err.message);
  
  return res.status(HTTP_STATUS.CONFLICT).json({
    success: false,
    error: ERROR_CODES.DUPLICATE_ENTRY,
    message: `${field} already exists`,
    field,
    timestamp: new Date().toISOString()
  });
}

/**
 * Handle database field errors
 */
function handleDatabaseFieldError(err, req, res) {
  return res.status(HTTP_STATUS.BAD_REQUEST).json({
    success: false,
    error: ERROR_CODES.DATABASE_ERROR,
    message: 'Invalid database field',
    timestamp: new Date().toISOString(),
    ...(Config.app.debug && { details: err.message })
  });
}

/**
 * Handle connection errors
 */
function handleConnectionError(err, req, res) {
  logger.error('Connection error:', err);
  
  return res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
    success: false,
    error: 'SERVICE_UNAVAILABLE',
    message: 'Service temporarily unavailable',
    timestamp: new Date().toISOString()
  });
}

/**
 * Handle rate limit errors
 */
function handleRateLimitError(err, req, res) {
  return res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
    success: false,
    error: ERROR_CODES.RATE_LIMIT_EXCEEDED,
    message: err.message || 'Too many requests. Please try again later.',
    retryAfter: err.retryAfter || 60,
    timestamp: new Date().toISOString()
  });
}

/**
 * Handle unknown errors
 */
function handleUnknownError(err, req, res) {
  logger.error('Unknown error:', err);

  // Don't leak error details in production
  const message = Config.app.env === ENVIRONMENTS.PRODUCTION
    ? 'An unexpected error occurred'
    : err.message;

  return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: ERROR_CODES.INTERNAL_ERROR,
    message,
    timestamp: new Date().toISOString(),
    ...(Config.app.env === ENVIRONMENTS.DEVELOPMENT && { 
      stack: err.stack,
      details: {
        name: err.name,
        code: err.code
      }
    })
  });
}

/**
 * Extract validation errors
 */
function extractValidationErrors(err) {
  if (err.errors) {
    // Mongoose-style validation errors
    return Object.keys(err.errors).map(key => ({
      field: key,
      message: err.errors[key].message
    }));
  }

  if (err.details) {
    // Joi-style validation errors
    return err.details.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message
    }));
  }

  return [{ message: err.message }];
}

/**
 * Extract duplicate field from error message
 */
function extractDuplicateField(message) {
  const match = message.match(/key '(.+?)'/);
  return match ? match[1] : 'field';
}

/**
 * Sanitize data for logging (remove sensitive fields)
 */
function sanitizeLogData(data) {
  if (!data || typeof data !== 'object') return data;

  const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'creditCard', 'ssn'];
  const sanitized = { ...data };

  for (const field of sensitiveFields) {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  }

  return sanitized;
}

/**
 * Async error wrapper
 */
export const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Not Found handler (404)
 */
export const notFoundHandler = (req, res, next) => {
  const error = new NotFoundError(`Route ${req.method} ${req.path}`);
  next(error);
};

/**
 * Unhandled rejection handler
 */
export const setupUnhandledRejectionHandler = () => {
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection:', {
      reason,
      promise
    });

    // In production, might want to restart the process
    if (Config.app.env === ENVIRONMENTS.PRODUCTION) {
      logger.error('Unhandled rejection - Process will restart');
      process.exit(1);
    }
  });
};

/**
 * Uncaught exception handler
 */
export const setupUncaughtExceptionHandler = () => {
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);

    // Always exit on uncaught exception
    logger.error('Uncaught exception - Process will terminate');
    process.exit(1);
  });
};

/**
 * Error response formatter
 */
export const formatErrorResponse = (error) => {
  return {
    success: false,
    error: error.errorCode || ERROR_CODES.INTERNAL_ERROR,
    message: error.message,
    ...(error.details && { details: error.details }),
    timestamp: error.timestamp || new Date().toISOString()
  };
};

/**
 * Create error from status code
 */
export const createError = (statusCode, message, errorCode) => {
  const error = new AppError(message, statusCode, errorCode);
  return error;
};

/**
 * Throw if condition is true
 */
export const throwIf = (condition, error) => {
  if (condition) {
    throw error;
  }
};

/**
 * Assert or throw
 */
export const assert = (condition, message, statusCode = HTTP_STATUS.BAD_REQUEST) => {
  if (!condition) {
    throw new AppError(message, statusCode);
  }
};

export default {
  errorHandler,
  notFoundHandler,
  asyncHandler,
  setupUnhandledRejectionHandler,
  setupUncaughtExceptionHandler,
  formatErrorResponse,
  createError,
  throwIf,
  assert,
  // Error classes
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  DatabaseError,
  RateLimitError,
  AttackDetectedError
};
