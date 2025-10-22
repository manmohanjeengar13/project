/**
 * Validation Middleware
 * Comprehensive input validation with multiple validation libraries
 */

import { body, param, query, validationResult } from 'express-validator';
import Joi from 'joi';
import validator from 'validator';
import { Logger } from '../core/Logger.js';
import { validationConfig, securityMode } from '../config/security.js';
import { REGEX, HTTP_STATUS, ERROR_CODES } from '../config/constants.js';
import { ValidationError } from './errorHandler.js';

const logger = Logger.getInstance();

/**
 * Validation result handler
 */
export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map(err => ({
      field: err.path || err.param,
      message: err.msg,
      value: err.value
    }));

    logger.warn('Validation failed', {
      path: req.path,
      errors: formattedErrors,
      ip: req.ip
    });

    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: ERROR_CODES.VALIDATION_ERROR,
      message: 'Validation failed',
      errors: formattedErrors
    });
  }

  next();
};

/**
 * Joi schema validator middleware
 */
export const validateSchema = (schema, source = 'body') => {
  return (req, res, next) => {
    // Skip validation in vulnerable mode
    if (securityMode.isVulnerable || !validationConfig.enabled) {
      return next();
    }

    const dataToValidate = req[source];
    
    const { error, value } = schema.validate(dataToValidate, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        type: detail.type
      }));

      logger.warn('Joi validation failed', {
        path: req.path,
        source,
        errors
      });

      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Validation failed',
        errors
      });
    }

    // Replace with validated data
    req[source] = value;
    next();
  };
};

/**
 * Custom validator wrapper
 */
export const validate = (validators) => {
  return [
    ...validators,
    handleValidationErrors
  ];
};

/**
 * Common validation schemas
 */
export const schemas = {
  // User Registration
  register: Joi.object({
    username: Joi.string()
      .min(validationConfig.maxLengths.username || 3)
      .max(validationConfig.maxLengths.username || 50)
      .pattern(validationConfig.patterns.username)
      .required()
      .messages({
        'string.pattern.base': 'Username can only contain letters, numbers, underscores and hyphens',
        'string.min': 'Username must be at least 3 characters',
        'string.max': 'Username must not exceed 50 characters'
      }),
    
    email: Joi.string()
      .email()
      .max(validationConfig.maxLengths.email || 100)
      .required()
      .messages({
        'string.email': 'Please provide a valid email address'
      }),
    
    password: Joi.string()
      .min(Config.auth?.passwordMinLength || 8)
      .max(validationConfig.maxLengths.password || 255)
      .pattern(validationConfig.patterns.password || /.+/)
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters',
        'string.pattern.base': 'Password must contain uppercase, lowercase, number and special character'
      }),
    
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({
        'any.only': 'Passwords do not match'
      }),

    firstName: Joi.string()
      .max(validationConfig.maxLengths.name || 100)
      .optional(),
    
    lastName: Joi.string()
      .max(validationConfig.maxLengths.name || 100)
      .optional()
  }),

  // User Login
  login: Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
    rememberMe: Joi.boolean().optional()
  }),

  // Update Profile
  updateProfile: Joi.object({
    firstName: Joi.string()
      .max(validationConfig.maxLengths.name || 100)
      .optional(),
    
    lastName: Joi.string()
      .max(validationConfig.maxLengths.name || 100)
      .optional(),
    
    email: Joi.string()
      .email()
      .max(validationConfig.maxLengths.email || 100)
      .optional(),
    
    phone: Joi.string()
      .pattern(validationConfig.patterns.phone)
      .max(validationConfig.maxLengths.phone || 20)
      .optional(),
    
    address: Joi.string()
      .max(validationConfig.maxLengths.address || 500)
      .optional()
  }),

  // Change Password
  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string()
      .min(Config.auth?.passwordMinLength || 8)
      .required(),
    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
  }),

  // Create Product
  createProduct: Joi.object({
    name: Joi.string()
      .min(3)
      .max(200)
      .required(),
    
    description: Joi.string()
      .max(validationConfig.maxLengths.description || 5000)
      .required(),
    
    price: Joi.number()
      .positive()
      .precision(2)
      .required(),
    
    stock: Joi.number()
      .integer()
      .min(0)
      .required(),
    
    category_id: Joi.number()
      .integer()
      .positive()
      .required(),
    
    sku: Joi.string()
      .max(50)
      .optional(),
    
    images: Joi.array()
      .items(Joi.string().uri())
      .optional()
  }),

  // Create Order
  createOrder: Joi.object({
    items: Joi.array()
      .items(Joi.object({
        product_id: Joi.number().integer().positive().required(),
        quantity: Joi.number().integer().positive().required(),
        price: Joi.number().positive().precision(2).required()
      }))
      .min(1)
      .required(),
    
    shipping_address: Joi.string()
      .max(validationConfig.maxLengths.address || 500)
      .required(),
    
    payment_method: Joi.string()
      .valid('credit_card', 'debit_card', 'paypal', 'cash_on_delivery')
      .required(),
    
    coupon_code: Joi.string()
      .max(50)
      .optional()
  }),

  // Create Review
  createReview: Joi.object({
    product_id: Joi.number()
      .integer()
      .positive()
      .required(),
    
    rating: Joi.number()
      .integer()
      .min(1)
      .max(5)
      .required(),
    
    title: Joi.string()
      .max(200)
      .required(),
    
    comment: Joi.string()
      .max(validationConfig.maxLengths.comment || 2000)
      .required()
  }),

  // ID Parameter
  id: Joi.object({
    id: Joi.number()
      .integer()
      .positive()
      .required()
  }),

  // Pagination
  pagination: Joi.object({
    page: Joi.number()
      .integer()
      .min(1)
      .default(1),
    
    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .default(20),
    
    sortBy: Joi.string()
      .optional(),
    
    sortOrder: Joi.string()
      .valid('ASC', 'DESC', 'asc', 'desc')
      .default('ASC')
  }),

  // Search Query
  search: Joi.object({
    q: Joi.string()
      .min(1)
      .max(200)
      .required(),
    
    category: Joi.string()
      .optional(),
    
    minPrice: Joi.number()
      .positive()
      .optional(),
    
    maxPrice: Joi.number()
      .positive()
      .optional()
  })
};

/**
 * Express-validator rules
 */
export const rules = {
  // Registration rules
  register: [
    body('username')
      .trim()
      .isLength({ min: 3, max: 50 })
      .matches(REGEX.USERNAME)
      .withMessage('Invalid username format'),
    
    body('email')
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage('Invalid email address'),
    
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters'),
    
    body('confirmPassword')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match')
  ],

  // Login rules
  login: [
    body('username')
      .trim()
      .notEmpty()
      .withMessage('Username is required'),
    
    body('password')
      .notEmpty()
      .withMessage('Password is required')
  ],

  // Email rules
  email: [
    body('email')
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage('Invalid email address')
  ],

  // ID parameter
  id: [
    param('id')
      .isInt({ min: 1 })
      .withMessage('Invalid ID')
  ],

  // Pagination query
  pagination: [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100')
  ]
};

/**
 * Custom validators
 */
export const customValidators = {
  // Check if email exists
  emailExists: async (email) => {
    const { Database } = await import('../core/Database.js');
    const db = Database.getInstance();
    
    const [users] = await db.execute(
      'SELECT id FROM users WHERE email = ? LIMIT 1',
      [email]
    );
    
    if (users.length > 0) {
      throw new Error('Email already exists');
    }
    return true;
  },

  // Check if username exists
  usernameExists: async (username) => {
    const { Database } = await import('../core/Database.js');
    const db = Database.getInstance();
    
    const [users] = await db.execute(
      'SELECT id FROM users WHERE username = ? LIMIT 1',
      [username]
    );
    
    if (users.length > 0) {
      throw new Error('Username already exists');
    }
    return true;
  },

  // Strong password
  isStrongPassword: (password) => {
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
      throw new Error('Password must contain uppercase, lowercase, number and special character');
    }
    return true;
  },

  // Valid phone number
  isValidPhone: (phone) => {
    if (!REGEX.PHONE.test(phone)) {
      throw new Error('Invalid phone number format');
    }
    return true;
  },

  // Valid URL
  isValidURL: (url) => {
    if (!validator.isURL(url, { protocols: ['http', 'https'], require_protocol: true })) {
      throw new Error('Invalid URL format');
    }
    return true;
  },

  // Future date
  isFutureDate: (date) => {
    const inputDate = new Date(date);
    const now = new Date();
    
    if (inputDate <= now) {
      throw new Error('Date must be in the future');
    }
    return true;
  },

  // Past date
  isPastDate: (date) => {
    const inputDate = new Date(date);
    const now = new Date();
    
    if (inputDate >= now) {
      throw new Error('Date must be in the past');
    }
    return true;
  }
};

/**
 * Validate with custom function
 */
export const validateWith = (validatorFn) => {
  return (req, res, next) => {
    if (securityMode.isVulnerable || !validationConfig.enabled) {
      return next();
    }

    try {
      const result = validatorFn(req);
      
      if (result === true) {
        return next();
      }

      if (result && result.errors) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: ERROR_CODES.VALIDATION_ERROR,
          message: 'Validation failed',
          errors: result.errors
        });
      }

      next();
    } catch (error) {
      logger.error('Custom validation error:', error);
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: error.message
      });
    }
  };
};

/**
 * Validate field length
 */
export const validateLength = (field, min, max, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} is required`
      });
    }

    const length = typeof value === 'string' ? value.length : String(value).length;
    
    if (length < min || length > max) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be between ${min} and ${max} characters`
      });
    }

    next();
  };
};

/**
 * Validate required fields
 */
export const validateRequired = (...fields) => {
  return (req, res, next) => {
    const missing = [];
    
    for (const field of fields) {
      if (!req.body || req.body[field] === undefined || req.body[field] === null || req.body[field] === '') {
        missing.push(field);
      }
    }

    if (missing.length > 0) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Missing required fields',
        missing
      });
    }

    next();
  };
};

/**
 * Validate type
 */
export const validateType = (field, type, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (value === undefined || value === null) {
      return next();
    }

    const actualType = typeof value;
    
    if (actualType !== type) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be of type ${type}`
      });
    }

    next();
  };
};

/**
 * Validate enum
 */
export const validateEnum = (field, allowedValues, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (value === undefined || value === null) {
      return next();
    }

    if (!allowedValues.includes(value)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be one of: ${allowedValues.join(', ')}`,
        allowedValues
      });
    }

    next();
  };
};

/**
 * Validate range
 */
export const validateRange = (field, min, max, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (value === undefined || value === null) {
      return next();
    }

    const numValue = Number(value);
    
    if (isNaN(numValue)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be a number`
      });
    }

    if (numValue < min || numValue > max) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be between ${min} and ${max}`
      });
    }

    next();
  };
};

/**
 * Validate pattern
 */
export const validatePattern = (field, pattern, message, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (value === undefined || value === null) {
      return next();
    }

    if (!pattern.test(String(value))) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: message || `${field} has invalid format`
      });
    }

    next();
  };
};

/**
 * Validate array
 */
export const validateArray = (field, minLength, maxLength, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!Array.isArray(value)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be an array`
      });
    }

    if (minLength && value.length < minLength) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must contain at least ${minLength} items`
      });
    }

    if (maxLength && value.length > maxLength) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must contain at most ${maxLength} items`
      });
    }

    next();
  };
};

/**
 * Validate unique array
 */
export const validateUniqueArray = (field, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!Array.isArray(value)) {
      return next();
    }

    const unique = new Set(value);
    
    if (unique.size !== value.length) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must contain unique values`
      });
    }

    next();
  };
};

/**
 * Validate date format
 */
export const validateDate = (field, format = 'YYYY-MM-DD', source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (value === undefined || value === null) {
      return next();
    }

    if (!validator.isDate(String(value))) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be a valid date`
      });
    }

    next();
  };
};

/**
 * Validate file upload
 */
export const validateFile = (options = {}) => {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB
    allowedTypes = ['image/jpeg', 'image/png', 'image/gif'],
    required = false
  } = options;

  return (req, res, next) => {
    if (!req.file && !req.files) {
      if (required) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: ERROR_CODES.VALIDATION_ERROR,
          message: 'File is required'
        });
      }
      return next();
    }

    const files = req.files || [req.file];

    for (const file of files) {
      // Check file size
      if (file.size > maxSize) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: ERROR_CODES.VALIDATION_ERROR,
          message: `File size exceeds maximum allowed size of ${maxSize / (1024 * 1024)}MB`
        });
      }

      // Check file type
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: ERROR_CODES.VALIDATION_ERROR,
          message: `File type not allowed. Allowed types: ${allowedTypes.join(', ')}`
        });
      }
    }

    next();
  };
};

/**
 * Validate JSON structure
 */
export const validateJSON = (field, schema, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (value === undefined || value === null) {
      return next();
    }

    let jsonData;
    
    try {
      jsonData = typeof value === 'string' ? JSON.parse(value) : value;
    } catch (error) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `${field} must be valid JSON`
      });
    }

    if (schema) {
      const { error } = schema.validate(jsonData);
      
      if (error) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: ERROR_CODES.VALIDATION_ERROR,
          message: `${field} JSON validation failed`,
          details: error.details
        });
      }
    }

    req[source][field] = jsonData;
    next();
  };
};

/**
 * Conditional validation
 */
export const validateIf = (condition, validators) => {
  return (req, res, next) => {
    if (condition(req)) {
      return validate(validators)(req, res, next);
    }
    next();
  };
};

/**
 * Skip validation
 */
export const skipValidation = (req, res, next) => {
  req.skipValidation = true;
  next();
};

/**
 * Validate or skip in vulnerable mode
 */
export const validateUnlessVulnerable = (validators) => {
  return (req, res, next) => {
    if (securityMode.isVulnerable || !validationConfig.enabled) {
      return next();
    }
    return validate(validators)(req, res, next);
  };
};

/**
 * Batch validate multiple schemas
 */
export const validateMultiple = (...validators) => {
  return async (req, res, next) => {
    for (const validator of validators) {
      const error = await new Promise((resolve) => {
        validator(req, res, (err) => resolve(err));
      });

      if (error) {
        return next(error);
      }
    }
    next();
  };
};

/**
 * Get validation statistics
 */
export const getValidationStats = () => {
  return {
    enabled: validationConfig.enabled && !securityMode.isVulnerable,
    mode: securityMode.current,
    maxLengths: validationConfig.maxLengths,
    patterns: Object.keys(validationConfig.patterns || {})
  };
};

/**
 * Validate credit card
 */
export const validateCreditCard = (field, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isCreditCard(String(value))) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Invalid credit card number'
      });
    }

    next();
  };
};

/**
 * Validate postal code
 */
export const validatePostalCode = (field, locale = 'any', source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isPostalCode(String(value), locale)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Invalid postal code'
      });
    }

    next();
  };
};

/**
 * Validate IP address
 */
export const validateIP = (field, version = 4, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isIP(String(value), version)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: `Invalid IPv${version} address`
      });
    }

    next();
  };
};

/**
 * Validate MAC address
 */
export const validateMAC = (field, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isMACAddress(String(value))) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Invalid MAC address'
      });
    }

    next();
  };
};

/**
 * Validate UUID
 */
export const validateUUID = (field, version = 'all', source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isUUID(String(value), version)) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Invalid UUID'
      });
    }

    next();
  };
};

/**
 * Validate hex color
 */
export const validateHexColor = (field, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isHexColor(String(value))) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Invalid hex color'
      });
    }

    next();
  };
};

/**
 * Validate MongoDB ObjectId
 */
export const validateObjectId = (field, source = 'body') => {
  return (req, res, next) => {
    const value = req[source]?.[field];
    
    if (!value) {
      return next();
    }

    if (!validator.isMongoId(String(value))) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'Invalid ObjectId'
      });
    }

    next();
  };
};

export default {
  handleValidationErrors,
  validateSchema,
  validate,
  schemas,
  rules,
  customValidators,
  validateWith,
  validateLength,
  validateRequired,
  validateType,
  validateEnum,
  validateRange,
  validatePattern,
  validateArray,
  validateUniqueArray,
  validateDate,
  validateFile,
  validateJSON,
  validateIf,
  skipValidation,
  validateUnlessVulnerable,
  validateMultiple,
  getValidationStats,
  validateCreditCard,
  validatePostalCode,
  validateIP,
  validateMAC,
  validateUUID,
  validateHexColor,
  validateObjectId
};
