/**
 * Sanitization Middleware
 * Input sanitization and XSS prevention
 */

import sanitizeHtml from 'sanitize-html';
import xss from 'xss';
import validator from 'validator';
import { Logger } from '../core/Logger.js';
import { securityMode, validationConfig } from '../config/security.js';

const logger = Logger.getInstance();

/**
 * Main sanitization middleware
 */
export const sanitizationMiddleware = (req, res, next) => {
  // Skip if in vulnerable mode
  if (securityMode.isVulnerable || !validationConfig.enabled) {
    return next();
  }

  try {
    // Sanitize query parameters
    if (req.query && Object.keys(req.query).length > 0) {
      req.query = sanitizeObject(req.query);
      logger.debug('Query parameters sanitized', { path: req.path });
    }

    // Sanitize body
    if (req.body && Object.keys(req.body).length > 0) {
      req.body = sanitizeObject(req.body);
      logger.debug('Request body sanitized', { path: req.path });
    }

    // Sanitize params
    if (req.params && Object.keys(req.params).length > 0) {
      req.params = sanitizeObject(req.params);
      logger.debug('Route params sanitized', { path: req.path });
    }

    next();
  } catch (error) {
    logger.error('Sanitization error:', error);
    next(); // Continue even if sanitization fails
  }
};

/**
 * Sanitize object recursively
 */
function sanitizeObject(obj, depth = 0) {
  // Prevent deep recursion
  if (depth > 10) {
    logger.warn('Max sanitization depth reached');
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, depth + 1));
  }

  if (obj !== null && typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value, depth + 1);
    }
    return sanitized;
  }

  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }

  return obj;
}

/**
 * Sanitize string value
 */
function sanitizeString(str) {
  if (!validationConfig.sanitization) {
    return str;
  }

  let sanitized = str;

  // Trim whitespace
  if (validationConfig.sanitization.trim) {
    sanitized = sanitized.trim();
  }

  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, '');

  // XSS prevention
  if (validationConfig.sanitization.escape) {
    sanitized = xss(sanitized);
  }

  // Strip HTML tags (optional, based on context)
  if (validationConfig.sanitization.stripTags) {
    sanitized = validator.stripLow(sanitized);
  }

  return sanitized;
}

/**
 * HTML sanitizer (for rich text)
 */
export const sanitizeHTML = (html, options = {}) => {
  const defaultOptions = {
    allowedTags: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'p', 'br', 'hr',
      'strong', 'em', 'u', 's', 'code', 'pre',
      'ul', 'ol', 'li',
      'a', 'img',
      'blockquote'
    ],
    allowedAttributes: {
      'a': ['href', 'title', 'target'],
      'img': ['src', 'alt', 'title', 'width', 'height']
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: {
      'a': ['http', 'https', 'mailto']
    },
    selfClosing: ['img', 'br', 'hr'],
    allowedIframeHostnames: [],
    transformTags: {
      'a': (tagName, attribs) => {
        // Add rel="noopener noreferrer" to all links
        return {
          tagName: 'a',
          attribs: {
            ...attribs,
            rel: 'noopener noreferrer',
            target: '_blank'
          }
        };
      }
    }
  };

  const finalOptions = { ...defaultOptions, ...options };

  return sanitizeHtml(html, finalOptions);
};

/**
 * Strict HTML sanitizer (no HTML allowed)
 */
export const stripHTML = (str) => {
  return sanitizeHtml(str, {
    allowedTags: [],
    allowedAttributes: {}
  });
};

/**
 * Sanitize email
 */
export const sanitizeEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return '';
  }

  let sanitized = email.trim().toLowerCase();

  if (validationConfig.sanitization.normalizeEmail) {
    sanitized = validator.normalizeEmail(sanitized) || sanitized;
  }

  // Remove any non-email characters
  sanitized = sanitized.replace(/[^a-z0-9@._+-]/gi, '');

  return sanitized;
};

/**
 * Sanitize URL
 */
export const sanitizeURL = (url) => {
  if (!url || typeof url !== 'string') {
    return '';
  }

  let sanitized = url.trim();

  // Check if valid URL
  if (!validator.isURL(sanitized, {
    protocols: ['http', 'https'],
    require_protocol: true
  })) {
    return '';
  }

  // Encode special characters
  try {
    const urlObj = new URL(sanitized);
    return urlObj.href;
  } catch (error) {
    logger.warn('Invalid URL:', url);
    return '';
  }
};

/**
 * Sanitize filename
 */
export const sanitizeFilename = (filename) => {
  if (!filename || typeof filename !== 'string') {
    return '';
  }

  let sanitized = filename.trim();

  // Remove path separators
  sanitized = sanitized.replace(/[\/\\]/g, '');

  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, '');

  // Remove special characters
  sanitized = sanitized.replace(/[^\w\s.-]/g, '');

  // Limit length
  if (sanitized.length > 255) {
    const ext = sanitized.split('.').pop();
    const name = sanitized.substring(0, 255 - ext.length - 1);
    sanitized = `${name}.${ext}`;
  }

  return sanitized;
};

/**
 * Sanitize SQL (basic - should use parameterized queries instead)
 */
export const sanitizeSQL = (input) => {
  if (!input || typeof input !== 'string') {
    return input;
  }

  // Remove SQL keywords and dangerous characters
  let sanitized = input;

  // Remove comments
  sanitized = sanitized.replace(/--/g, '');
  sanitized = sanitized.replace(/\/\*.*?\*\//g, '');

  // Remove dangerous keywords
  const dangerousKeywords = [
    'DROP', 'DELETE', 'TRUNCATE', 'ALTER',
    'EXEC', 'EXECUTE', 'UNION', 'INSERT',
    'UPDATE', 'CREATE', 'GRANT', 'REVOKE'
  ];

  for (const keyword of dangerousKeywords) {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
    sanitized = sanitized.replace(regex, '');
  }

  return sanitized;
};

/**
 * Sanitize JSON
 */
export const sanitizeJSON = (json) => {
  try {
    if (typeof json === 'string') {
      json = JSON.parse(json);
    }
    return sanitizeObject(json);
  } catch (error) {
    logger.error('JSON sanitization error:', error);
    return null;
  }
};

/**
 * Remove dangerous characters
 */
export const removeDangerousChars = (str) => {
  if (typeof str !== 'string') {
    return str;
  }

  // Remove null bytes
  let sanitized = str.replace(/\0/g, '');

  // Remove control characters
  sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');

  return sanitized;
};

/**
 * Escape special characters for regex
 */
export const escapeRegex = (str) => {
  if (typeof str !== 'string') {
    return str;
  }
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\    allowedSchemes: ['http', 'https',');
};

/**
 * Sanitize phone number
 */
export const sanitizePhone = (phone) => {
  if (!phone || typeof phone !== 'string') {
    return '';
  }

  // Remove all non-numeric characters except + at start
  let sanitized = phone.trim();
  sanitized = sanitized.replace(/[^\d+]/g, '');

  // Ensure + is only at the start
  if (sanitized.includes('+')) {
    const plus = sanitized[0] === '+' ? '+' : '';
    sanitized = plus + sanitized.replace(/\+/g, '');
  }

  return sanitized;
};

/**
 * Sanitize credit card number
 */
export const sanitizeCreditCard = (cardNumber) => {
  if (!cardNumber || typeof cardNumber !== 'string') {
    return '';
  }

  // Remove all non-numeric characters
  return cardNumber.replace(/\D/g, '');
};

/**
 * Sanitize for XML
 */
export const sanitizeXML = (str) => {
  if (typeof str !== 'string') {
    return str;
  }

  const xmlEscapeMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&apos;'
  };

  return str.replace(/[&<>"']/g, char => xmlEscapeMap[char]);
};

/**
 * Sanitize for LDAP
 */
export const sanitizeLDAP = (str) => {
  if (typeof str !== 'string') {
    return str;
  }

  // Escape LDAP special characters
  const ldapEscapeMap = {
    '*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '\\': '\\5c',
    '\0': '\\00',
    '/': '\\2f'
  };

  return str.replace(/[*()\\\0\/]/g, char => ldapEscapeMap[char]);
};

/**
 * Sanitize command line arguments
 */
export const sanitizeCommand = (str) => {
  if (typeof str !== 'string') {
    return str;
  }

  // Remove shell metacharacters
  return str.replace(/[;&|`$(){}[\]<>]/g, '');
};

/**
 * Sanitize MongoDB query
 */
export const sanitizeMongoDB = (query) => {
  if (typeof query !== 'object' || query === null) {
    return query;
  }

  const sanitized = {};

  for (const [key, value] of Object.entries(query)) {
    // Remove $ operators (to prevent NoSQL injection)
    if (key.startsWith(')) {
      continue;
    }

    if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeMongoDB(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

/**
 * Content-specific sanitizers
 */
export const sanitizers = {
  username: (str) => {
    if (typeof str !== 'string') return '';
    return str.trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, '')
      .substring(0, validationConfig.maxLengths.username);
  },

  name: (str) => {
    if (typeof str !== 'string') return '';
    return str.trim()
      .replace(/[^a-zA-Z\s'-]/g, '')
      .substring(0, validationConfig.maxLengths.name);
  },

  description: (str) => {
    if (typeof str !== 'string') return '';
    return sanitizeHTML(str).substring(0, validationConfig.maxLengths.description);
  },

  comment: (str) => {
    if (typeof str !== 'string') return '';
    return sanitizeHTML(str).substring(0, validationConfig.maxLengths.comment);
  },

  slug: (str) => {
    if (typeof str !== 'string') return '';
    return str.trim()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  },

  zipCode: (str) => {
    if (typeof str !== 'string') return '';
    return str.trim()
      .replace(/[^0-9-]/g, '')
      .substring(0, validationConfig.maxLengths.zipCode);
  }
};

/**
 * Sanitization middleware for specific fields
 */
export const sanitizeFields = (fieldsMap) => {
  return (req, res, next) => {
    if (securityMode.isVulnerable) {
      return next();
    }

    try {
      for (const [field, sanitizer] of Object.entries(fieldsMap)) {
        if (req.body && req.body[field] !== undefined) {
          req.body[field] = sanitizer(req.body[field]);
        }
        if (req.query && req.query[field] !== undefined) {
          req.query[field] = sanitizer(req.query[field]);
        }
      }
      next();
    } catch (error) {
      logger.error('Field sanitization error:', error);
      next();
    }
  };
};

/**
 * Sanitize file upload metadata
 */
export const sanitizeFileMetadata = (file) => {
  if (!file) return file;

  return {
    ...file,
    originalname: sanitizeFilename(file.originalname),
    filename: sanitizeFilename(file.filename),
    mimetype: file.mimetype.replace(/[^a-z0-9\/.-]/gi, '')
  };
};

/**
 * Remove sensitive data before logging
 */
export const sanitizeForLogging = (data) => {
  if (!data || typeof data !== 'object') {
    return data;
  }

  const sensitiveFields = [
    'password', 'token', 'secret', 'apiKey', 'api_key',
    'creditCard', 'credit_card', 'ssn', 'authorization',
    'cookie', 'sessionId', 'session_id'
  ];

  const sanitized = Array.isArray(data) ? [] : {};

  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    
    if (sensitiveFields.some(field => lowerKey.includes(field.toLowerCase()))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeForLogging(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

/**
 * Batch sanitize array of objects
 */
export const sanitizeBatch = (items, sanitizer) => {
  if (!Array.isArray(items)) {
    return items;
  }

  return items.map(item => sanitizer(item));
};

/**
 * Skip sanitization for specific routes
 */
export const skipSanitization = (req, res, next) => {
  req.skipSanitization = true;
  next();
};

/**
 * Conditional sanitization
 */
export const sanitizeIf = (condition) => {
  return (req, res, next) => {
    if (req.skipSanitization || !condition(req)) {
      return next();
    }
    sanitizationMiddleware(req, res, next);
  };
};

/**
 * Get sanitization statistics
 */
export const getSanitizationStats = () => {
  return {
    enabled: validationConfig.enabled && !securityMode.isVulnerable,
    mode: securityMode.current,
    settings: {
      stripTags: validationConfig.sanitization.stripTags,
      trim: validationConfig.sanitization.trim,
      escape: validationConfig.sanitization.escape,
      normalizeEmail: validationConfig.sanitization.normalizeEmail
    }
  };
};

export default {
  sanitizationMiddleware,
  sanitizeHTML,
  stripHTML,
  sanitizeEmail,
  sanitizeURL,
  sanitizeFilename,
  sanitizeSQL,
  sanitizeJSON,
  removeDangerousChars,
  escapeRegex,
  sanitizePhone,
  sanitizeCreditCard,
  sanitizeXML,
  sanitizeLDAP,
  sanitizeCommand,
  sanitizeMongoDB,
  sanitizers,
  sanitizeFields,
  sanitizeFileMetadata,
  sanitizeForLogging,
  sanitizeBatch,
  skipSanitization,
  sanitizeIf,
  getSanitizationStats
};
