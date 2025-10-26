/**
 * Sanitizer Utilities - MILITARY-GRADE Input Sanitization Functions
 * Enterprise-level input cleaning and XSS prevention
 * 
 * @module utils/sanitizers
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - HTML sanitization (XSS prevention)
 * - SQL injection prevention
 * - Command injection prevention
 * - Path traversal prevention
 * - Email sanitization
 * - URL sanitization
 * - Filename sanitization
 * - Phone number sanitization
 * - Credit card sanitization
 * - JSON sanitization
 * - XML sanitization
 * - LDAP injection prevention
 * - NoSQL injection prevention
 * - Whitespace normalization
 * - Unicode normalization
 * - Strip tags
 * - Escape special characters
 * - Remove null bytes
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import sanitizeHtml from 'sanitize-html';
import validator from 'validator';
import xss from 'xss';

// ============================================================================
// HTML SANITIZATION
// ============================================================================

/**
 * Sanitize HTML content (strict mode)
 * @param {string} html - HTML content
 * @param {object} options - Sanitization options
 * @returns {string} Sanitized HTML
 */
export const sanitizeHTML = (html, options = {}) => {
  if (!html || typeof html !== 'string') return '';

  const defaultOptions = {
    allowedTags: [
      'p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre'
    ],
    allowedAttributes: {
      'a': ['href', 'title', 'target'],
      'img': ['src', 'alt', 'title']
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: {
      img: ['http', 'https', 'data']
    },
    disallowedTagsMode: 'discard',
    enforceHtmlBoundary: true
  };

  return sanitizeHtml(html, { ...defaultOptions, ...options });
};

/**
 * Strip all HTML tags
 * @param {string} html - HTML content
 * @returns {string} Plain text
 */
export const stripHTML = (html) => {
  if (!html || typeof html !== 'string') return '';
  
  return sanitizeHtml(html, {
    allowedTags: [],
    allowedAttributes: {}
  });
};

/**
 * Sanitize HTML with XSS library (aggressive filtering)
 * @param {string} html - HTML content
 * @returns {string} Sanitized HTML
 */
export const sanitizeXSS = (html) => {
  if (!html || typeof html !== 'string') return '';
  
  return xss(html, {
    whiteList: {
      p: [],
      br: [],
      strong: [],
      em: [],
      u: [],
      a: ['href', 'title'],
      ul: [],
      ol: [],
      li: []
    },
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
  });
};

/**
 * Escape HTML entities
 * @param {string} str - Input string
 * @returns {string} Escaped string
 */
export const escapeHTML = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;'
  };
  
  return str.replace(/[&<>"'/]/g, char => map[char]);
};

/**
 * Unescape HTML entities
 * @param {string} str - Escaped string
 * @returns {string} Unescaped string
 */
export const unescapeHTML = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  const map = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#x27;': "'",
    '&#x2F;': '/'
  };
  
  return str.replace(/&(?:amp|lt|gt|quot|#x27|#x2F);/g, entity => map[entity]);
};

// ============================================================================
// SQL INJECTION PREVENTION
// ============================================================================

/**
 * Sanitize SQL input (escape special characters)
 * @param {string} input - User input
 * @returns {string} Sanitized input
 */
export const sanitizeSQL = (input) => {
  if (!input || typeof input !== 'string') return '';
  
  // Remove dangerous SQL keywords and characters
  return input
    .replace(/'/g, "''") // Escape single quotes
    .replace(/;/g, '') // Remove semicolons
    .replace(/--/g, '') // Remove SQL comments
    .replace(/\/\*/g, '') // Remove block comment start
    .replace(/\*\//g, '') // Remove block comment end
    .replace(/\bUNION\b/gi, '')
    .replace(/\bSELECT\b/gi, '')
    .replace(/\bINSERT\b/gi, '')
    .replace(/\bUPDATE\b/gi, '')
    .replace(/\bDELETE\b/gi, '')
    .replace(/\bDROP\b/gi, '')
    .replace(/\bEXEC\b/gi, '')
    .replace(/\bEXECUTE\b/gi, '');
};

/**
 * Remove SQL comments
 * @param {string} input - SQL input
 * @returns {string} Cleaned input
 */
export const removeSQLComments = (input) => {
  if (!input || typeof input !== 'string') return '';
  
  return input
    .replace(/--.*$/gm, '') // Single line comments
    .replace(/\/\*[\s\S]*?\*\//g, ''); // Multi-line comments
};

// ============================================================================
// COMMAND INJECTION PREVENTION
// ============================================================================

/**
 * Sanitize shell command input
 * @param {string} input - Command input
 * @returns {string} Sanitized input
 */
export const sanitizeCommand = (input) => {
  if (!input || typeof input !== 'string') return '';
  
  // Remove shell metacharacters
  const dangerousChars = /[;|&$`<>(){}[\]!*?~^\\]/g;
  return input.replace(dangerousChars, '');
};

/**
 * Escape shell arguments
 * @param {string} arg - Shell argument
 * @returns {string} Escaped argument
 */
export const escapeShellArg = (arg) => {
  if (!arg || typeof arg !== 'string') return "''";
  
  // Wrap in single quotes and escape any single quotes
  return "'" + arg.replace(/'/g, "'\\''") + "'";
};

// ============================================================================
// PATH TRAVERSAL PREVENTION
// ============================================================================

/**
 * Sanitize file path (prevent directory traversal)
 * @param {string} path - File path
 * @returns {string} Sanitized path
 */
export const sanitizePath = (path) => {
  if (!path || typeof path !== 'string') return '';
  
  return path
    .replace(/\.\./g, '') // Remove parent directory references
    .replace(/\\/g, '/') // Normalize separators
    .replace(/\/+/g, '/') // Remove duplicate slashes
    .replace(/^\//, ''); // Remove leading slash
};

/**
 * Sanitize filename
 * @param {string} filename - Filename
 * @returns {string} Sanitized filename
 */
export const sanitizeFilename = (filename) => {
  if (!filename || typeof filename !== 'string') return '';
  
  return filename
    .replace(/[^a-zA-Z0-9._-]/g, '_') // Replace invalid chars
    .replace(/\.{2,}/g, '.') // Remove multiple dots
    .replace(/^\./, '') // Remove leading dot
    .substring(0, 255); // Limit length
};

// ============================================================================
// EMAIL SANITIZATION
// ============================================================================

/**
 * Sanitize email address
 * @param {string} email - Email address
 * @returns {string} Sanitized email
 */
export const sanitizeEmail = (email) => {
  if (!email || typeof email !== 'string') return '';
  
  return validator.normalizeEmail(email, {
    all_lowercase: true,
    gmail_remove_dots: false,
    gmail_remove_subaddress: false,
    outlookdotcom_remove_subaddress: false,
    yahoo_remove_subaddress: false,
    icloud_remove_subaddress: false
  }) || '';
};

/**
 * Remove email comments and formatting
 * @param {string} email - Email address
 * @returns {string} Clean email
 */
export const cleanEmail = (email) => {
  if (!email || typeof email !== 'string') return '';
  
  // Extract just the email address (remove display name)
  const match = email.match(/<?([^<>]+)>?$/);
  return match ? match[1].trim().toLowerCase() : email.trim().toLowerCase();
};

// ============================================================================
// URL SANITIZATION
// ============================================================================

/**
 * Sanitize URL
 * @param {string} url - URL string
 * @returns {string} Sanitized URL
 */
export const sanitizeURL = (url) => {
  if (!url || typeof url !== 'string') return '';
  
  try {
    const urlObj = new URL(url);
    
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return '';
    }
    
    return urlObj.toString();
  } catch {
    return '';
  }
};

/**
 * Remove dangerous URL schemes
 * @param {string} url - URL string
 * @returns {string} Safe URL
 */
export const removeDangerousSchemes = (url) => {
  if (!url || typeof url !== 'string') return '';
  
  const dangerousSchemes = [
    'javascript:', 'data:', 'vbscript:', 'file:', 'about:',
    'jar:', 'ftp:', 'sftp:', 'tel:', 'sms:'
  ];
  
  const lowerUrl = url.toLowerCase();
  if (dangerousSchemes.some(scheme => lowerUrl.startsWith(scheme))) {
    return '';
  }
  
  return url;
};

// ============================================================================
// PHONE NUMBER SANITIZATION
// ============================================================================

/**
 * Sanitize phone number (keep only digits and +)
 * @param {string} phone - Phone number
 * @returns {string} Sanitized phone
 */
export const sanitizePhone = (phone) => {
  if (!phone || typeof phone !== 'string') return '';
  
  // Keep only digits, plus sign, and common separators
  return phone.replace(/[^\d+\-() ]/g, '');
};

/**
 * Extract digits from phone number
 * @param {string} phone - Phone number
 * @returns {string} Digits only
 */
export const extractPhoneDigits = (phone) => {
  if (!phone || typeof phone !== 'string') return '';
  
  return phone.replace(/\D/g, '');
};

// ============================================================================
// CREDIT CARD SANITIZATION
// ============================================================================

/**
 * Mask credit card number
 * @param {string} cardNumber - Card number
 * @param {number} visibleDigits - Visible last digits
 * @returns {string} Masked card number
 */
export const maskCreditCard = (cardNumber, visibleDigits = 4) => {
  if (!cardNumber || typeof cardNumber !== 'string') return '';
  
  const cleaned = cardNumber.replace(/\s/g, '');
  const masked = '*'.repeat(cleaned.length - visibleDigits);
  const visible = cleaned.slice(-visibleDigits);
  
  return masked + visible;
};

/**
 * Sanitize credit card input (remove non-digits)
 * @param {string} cardNumber - Card number
 * @returns {string} Sanitized card number
 */
export const sanitizeCreditCard = (cardNumber) => {
  if (!cardNumber || typeof cardNumber !== 'string') return '';
  
  return cardNumber.replace(/\D/g, '');
};

// ============================================================================
// JSON SANITIZATION
// ============================================================================

/**
 * Sanitize JSON string (remove potentially dangerous content)
 * @param {string} jsonStr - JSON string
 * @returns {string} Sanitized JSON
 */
export const sanitizeJSON = (jsonStr) => {
  if (!jsonStr || typeof jsonStr !== 'string') return '';
  
  try {
    const parsed = JSON.parse(jsonStr);
    return JSON.stringify(parsed);
  } catch {
    return '';
  }
};

/**
 * Deep sanitize object (remove dangerous keys)
 * @param {object} obj - Object to sanitize
 * @param {array} dangerousKeys - Keys to remove
 * @returns {object} Sanitized object
 */
export const sanitizeObject = (obj, dangerousKeys = ['__proto__', 'constructor', 'prototype']) => {
  if (typeof obj !== 'object' || obj === null) return obj;
  
  const sanitized = Array.isArray(obj) ? [] : {};
  
  for (const key in obj) {
    if (obj.hasOwnProperty(key) && !dangerousKeys.includes(key)) {
      sanitized[key] = typeof obj[key] === 'object' 
        ? sanitizeObject(obj[key], dangerousKeys)
        : obj[key];
    }
  }
  
  return sanitized;
};

// ============================================================================
// XML SANITIZATION
// ============================================================================

/**
 * Sanitize XML input (prevent XXE attacks)
 * @param {string} xml - XML string
 * @returns {string} Sanitized XML
 */
export const sanitizeXML = (xml) => {
  if (!xml || typeof xml !== 'string') return '';
  
  // Remove DOCTYPE declarations and entity references
  return xml
    .replace(/<!DOCTYPE[^>]*>/gi, '')
    .replace(/<!ENTITY[^>]*>/gi, '')
    .replace(/&[a-zA-Z0-9]+;/g, '');
};

// ============================================================================
// LDAP INJECTION PREVENTION
// ============================================================================

/**
 * Sanitize LDAP filter input
 * @param {string} input - LDAP input
 * @returns {string} Sanitized input
 */
export const sanitizeLDAP = (input) => {
  if (!input || typeof input !== 'string') return '';
  
  const escapeMap = {
    '\\': '\\5c',
    '*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '\0': '\\00'
  };
  
  return input.replace(/[\\*()\0]/g, char => escapeMap[char]);
};

// ============================================================================
// NOSQL INJECTION PREVENTION
// ============================================================================

/**
 * Sanitize MongoDB query input
 * @param {*} input - Query input
 * @returns {*} Sanitized input
 */
export const sanitizeMongoDB = (input) => {
  if (typeof input === 'object' && input !== null) {
    // Remove operators that start with $
    const sanitized = {};
    for (const key in input) {
      if (input.hasOwnProperty(key) && !key.startsWith('$')) {
        sanitized[key] = sanitizeMongoDB(input[key]);
      }
    }
    return sanitized;
  }
  
  return input;
};

// ============================================================================
// WHITESPACE NORMALIZATION
// ============================================================================

/**
 * Normalize whitespace
 * @param {string} str - Input string
 * @returns {string} Normalized string
 */
export const normalizeWhitespace = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str
    .replace(/\s+/g, ' ') // Replace multiple spaces with single
    .trim(); // Remove leading/trailing
};

/**
 * Remove all whitespace
 * @param {string} str - Input string
 * @returns {string} String without whitespace
 */
export const removeWhitespace = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/\s/g, '');
};

/**
 * Normalize line breaks
 * @param {string} str - Input string
 * @param {string} replacement - Line break replacement
 * @returns {string} Normalized string
 */
export const normalizeLineBreaks = (str, replacement = '\n') => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/\r\n|\r|\n/g, replacement);
};

// ============================================================================
// UNICODE NORMALIZATION
// ============================================================================

/**
 * Normalize Unicode string
 * @param {string} str - Input string
 * @param {string} form - Normalization form (NFC, NFD, NFKC, NFKD)
 * @returns {string} Normalized string
 */
export const normalizeUnicode = (str, form = 'NFC') => {
  if (!str || typeof str !== 'string') return '';
  
  return str.normalize(form);
};

/**
 * Remove zero-width characters
 * @param {string} str - Input string
 * @returns {string} Cleaned string
 */
export const removeZeroWidthChars = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/[\u200B-\u200D\uFEFF]/g, '');
};

/**
 * Remove control characters
 * @param {string} str - Input string
 * @returns {string} Cleaned string
 */
export const removeControlChars = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
};

// ============================================================================
// SPECIAL CHARACTER HANDLING
// ============================================================================

/**
 * Remove null bytes
 * @param {string} str - Input string
 * @returns {string} Cleaned string
 */
export const removeNullBytes = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/\0/g, '');
};

/**
 * Escape regular expression special characters
 * @param {string} str - Input string
 * @returns {string} Escaped string
 */
export const escapeRegex = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};

/**
 * Remove dangerous characters
 * @param {string} str - Input string
 * @returns {string} Cleaned string
 */
export const removeDangerousChars = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str.replace(/[<>'"`;(){}[\]\\|&$]/g, '');
};

// ============================================================================
// COMPOSITE SANITIZATION
// ============================================================================

/**
 * Apply multiple sanitizers
 * @param {string} input - Input string
 * @param {array} sanitizers - Array of sanitizer functions
 * @returns {string} Sanitized string
 */
export const applySanitizers = (input, sanitizers = []) => {
  return sanitizers.reduce((result, sanitizer) => sanitizer(result), input);
};

/**
 * Deep sanitize object recursively
 * @param {*} obj - Object to sanitize
 * @param {function} sanitizer - Sanitizer function for strings
 * @returns {*} Sanitized object
 */
export const deepSanitize = (obj, sanitizer = stripHTML) => {
  if (typeof obj === 'string') {
    return sanitizer(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => deepSanitize(item, sanitizer));
  }
  
  if (typeof obj === 'object' && obj !== null) {
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        sanitized[key] = deepSanitize(obj[key], sanitizer);
      }
    }
    return sanitized;
  }
  
  return obj;
};

/**
 * Sanitize for logging (remove sensitive data)
 * @param {string} str - Input string
 * @returns {string} Safe for logging
 */
export const sanitizeForLogging = (str) => {
  if (!str || typeof str !== 'string') return '';
  
  return str
    .replace(/password[=:]\s*\S+/gi, 'password=***')
    .replace(/token[=:]\s*\S+/gi, 'token=***')
    .replace(/api[_-]?key[=:]\s*\S+/gi, 'api_key=***')
    .replace(/secret[=:]\s*\S+/gi, 'secret=***')
    .replace(/\b\d{13,19}\b/g, '****-****-****-****'); // Credit cards
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // HTML
  sanitizeHTML,
  stripHTML,
  sanitizeXSS,
  escapeHTML,
  unescapeHTML,
  
  // SQL
  sanitizeSQL,
  removeSQLComments,
  
  // Command
  sanitizeCommand,
  escapeShellArg,
  
  // Path
  sanitizePath,
  sanitizeFilename,
  
  // Email
  sanitizeEmail,
  cleanEmail,
  
  // URL
  sanitizeURL,
  removeDangerousSchemes,
  
  // Phone
  sanitizePhone,
  extractPhoneDigits,
  
  // Credit Card
  maskCreditCard,
  sanitizeCreditCard,
  
  // JSON
  sanitizeJSON,
  sanitizeObject,
  
  // XML
  sanitizeXML,
  
  // LDAP
  sanitizeLDAP,
  
  // NoSQL
  sanitizeMongoDB,
  
  // Whitespace
  normalizeWhitespace,
  removeWhitespace,
  normalizeLineBreaks,
  
  // Unicode
  normalizeUnicode,
  removeZeroWidthChars,
  removeControlChars,
  
  // Special
  removeNullBytes,
  escapeRegex,
  removeDangerousChars,
  
  // Composite
  applySanitizers,
  deepSanitize,
  sanitizeForLogging
};
