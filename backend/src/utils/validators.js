/**
 * Validator Utilities - MILITARY-GRADE Validation Functions
 * Enterprise-level input validation with comprehensive checks
 * 
 * @module utils/validators
 * @version 3.0.1
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - Email validation (RFC 5322 compliant)
 * - Phone number validation (international)
 * - URL validation
 * - IP address validation (IPv4, IPv6)
 * - Credit card validation (Luhn algorithm)
 * - Password strength validation
 * - Username validation
 * - File validation
 * - Date validation
 * - Postal code validation
 * - Social security number validation
 * - IBAN validation
 * - VAT number validation
 * - MAC address validation
 * - UUID validation
 * - JSON validation
 * - Base64 validation
 * - Hex color validation
 * - MongoDB ObjectId validation
 * - SQL injection detection
 * - XSS detection
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import validator from 'validator';

// ============================================================================
// EMAIL VALIDATION
// ============================================================================

/**
 * Validate email address (RFC 5322)
 * @param {string} email - Email address
 * @param {object} options - Validation options
 * @returns {boolean} Is valid
 */
export const isValidEmail = (email, options = {}) => {
  if (!email || typeof email !== 'string') return false;
  
  const {
    allowDisplayName = false,
    requireDisplayName = false,
    allowUTF8LocalPart = true,
    requireTld = true,
    blacklistedChars = '',
    domainBlacklist = []
  } = options;
  
  const isValid = validator.isEmail(email, {
    allow_display_name: allowDisplayName,
    require_display_name: requireDisplayName,
    allow_utf8_local_part: allowUTF8LocalPart,
    require_tld: requireTld,
    blacklisted_chars: blacklistedChars
  });
  
  if (!isValid) return false;
  
  // Check domain blacklist
  if (domainBlacklist.length > 0) {
    const domain = email.split('@')[1];
    if (domainBlacklist.includes(domain)) return false;
  }
  
  return true;
};

/**
 * Check if email is from disposable domain
 * @param {string} email - Email address
 * @returns {boolean} Is disposable
 */
export const isDisposableEmail = (email) => {
  const disposableDomains = [
    'tempmail.com', '10minutemail.com', 'guerrillamail.com',
    'mailinator.com', 'temp-mail.org', 'throwaway.email',
    'maildrop.cc', 'sharklasers.com', 'yopmail.com'
  ];
  
  const domain = email.split('@')[1]?.toLowerCase();
  return disposableDomains.includes(domain);
};

// ============================================================================
// PHONE VALIDATION
// ============================================================================

/**
 * Validate phone number (international format)
 * @param {string} phone - Phone number
 * @param {string} country - Country code (e.g., 'US', 'GB')
 * @returns {boolean} Is valid
 */
export const isValidPhone = (phone, country = null) => {
  if (!phone || typeof phone !== 'string') return false;
  
  return validator.isMobilePhone(phone, country || 'any', {
    strictMode: false
  });
};

/**
 * Validate phone with specific format
 * @param {string} phone - Phone number
 * @param {RegExp} format - Expected format regex
 * @returns {boolean} Is valid
 */
export const isValidPhoneFormat = (phone, format) => {
  return format.test(phone);
};

// ============================================================================
// URL VALIDATION
// ============================================================================

/**
 * Validate URL
 * @param {string} url - URL string
 * @param {object} options - Validation options
 * @returns {boolean} Is valid
 */
export const isValidURL = (url, options = {}) => {
  if (!url || typeof url !== 'string') return false;
  
  const {
    protocols = ['http', 'https'],
    requireProtocol = true,
    requireHost = true,
    requireValidProtocol = true,
    allowQueryComponents = true,
    allowFragments = true,
    requireTld = true
  } = options;
  
  return validator.isURL(url, {
    protocols,
    require_protocol: requireProtocol,
    require_host: requireHost,
    require_valid_protocol: requireValidProtocol,
    allow_query_components: allowQueryComponents,
    allow_fragments: allowFragments,
    require_tld: requireTld
  });
};

/**
 * Check if URL is safe (no known malicious patterns)
 * @param {string} url - URL string
 * @returns {boolean} Is safe
 */
export const isSafeURL = (url) => {
  const dangerousPatterns = [
    /javascript:/i,
    /data:/i,
    /vbscript:/i,
    /file:/i,
    /<script/i,
    /on\w+=/i
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(url));
};

// ============================================================================
// IP ADDRESS VALIDATION
// ============================================================================

/**
 * Validate IPv4 address
 * @param {string} ip - IP address
 * @returns {boolean} Is valid IPv4
 */
export const isValidIPv4 = (ip) => {
  return validator.isIP(ip, 4);
};

/**
 * Validate IPv6 address
 * @param {string} ip - IP address
 * @returns {boolean} Is valid IPv6
 */
export const isValidIPv6 = (ip) => {
  return validator.isIP(ip, 6);
};

/**
 * Validate IP address (both IPv4 and IPv6)
 * @param {string} ip - IP address
 * @returns {boolean} Is valid IP
 */
export const isValidIP = (ip) => {
  return validator.isIP(ip);
};

/**
 * Check if IP is private/internal
 * @param {string} ip - IP address
 * @returns {boolean} Is private
 */
export const isPrivateIP = (ip) => {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/
  ];
  
  return privateRanges.some(range => range.test(ip));
};

// ============================================================================
// CREDIT CARD VALIDATION
// ============================================================================

/**
 * Validate credit card number (Luhn algorithm)
 * @param {string} cardNumber - Card number
 * @returns {boolean} Is valid
 */
export const isValidCreditCard = (cardNumber) => {
  if (!cardNumber || typeof cardNumber !== 'string') return false;
  
  return validator.isCreditCard(cardNumber.replace(/\s/g, ''));
};

/**
 * Get credit card type
 * @param {string} cardNumber - Card number
 * @returns {string|null} Card type (visa, mastercard, amex, etc.)
 */
export const getCreditCardType = (cardNumber) => {
  const cleaned = cardNumber.replace(/\s/g, '');
  
  const patterns = {
    visa: /^4[0-9]{12}(?:[0-9]{3})?$/,
    mastercard: /^5[1-5][0-9]{14}$/,
    amex: /^3[47][0-9]{13}$/,
    discover: /^6(?:011|5[0-9]{2})[0-9]{12}$/,
    diners: /^3(?:0[0-5]|[68][0-9])[0-9]{11}$/,
    jcb: /^(?:2131|1800|35\d{3})\d{11}$/
  };
  
  for (const [type, pattern] of Object.entries(patterns)) {
    if (pattern.test(cleaned)) return type;
  }
  
  return null;
};

/**
 * Validate CVV/CVC code (FIXED)
 * @param {string} cvv - CVV code
 * @param {string} cardType - Card type
 * @returns {boolean} Is valid
 */
export const isValidCVV = (cvv, cardType = null) => {
  if (!cvv || typeof cvv !== 'string') return false;
  
  const length = cardType === 'amex' ? 4 : 3;
  return new RegExp(`^\\d{${length}}/**
 * Validator Utilities - MILITARY-GRADE Validation Functions
 * Enterprise-level input validation with comprehensive checks
 * 
 * @module utils/validators
 * @version 3.0.1
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - Email validation (RFC 5322 compliant)
 * - Phone number validation (international)
 * - URL validation
 * - IP address validation (IPv4, IPv6)
 * - Credit card validation (Luhn algorithm)
 * - Password strength validation
 * - Username validation
 * - File validation
 * - Date validation
 * - Postal code validation
 * - Social security number validation
 * - IBAN validation
 * - VAT number validation
 * - MAC address validation
 * - UUID validation
 * - JSON validation
 * - Base64 validation
 * - Hex color validation
 * - MongoDB ObjectId validation
 * - SQL injection detection
 * - XSS detection
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import validator from 'validator';

// ============================================================================
// EMAIL VALIDATION
// ============================================================================

/**
 * Validate email address (RFC 5322)
 * @param {string} email - Email address
 * @param {object} options - Validation options
 * @returns {boolean} Is valid
 */
export const isValidEmail = (email, options = {}) => {
  if (!email || typeof email !== 'string') return false;
  
  const {
    allowDisplayName = false,
    requireDisplayName = false,
    allowUTF8LocalPart = true,
    requireTld = true,
    blacklistedChars = '',
    domainBlacklist = []
  } = options;
  
  const isValid = validator.isEmail(email, {
    allow_display_name: allowDisplayName,
    require_display_name: requireDisplayName,
    allow_utf8_local_part: allowUTF8LocalPart,
    require_tld: requireTld,
    blacklisted_chars: blacklistedChars
  });
  
  if (!isValid) return false;
  
  // Check domain blacklist
  if (domainBlacklist.length > 0) {
    const domain = email.split('@')[1];
    if (domainBlacklist.includes(domain)) return false;
  }
  
  return true;
};

/**
 * Check if email is from disposable domain
 * @param {string} email - Email address
 * @returns {boolean} Is disposable
 */
export const isDisposableEmail = (email) => {
  const disposableDomains = [
    'tempmail.com', '10minutemail.com', 'guerrillamail.com',
    'mailinator.com', 'temp-mail.org', 'throwaway.email',
    'maildrop.cc', 'sharklasers.com', 'yopmail.com'
  ];
  
).test(cvv);
};

// ============================================================================
// PASSWORD VALIDATION
// ============================================================================

/**
 * Validate password strength
 * @param {string} password - Password
 * @param {object} options - Validation options
 * @returns {object} Validation result
 */
export const validatePasswordStrength = (password, options = {}) => {
  const {
    minLength = 8,
    maxLength = 128,
    requireUppercase = true,
    requireLowercase = true,
    requireNumbers = true,
    requireSpecial = true,
    minScore = 3
  } = options;
  
  const errors = [];
  let score = 0;
  
  // Length check
  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters`);
  } else if (password.length >= minLength) {
    score += 1;
  }
  
  if (password.length > maxLength) {
    errors.push(`Password cannot exceed ${maxLength} characters`);
  }
  
  // Uppercase check
  if (requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  } else if (/[A-Z]/.test(password)) {
    score += 1;
  }
  
  // Lowercase check
  if (requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  } else if (/[a-z]/.test(password)) {
    score += 1;
  }
  
  // Number check
  if (requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  } else if (/\d/.test(password)) {
    score += 1;
  }
  
  // Special character check
  if (requireSpecial && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  } else if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    score += 1;
  }
  
  // Calculate strength
  const strength = score <= 2 ? 'weak' : score === 3 ? 'medium' : score === 4 ? 'strong' : 'very strong';
  
  return {
    valid: errors.length === 0 && score >= minScore,
    score,
    strength,
    errors
  };
};

/**
 * Calculate password entropy
 * @param {string} password - Password
 * @returns {number} Entropy in bits
 */
export const calculatePasswordEntropy = (password) => {
  let charset = 0;
  
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/\d/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 32;
  
  return Math.log2(Math.pow(charset, password.length));
};

/**
 * Check if password is commonly used
 * @param {string} password - Password
 * @returns {boolean} Is common
 */
export const isCommonPassword = (password) => {
  const commonPasswords = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
    'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'bailey', 'passw0rd', 'shadow', '123123', '654321',
    'superman', 'qazwsx', 'michael', 'football'
  ];
  
  return commonPasswords.includes(password.toLowerCase());
};

// ============================================================================
// USERNAME VALIDATION
// ============================================================================

/**
 * Validate username
 * @param {string} username - Username
 * @param {object} options - Validation options
 * @returns {object} Validation result
 */
export const validateUsername = (username, options = {}) => {
  const {
    minLength = 3,
    maxLength = 30,
    allowedChars = /^[a-zA-Z0-9_-]+$/,
    reservedNames = ['admin', 'root', 'system', 'api', 'null', 'undefined']
  } = options;
  
  const errors = [];
  
  if (!username || typeof username !== 'string') {
    errors.push('Username is required');
    return { valid: false, errors };
  }
  
  if (username.length < minLength) {
    errors.push(`Username must be at least ${minLength} characters`);
  }
  
  if (username.length > maxLength) {
    errors.push(`Username cannot exceed ${maxLength} characters`);
  }
  
  if (!allowedChars.test(username)) {
    errors.push('Username can only contain letters, numbers, underscores, and hyphens');
  }
  
  if (reservedNames.includes(username.toLowerCase())) {
    errors.push('This username is reserved');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

// ============================================================================
// FILE VALIDATION
// ============================================================================

/**
 * Validate file type by MIME type
 * @param {string} mimeType - MIME type
 * @param {string[]} allowedTypes - Allowed MIME types
 * @returns {boolean} Is valid
 */
export const isValidFileType = (mimeType, allowedTypes) => {
  return allowedTypes.includes(mimeType);
};

/**
 * Validate file extension
 * @param {string} filename - Filename
 * @param {string[]} allowedExtensions - Allowed extensions
 * @returns {boolean} Is valid
 */
export const isValidFileExtension = (filename, allowedExtensions) => {
  const ext = filename.split('.').pop().toLowerCase();
  return allowedExtensions.map(e => e.toLowerCase()).includes(ext);
};

/**
 * Validate file size
 * @param {number} size - File size in bytes
 * @param {number} maxSize - Maximum size in bytes
 * @returns {boolean} Is valid
 */
export const isValidFileSize = (size, maxSize) => {
  return size > 0 && size <= maxSize;
};

/**
 * Validate image dimensions
 * @param {number} width - Image width
 * @param {number} height - Image height
 * @param {object} constraints - Dimension constraints
 * @returns {boolean} Is valid
 */
export const isValidImageDimensions = (width, height, constraints = {}) => {
  const { minWidth = 0, maxWidth = Infinity, minHeight = 0, maxHeight = Infinity } = constraints;
  
  return width >= minWidth && width <= maxWidth && height >= minHeight && height <= maxHeight;
};

// ============================================================================
// DATE VALIDATION
// ============================================================================

/**
 * Validate date string
 * @param {string} dateStr - Date string
 * @param {string} format - Expected format
 * @returns {boolean} Is valid
 */
export const isValidDate = (dateStr, format = 'YYYY-MM-DD') => {
  return validator.isDate(dateStr, { format });
};

/**
 * Check if date is in the past
 * @param {string|Date} date - Date
 * @returns {boolean} Is in past
 */
export const isDateInPast = (date) => {
  const dateObj = date instanceof Date ? date : new Date(date);
  return dateObj < new Date();
};

/**
 * Check if date is in the future
 * @param {string|Date} date - Date
 * @returns {boolean} Is in future
 */
export const isDateInFuture = (date) => {
  const dateObj = date instanceof Date ? date : new Date(date);
  return dateObj > new Date();
};

/**
 * Validate date range
 * @param {string|Date} startDate - Start date
 * @param {string|Date} endDate - End date
 * @returns {boolean} Is valid range
 */
export const isValidDateRange = (startDate, endDate) => {
  const start = startDate instanceof Date ? startDate : new Date(startDate);
  const end = endDate instanceof Date ? endDate : new Date(endDate);
  return start < end;
};

/**
 * Validate age (must be at least minAge years old)
 * @param {string|Date} birthDate - Birth date
 * @param {number} minAge - Minimum age
 * @returns {boolean} Is valid age
 */
export const isValidAge = (birthDate, minAge = 18) => {
  const birth = birthDate instanceof Date ? birthDate : new Date(birthDate);
  const today = new Date();
  const age = today.getFullYear() - birth.getFullYear();
  const monthDiff = today.getMonth() - birth.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
    return age - 1 >= minAge;
  }
  
  return age >= minAge;
};

// ============================================================================
// POSTAL CODE VALIDATION
// ============================================================================

/**
 * Validate postal code by country
 * @param {string} postalCode - Postal code
 * @param {string} country - Country code
 * @returns {boolean} Is valid
 */
export const isValidPostalCode = (postalCode, country) => {
  return validator.isPostalCode(postalCode, country);
};

// ============================================================================
// SPECIAL FORMAT VALIDATION
// ============================================================================

/**
 * Validate UUID
 * @param {string} uuid - UUID string
 * @param {string} version - UUID version (3, 4, 5, or 'all')
 * @returns {boolean} Is valid
 */
export const isValidUUID = (uuid, version = 'all') => {
  return validator.isUUID(uuid, version);
};

/**
 * Validate MongoDB ObjectId
 * @param {string} id - ObjectId string
 * @returns {boolean} Is valid
 */
export const isValidObjectId = (id) => {
  return validator.isMongoId(id);
};

/**
 * Validate JSON string
 * @param {string} str - JSON string
 * @returns {boolean} Is valid
 */
export const isValidJSON = (str) => {
  return validator.isJSON(str);
};

/**
 * Validate Base64 string
 * @param {string} str - Base64 string
 * @returns {boolean} Is valid
 */
export const isValidBase64 = (str) => {
  return validator.isBase64(str);
};

/**
 * Validate hex color
 * @param {string} color - Hex color code
 * @returns {boolean} Is valid
 */
export const isValidHexColor = (color) => {
  return validator.isHexColor(color);
};

/**
 * Validate MAC address
 * @param {string} mac - MAC address
 * @returns {boolean} Is valid
 */
export const isValidMACAddress = (mac) => {
  return validator.isMACAddress(mac);
};

/**
 * Validate IBAN
 * @param {string} iban - IBAN code
 * @returns {boolean} Is valid
 */
export const isValidIBAN = (iban) => {
  return validator.isIBAN(iban);
};

/**
 * Validate JWT token
 * @param {string} token - JWT token
 * @returns {boolean} Is valid format
 */
export const isValidJWT = (token) => {
  return validator.isJWT(token);
};

// ============================================================================
// SECURITY VALIDATION
// ============================================================================

/**
 * Detect potential SQL injection patterns
 * @param {string} input - User input
 * @returns {boolean} Contains SQL injection patterns
 */
export const containsSQLInjection = (input) => {
  if (!input || typeof input !== 'string') return false;
  
  const sqlPatterns = [
    /(\bUNION\b.*\bSELECT\b)/i,
    /(\bSELECT\b.*\bFROM\b)/i,
    /(\bINSERT\b.*\bINTO\b)/i,
    /(\bUPDATE\b.*\bSET\b)/i,
    /(\bDELETE\b.*\bFROM\b)/i,
    /(\bDROP\b.*\bTABLE\b)/i,
    /(\bCREATE\b.*\bTABLE\b)/i,
    /(\bEXEC\b|\bEXECUTE\b)/i,
    /(;|\-\-|\/\*|\*\/)/,
    /('|"|`)/,
    /(\bOR\b.*=.*)/i,
    /(\bAND\b.*=.*)/i
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
};

/**
 * Detect potential XSS patterns
 * @param {string} input - User input
 * @returns {boolean} Contains XSS patterns
 */
export const containsXSS = (input) => {
  if (!input || typeof input !== 'string') return false;
  
  const xssPatterns = [
    /<script[^>]*>.*<\/script>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<embed/i,
    /<object/i,
    /<img[^>]+src\s*=\s*["']?javascript:/i,
    /<svg[^>]*onload/i,
    /eval\s*\(/i,
    /expression\s*\(/i
  ];
  
  return xssPatterns.some(pattern => pattern.test(input));
};

/**
 * Detect path traversal attempts
 * @param {string} path - File path
 * @returns {boolean} Contains path traversal
 */
export const containsPathTraversal = (path) => {
  if (!path || typeof path !== 'string') return false;
  
  const traversalPatterns = [
    /\.\./,
    /\.\.\\/, 
    /%2e%2e/i,
    /\.\.%2f/i,
    /%252e/i
  ];
  
  return traversalPatterns.some(pattern => pattern.test(path));
};

/**
 * Validate input doesn't contain null bytes
 * @param {string} input - User input
 * @returns {boolean} Is safe
 */
export const isNullByteFree = (input) => {
  return !input.includes('\0') && !input.includes('%00');
};

// ============================================================================
// BUSINESS LOGIC VALIDATION
// ============================================================================

/**
 * Validate coupon code format
 * @param {string} code - Coupon code
 * @returns {boolean} Is valid format
 */
export const isValidCouponCode = (code) => {
  return /^[A-Z0-9]{6,20}$/.test(code);
};

/**
 * Validate order quantity
 * @param {number} quantity - Quantity
 * @param {number} min - Minimum allowed
 * @param {number} max - Maximum allowed
 * @returns {boolean} Is valid
 */
export const isValidQuantity = (quantity, min = 1, max = 999) => {
  return Number.isInteger(quantity) && quantity >= min && quantity <= max;
};

/**
 * Validate price/amount
 * @param {number} amount - Amount
 * @param {number} min - Minimum amount
 * @param {number} max - Maximum amount
 * @returns {boolean} Is valid
 */
export const isValidAmount = (amount, min = 0, max = 1000000) => {
  return typeof amount === 'number' && amount >= min && amount <= max;
};

/**
 * Validate SKU format
 * @param {string} sku - SKU code
 * @returns {boolean} Is valid
 */
export const isValidSKU = (sku) => {
  return /^[A-Z0-9-_]{3,50}$/i.test(sku);
};

/**
 * Validate rating value
 * @param {number} rating - Rating value
 * @param {number} min - Minimum rating
 * @param {number} max - Maximum rating
 * @returns {boolean} Is valid
 */
export const isValidRating = (rating, min = 1, max = 5) => {
  return Number.isInteger(rating) && rating >= min && rating <= max;
};

// ============================================================================
// COMPOSITE VALIDATION
// ============================================================================

/**
 * Validate multiple fields
 * @param {object} data - Data to validate
 * @param {object} rules - Validation rules
 * @returns {object} Validation result
 */
export const validateFields = (data, rules) => {
  const errors = {};
  
  for (const [field, rule] of Object.entries(rules)) {
    const value = data[field];
    
    if (rule.required && (value === undefined || value === null || value === '')) {
      errors[field] = `${field} is required`;
      continue;
    }
    
    if (value && rule.type) {
      const typeChecks = {
        email: () => isValidEmail(value),
        phone: () => isValidPhone(value),
        url: () => isValidURL(value),
        uuid: () => isValidUUID(value),
        ip: () => isValidIP(value)
      };
      
      if (typeChecks[rule.type] && !typeChecks[rule.type]()) {
        errors[field] = `${field} must be a valid ${rule.type}`;
      }
    }
    
    if (value && rule.min !== undefined && value.length < rule.min) {
      errors[field] = `${field} must be at least ${rule.min} characters`;
    }
    
    if (value && rule.max !== undefined && value.length > rule.max) {
      errors[field] = `${field} cannot exceed ${rule.max} characters`;
    }
    
    if (value && rule.pattern && !rule.pattern.test(value)) {
      errors[field] = rule.message || `${field} format is invalid`;
    }
    
    if (value && rule.custom && !rule.custom(value)) {
      errors[field] = rule.message || `${field} validation failed`;
    }
  }
  
  return {
    valid: Object.keys(errors).length === 0,
    errors
  };
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Email
  isValidEmail,
  isDisposableEmail,
  
  // Phone
  isValidPhone,
  isValidPhoneFormat,
  
  // URL
  isValidURL,
  isSafeURL,
  
  // IP
  isValidIP,
  isValidIPv4,
  isValidIPv6,
  isPrivateIP,
  
  // Credit Card
  isValidCreditCard,
  getCreditCardType,
  isValidCVV,
  
  // Password
  validatePasswordStrength,
  calculatePasswordEntropy,
  isCommonPassword,
  
  // Username
  validateUsername,
  
  // File
  isValidFileType,
  isValidFileExtension,
  isValidFileSize,
  isValidImageDimensions,
  
  // Date
  isValidDate,
  isDateInPast,
  isDateInFuture,
  isValidDateRange,
  isValidAge,
  
  // Postal
  isValidPostalCode,
  
  // Special Formats
  isValidUUID,
  isValidObjectId,
  isValidJSON,
  isValidBase64,
  isValidHexColor,
  isValidMACAddress,
  isValidIBAN,
  isValidJWT,
  
  // Security
  containsSQLInjection,
  containsXSS,
  containsPathTraversal,
  isNullByteFree,
  
  // Business
  isValidCouponCode,
  isValidQuantity,
  isValidAmount,
  isValidSKU,
  isValidRating,
  
  // Composite
  validateFields
};
