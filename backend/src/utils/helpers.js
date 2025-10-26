/**
 * Helper Utilities - MILITARY-GRADE Common Helper Functions
 * Enterprise-level utility functions for application-wide use
 * 
 * @module utils/helpers
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - String manipulation utilities
 * - Object operations
 * - Array utilities
 * - Number helpers
 * - Pagination helpers
 * - Slug generation
 * - Random generators
 * - Deep cloning
 * - Debouncing & throttling
 * - Retry mechanisms
 * - Promise utilities
 * - File size formatting
 * - Color utilities
 * - URL helpers
 * - Error handling utilities
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import crypto from 'crypto';
import { nanoid } from 'nanoid';

// ============================================================================
// STRING UTILITIES
// ============================================================================

/**
 * Generate URL-friendly slug from string
 * @param {string} str - Input string
 * @param {object} options - Options
 * @returns {string} Slug
 */
export const slugify = (str, options = {}) => {
  const {
    separator = '-',
    lowercase = true,
    trim = true
  } = options;

  let slug = str
    .toString()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Remove diacritics
    .replace(/[^a-zA-Z0-9\s-]/g, '') // Remove special chars
    .replace(/\s+/g, separator) // Replace spaces
    .replace(new RegExp(`${separator}+`, 'g'), separator); // Remove duplicate separators

  if (lowercase) slug = slug.toLowerCase();
  if (trim) slug = slug.replace(new RegExp(`^${separator}+|${separator}+$`, 'g'), '');

  return slug;
};

/**
 * Truncate string with ellipsis
 * @param {string} str - Input string
 * @param {number} length - Max length
 * @param {string} suffix - Suffix to append
 * @returns {string} Truncated string
 */
export const truncate = (str, length = 100, suffix = '...') => {
  if (!str || str.length <= length) return str;
  return str.substring(0, length - suffix.length).trim() + suffix;
};

/**
 * Capitalize first letter of string
 * @param {string} str - Input string
 * @returns {string} Capitalized string
 */
export const capitalize = (str) => {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

/**
 * Convert string to title case
 * @param {string} str - Input string
 * @returns {string} Title case string
 */
export const titleCase = (str) => {
  if (!str) return '';
  return str
    .toLowerCase()
    .split(' ')
    .map(word => capitalize(word))
    .join(' ');
};

/**
 * Convert camelCase to snake_case
 * @param {string} str - Input string
 * @returns {string} Snake case string
 */
export const camelToSnake = (str) => {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
};

/**
 * Convert snake_case to camelCase
 * @param {string} str - Input string
 * @returns {string} Camel case string
 */
export const snakeToCamel = (str) => {
  return str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
};

/**
 * Extract initials from name
 * @param {string} name - Full name
 * @param {number} max - Maximum initials
 * @returns {string} Initials
 */
export const getInitials = (name, max = 2) => {
  if (!name) return '';
  return name
    .split(' ')
    .filter(Boolean)
    .slice(0, max)
    .map(word => word[0].toUpperCase())
    .join('');
};

/**
 * Mask sensitive string (email, phone, card)
 * @param {string} str - Input string
 * @param {number} visibleStart - Visible characters at start
 * @param {number} visibleEnd - Visible characters at end
 * @param {string} maskChar - Mask character
 * @returns {string} Masked string
 */
export const maskString = (str, visibleStart = 2, visibleEnd = 2, maskChar = '*') => {
  if (!str || str.length <= visibleStart + visibleEnd) return str;
  
  const start = str.substring(0, visibleStart);
  const end = str.substring(str.length - visibleEnd);
  const masked = maskChar.repeat(str.length - visibleStart - visibleEnd);
  
  return start + masked + end;
};

/**
 * Generate random string
 * @param {number} length - String length
 * @param {string} charset - Character set
 * @returns {string} Random string
 */
export const randomString = (length = 16, charset = 'alphanumeric') => {
  const charsets = {
    numeric: '0123456789',
    alpha: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    alphanumeric: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    alphanumericLower: '0123456789abcdefghijklmnopqrstuvwxyz',
    hex: '0123456789abcdef',
    base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  };

  const chars = charsets[charset] || charsets.alphanumeric;
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
};

// ============================================================================
// OBJECT UTILITIES
// ============================================================================

/**
 * Deep clone object
 * @param {object} obj - Object to clone
 * @returns {object} Cloned object
 */
export const deepClone = (obj) => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime());
  if (obj instanceof Array) return obj.map(item => deepClone(item));
  
  const clonedObj = {};
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      clonedObj[key] = deepClone(obj[key]);
    }
  }
  return clonedObj;
};

/**
 * Deep merge objects
 * @param {object} target - Target object
 * @param {...object} sources - Source objects
 * @returns {object} Merged object
 */
export const deepMerge = (target, ...sources) => {
  if (!sources.length) return target;
  
  const source = sources.shift();
  
  if (isObject(target) && isObject(source)) {
    for (const key in source) {
      if (isObject(source[key])) {
        if (!target[key]) Object.assign(target, { [key]: {} });
        deepMerge(target[key], source[key]);
      } else {
        Object.assign(target, { [key]: source[key] });
      }
    }
  }
  
  return deepMerge(target, ...sources);
};

/**
 * Check if value is plain object
 * @param {*} value - Value to check
 * @returns {boolean} Is plain object
 */
export const isObject = (value) => {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
};

/**
 * Check if object is empty
 * @param {object} obj - Object to check
 * @returns {boolean} Is empty
 */
export const isEmpty = (obj) => {
  if (obj === null || obj === undefined) return true;
  if (Array.isArray(obj) || typeof obj === 'string') return obj.length === 0;
  if (typeof obj === 'object') return Object.keys(obj).length === 0;
  return false;
};

/**
 * Pick specific keys from object
 * @param {object} obj - Source object
 * @param {string[]} keys - Keys to pick
 * @returns {object} Picked object
 */
export const pick = (obj, keys) => {
  return keys.reduce((result, key) => {
    if (obj.hasOwnProperty(key)) {
      result[key] = obj[key];
    }
    return result;
  }, {});
};

/**
 * Omit specific keys from object
 * @param {object} obj - Source object
 * @param {string[]} keys - Keys to omit
 * @returns {object} Omitted object
 */
export const omit = (obj, keys) => {
  const result = { ...obj };
  keys.forEach(key => delete result[key]);
  return result;
};

/**
 * Get nested property value safely
 * @param {object} obj - Object
 * @param {string} path - Property path (e.g., 'user.profile.name')
 * @param {*} defaultValue - Default value if not found
 * @returns {*} Property value
 */
export const get = (obj, path, defaultValue = undefined) => {
  const keys = path.split('.');
  let result = obj;
  
  for (const key of keys) {
    if (result === null || result === undefined) return defaultValue;
    result = result[key];
  }
  
  return result !== undefined ? result : defaultValue;
};

/**
 * Set nested property value safely
 * @param {object} obj - Object
 * @param {string} path - Property path
 * @param {*} value - Value to set
 * @returns {object} Modified object
 */
export const set = (obj, path, value) => {
  const keys = path.split('.');
  const lastKey = keys.pop();
  let current = obj;
  
  for (const key of keys) {
    if (!(key in current) || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key];
  }
  
  current[lastKey] = value;
  return obj;
};

/**
 * Flatten nested object
 * @param {object} obj - Object to flatten
 * @param {string} prefix - Key prefix
 * @returns {object} Flattened object
 */
export const flatten = (obj, prefix = '') => {
  const result = {};
  
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      const newKey = prefix ? `${prefix}.${key}` : key;
      
      if (isObject(obj[key]) && !Array.isArray(obj[key])) {
        Object.assign(result, flatten(obj[key], newKey));
      } else {
        result[newKey] = obj[key];
      }
    }
  }
  
  return result;
};

// ============================================================================
// ARRAY UTILITIES
// ============================================================================

/**
 * Remove duplicates from array
 * @param {array} arr - Input array
 * @param {string} key - Optional key for object arrays
 * @returns {array} Unique array
 */
export const unique = (arr, key = null) => {
  if (!key) return [...new Set(arr)];
  
  const seen = new Set();
  return arr.filter(item => {
    const value = item[key];
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
};

/**
 * Chunk array into smaller arrays
 * @param {array} arr - Input array
 * @param {number} size - Chunk size
 * @returns {array} Chunked arrays
 */
export const chunk = (arr, size) => {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
};

/**
 * Shuffle array randomly
 * @param {array} arr - Input array
 * @returns {array} Shuffled array
 */
export const shuffle = (arr) => {
  const shuffled = [...arr];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
};

/**
 * Get random item from array
 * @param {array} arr - Input array
 * @returns {*} Random item
 */
export const randomItem = (arr) => {
  return arr[Math.floor(Math.random() * arr.length)];
};

/**
 * Group array by key
 * @param {array} arr - Input array
 * @param {string|function} key - Grouping key or function
 * @returns {object} Grouped object
 */
export const groupBy = (arr, key) => {
  return arr.reduce((result, item) => {
    const group = typeof key === 'function' ? key(item) : item[key];
    (result[group] = result[group] || []).push(item);
    return result;
  }, {});
};

/**
 * Sort array by multiple keys
 * @param {array} arr - Input array
 * @param {array} keys - Sort keys with directions
 * @returns {array} Sorted array
 */
export const sortBy = (arr, keys) => {
  return [...arr].sort((a, b) => {
    for (const { key, direction = 'asc' } of keys) {
      const aVal = get(a, key);
      const bVal = get(b, key);
      
      if (aVal < bVal) return direction === 'asc' ? -1 : 1;
      if (aVal > bVal) return direction === 'asc' ? 1 : -1;
    }
    return 0;
  });
};

// ============================================================================
// NUMBER UTILITIES
// ============================================================================

/**
 * Format number with thousand separators
 * @param {number} num - Number to format
 * @param {string} separator - Thousand separator
 * @returns {string} Formatted number
 */
export const formatNumber = (num, separator = ',') => {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, separator);
};

/**
 * Format currency
 * @param {number} amount - Amount
 * @param {string} currency - Currency code
 * @param {string} locale - Locale
 * @returns {string} Formatted currency
 */
export const formatCurrency = (amount, currency = 'USD', locale = 'en-US') => {
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency
  }).format(amount);
};

/**
 * Calculate percentage
 * @param {number} value - Value
 * @param {number} total - Total
 * @param {number} decimals - Decimal places
 * @returns {number} Percentage
 */
export const percentage = (value, total, decimals = 2) => {
  if (total === 0) return 0;
  return parseFloat(((value / total) * 100).toFixed(decimals));
};

/**
 * Clamp number between min and max
 * @param {number} num - Number
 * @param {number} min - Minimum
 * @param {number} max - Maximum
 * @returns {number} Clamped number
 */
export const clamp = (num, min, max) => {
  return Math.min(Math.max(num, min), max);
};

/**
 * Generate random number in range
 * @param {number} min - Minimum
 * @param {number} max - Maximum
 * @param {boolean} integer - Return integer
 * @returns {number} Random number
 */
export const randomNumber = (min, max, integer = true) => {
  const num = Math.random() * (max - min) + min;
  return integer ? Math.floor(num) : num;
};

/**
 * Round number to decimal places
 * @param {number} num - Number
 * @param {number} decimals - Decimal places
 * @returns {number} Rounded number
 */
export const round = (num, decimals = 0) => {
  return Math.round(num * Math.pow(10, decimals)) / Math.pow(10, decimals);
};

// ============================================================================
// PAGINATION UTILITIES
// ============================================================================

/**
 * Calculate pagination metadata
 * @param {number} total - Total items
 * @param {number} page - Current page
 * @param {number} limit - Items per page
 * @returns {object} Pagination metadata
 */
export const paginate = (total, page = 1, limit = 20) => {
  const totalPages = Math.ceil(total / limit);
  const currentPage = clamp(page, 1, totalPages || 1);
  const offset = (currentPage - 1) * limit;
  
  return {
    total,
    page: currentPage,
    limit,
    totalPages,
    offset,
    hasNext: currentPage < totalPages,
    hasPrev: currentPage > 1,
    nextPage: currentPage < totalPages ? currentPage + 1 : null,
    prevPage: currentPage > 1 ? currentPage - 1 : null
  };
};

/**
 * Generate page numbers for pagination UI
 * @param {number} currentPage - Current page
 * @param {number} totalPages - Total pages
 * @param {number} maxVisible - Max visible pages
 * @returns {array} Page numbers
 */
export const getPaginationPages = (currentPage, totalPages, maxVisible = 7) => {
  if (totalPages <= maxVisible) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  
  const pages = [];
  const half = Math.floor(maxVisible / 2);
  let start = Math.max(currentPage - half, 1);
  let end = Math.min(start + maxVisible - 1, totalPages);
  
  if (end - start < maxVisible - 1) {
    start = Math.max(end - maxVisible + 1, 1);
  }
  
  for (let i = start; i <= end; i++) {
    pages.push(i);
  }
  
  return pages;
};

// ============================================================================
// ID GENERATION
// ============================================================================

/**
 * Generate unique ID
 * @param {string} prefix - ID prefix
 * @param {number} length - ID length
 * @returns {string} Unique ID
 */
export const generateId = (prefix = '', length = 16) => {
  const id = nanoid(length);
  return prefix ? `${prefix}_${id}` : id;
};

/**
 * Generate UUID v4
 * @returns {string} UUID
 */
export const generateUUID = () => {
  return crypto.randomUUID();
};

/**
 * Generate numeric ID
 * @param {number} length - ID length
 * @returns {string} Numeric ID
 */
export const generateNumericId = (length = 10) => {
  return randomString(length, 'numeric');
};

// ============================================================================
// PROMISE UTILITIES
// ============================================================================

/**
 * Sleep/delay execution
 * @param {number} ms - Milliseconds
 * @returns {Promise} Promise that resolves after delay
 */
export const sleep = (ms) => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

/**
 * Retry async function with exponential backoff
 * @param {function} fn - Async function
 * @param {object} options - Retry options
 * @returns {Promise} Function result
 */
export const retry = async (fn, options = {}) => {
  const {
    maxAttempts = 3,
    delay = 1000,
    backoff = 2,
    onRetry = null
  } = options;
  
  let lastError;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt < maxAttempts) {
        const waitTime = delay * Math.pow(backoff, attempt - 1);
        if (onRetry) onRetry(attempt, waitTime, error);
        await sleep(waitTime);
      }
    }
  }
  
  throw lastError;
};

/**
 * Execute promises with timeout
 * @param {Promise} promise - Promise to execute
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise} Promise result or timeout
 */
export const withTimeout = (promise, timeoutMs) => {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Operation timed out')), timeoutMs)
    )
  ]);
};

// ============================================================================
// DEBOUNCE & THROTTLE
// ============================================================================

/**
 * Debounce function
 * @param {function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @returns {function} Debounced function
 */
export const debounce = (func, wait = 300) => {
  let timeout;
  
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

/**
 * Throttle function
 * @param {function} func - Function to throttle
 * @param {number} limit - Time limit in ms
 * @returns {function} Throttled function
 */
export const throttle = (func, limit = 300) => {
  let inThrottle;
  
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

// ============================================================================
// FILE SIZE UTILITIES
// ============================================================================

/**
 * Format bytes to human-readable format
 * @param {number} bytes - Bytes
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted size
 */
export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
};

/**
 * Parse human-readable size to bytes
 * @param {string} size - Size string (e.g., '5MB')
 * @returns {number} Bytes
 */
export const parseSize = (size) => {
  const units = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
  const match = size.match(/^(\d+(?:\.\d+)?)\s*([KMGT]?B)$/i);
  
  if (!match) throw new Error('Invalid size format');
  
  const [, value, unit] = match;
  return parseFloat(value) * (units[unit.toUpperCase()] || 1);
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // String
  slugify,
  truncate,
  capitalize,
  titleCase,
  camelToSnake,
  snakeToCamel,
  getInitials,
  maskString,
  randomString,
  
  // Object
  deepClone,
  deepMerge,
  isObject,
  isEmpty,
  pick,
  omit,
  get,
  set,
  flatten,
  
  // Array
  unique,
  chunk,
  shuffle,
  randomItem,
  groupBy,
  sortBy,
  
  // Number
  formatNumber,
  formatCurrency,
  percentage,
  clamp,
  randomNumber,
  round,
  
  // Pagination
  paginate,
  getPaginationPages,
  
  // ID Generation
  generateId,
  generateUUID,
  generateNumericId,
  
  // Promise
  sleep,
  retry,
  withTimeout,
  
  // Performance
  debounce,
  throttle,
  
  // File
  formatBytes,
  parseSize
};
