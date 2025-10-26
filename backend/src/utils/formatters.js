/**
 * Formatter Utilities - MILITARY-GRADE Data Formatting Functions
 * Enterprise-level output formatting and display utilities
 * 
 * @module utils/formatters
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - Date/Time formatting
 * - Number formatting
 * - Currency formatting
 * - Phone number formatting
 * - Credit card formatting
 * - File size formatting
 * - Duration formatting
 * - Percentage formatting
 * - Address formatting
 * - Name formatting
 * - List formatting
 * - Table formatting
 * - JSON pretty print
 * - XML pretty print
 * - Color formatting
 * - Unit conversion
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import { format as formatDate, formatDistance, formatRelative, parseISO } from 'date-fns';

// ============================================================================
// DATE & TIME FORMATTING
// ============================================================================

/**
 * Format date to readable string
 * @param {Date|string} date - Date object or ISO string
 * @param {string} formatStr - Format string
 * @returns {string} Formatted date
 */
export const formatDateString = (date, formatStr = 'MMM dd, yyyy') => {
  if (!date) return '';
  
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return formatDate(dateObj, formatStr);
};

/**
 * Format date and time
 * @param {Date|string} date - Date
 * @returns {string} Formatted date and time
 */
export const formatDateTime = (date) => {
  return formatDateString(date, 'MMM dd, yyyy HH:mm:ss');
};

/**
 * Format time only
 * @param {Date|string} date - Date
 * @returns {string} Formatted time
 */
export const formatTime = (date) => {
  return formatDateString(date, 'HH:mm:ss');
};

/**
 * Format date as relative (e.g., "2 hours ago")
 * @param {Date|string} date - Date
 * @returns {string} Relative time
 */
export const formatRelativeTime = (date) => {
  if (!date) return '';
  
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return formatDistance(dateObj, new Date(), { addSuffix: true });
};

/**
 * Format date with timezone
 * @param {Date|string} date - Date
 * @param {string} timezone - Timezone
 * @returns {string} Formatted date with timezone
 */
export const formatDateWithTimezone = (date, timezone = 'UTC') => {
  if (!date) return '';
  
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  return dateObj.toLocaleString('en-US', { timeZone: timezone });
};

/**
 * Format ISO date
 * @param {Date|string} date - Date
 * @returns {string} ISO formatted date
 */
export const formatISO = (date) => {
  if (!date) return '';
  
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  return dateObj.toISOString();
};

// ============================================================================
// NUMBER FORMATTING
// ============================================================================

/**
 * Format number with thousand separators
 * @param {number} num - Number
 * @param {object} options - Formatting options
 * @returns {string} Formatted number
 */
export const formatNumber = (num, options = {}) => {
  const { locale = 'en-US', decimals, useGrouping = true } = options;
  
  return new Intl.NumberFormat(locale, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
    useGrouping
  }).format(num);
};

/**
 * Format number as percentage
 * @param {number} value - Value (0-1 or 0-100)
 * @param {object} options - Options
 * @returns {string} Formatted percentage
 */
export const formatPercentage = (value, options = {}) => {
  const { decimals = 2, multiply100 = false } = options;
  const percentage = multiply100 ? value : value * 100;
  
  return `${formatNumber(percentage, { decimals })}%`;
};

/**
 * Format number with ordinal suffix (1st, 2nd, 3rd)
 * @param {number} num - Number
 * @returns {string} Ordinal number
 */
export const formatOrdinal = (num) => {
  const suffixes = ['th', 'st', 'nd', 'rd'];
  const v = num % 100;
  return num + (suffixes[(v - 20) % 10] || suffixes[v] || suffixes[0]);
};

/**
 * Format number as compact (1K, 1M, 1B)
 * @param {number} num - Number
 * @param {number} decimals - Decimal places
 * @returns {string} Compact number
 */
export const formatCompactNumber = (num, decimals = 1) => {
  const units = ['', 'K', 'M', 'B', 'T'];
  const unitIndex = Math.floor(Math.log10(Math.abs(num)) / 3);
  const scaledNum = num / Math.pow(1000, unitIndex);
  
  return formatNumber(scaledNum, { decimals }) + units[unitIndex];
};

// ============================================================================
// CURRENCY FORMATTING
// ============================================================================

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
 * Format price with custom symbol
 * @param {number} amount - Amount
 * @param {string} symbol - Currency symbol
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted price
 */
export const formatPrice = (amount, symbol = '$', decimals = 2) => {
  const formatted = formatNumber(amount, { decimals });
  return `${symbol}${formatted}`;
};

/**
 * Format cryptocurrency
 * @param {number} amount - Amount
 * @param {string} symbol - Crypto symbol
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted crypto amount
 */
export const formatCrypto = (amount, symbol = 'BTC', decimals = 8) => {
  return `${formatNumber(amount, { decimals })} ${symbol}`;
};

// ============================================================================
// PHONE NUMBER FORMATTING
// ============================================================================

/**
 * Format phone number (US format)
 * @param {string} phone - Phone number
 * @returns {string} Formatted phone
 */
export const formatPhoneUS = (phone) => {
  const cleaned = phone.replace(/\D/g, '');
  
  if (cleaned.length === 10) {
    return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
  }
  
  if (cleaned.length === 11 && cleaned[0] === '1') {
    return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`;
  }
  
  return phone;
};

/**
 * Format international phone number
 * @param {string} phone - Phone number
 * @param {string} countryCode - Country code
 * @returns {string} Formatted phone
 */
export const formatPhoneInternational = (phone, countryCode = '+1') => {
  const cleaned = phone.replace(/\D/g, '');
  
  if (!phone.startsWith('+')) {
    return `${countryCode} ${cleaned}`;
  }
  
  return phone;
};

// ============================================================================
// CREDIT CARD FORMATTING
// ============================================================================

/**
 * Format credit card number
 * @param {string} cardNumber - Card number
 * @returns {string} Formatted card number
 */
export const formatCreditCard = (cardNumber) => {
  const cleaned = cardNumber.replace(/\s/g, '');
  const groups = cleaned.match(/.{1,4}/g);
  
  return groups ? groups.join(' ') : cardNumber;
};

/**
 * Format masked credit card
 * @param {string} cardNumber - Card number
 * @param {number} visibleDigits - Visible digits
 * @returns {string} Masked card
 */
export const formatMaskedCard = (cardNumber, visibleDigits = 4) => {
  const cleaned = cardNumber.replace(/\s/g, '');
  const masked = '**** **** **** ' + cleaned.slice(-visibleDigits);
  return masked;
};

// ============================================================================
// FILE SIZE FORMATTING
// ============================================================================

/**
 * Format bytes to human readable
 * @param {number} bytes - Bytes
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted size
 */
export const formatFileSize = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
};

/**
 * Format speed (bytes per second)
 * @param {number} bytesPerSecond - Bytes per second
 * @returns {string} Formatted speed
 */
export const formatSpeed = (bytesPerSecond) => {
  return `${formatFileSize(bytesPerSecond)}/s`;
};

// ============================================================================
// DURATION FORMATTING
// ============================================================================

/**
 * Format duration in milliseconds
 * @param {number} ms - Milliseconds
 * @returns {string} Formatted duration
 */
export const formatDuration = (ms) => {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
};

/**
 * Format time in HH:MM:SS
 * @param {number} seconds - Total seconds
 * @returns {string} Formatted time
 */
export const formatTimeHMS = (seconds) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  
  return [h, m, s]
    .map(v => v < 10 ? '0' + v : v)
    .join(':');
};

/**
 * Format uptime
 * @param {number} seconds - Uptime in seconds
 * @returns {string} Formatted uptime
 */
export const formatUptime = (seconds) => {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  
  const parts = [];
  if (days > 0) parts.push(`${days} day${days !== 1 ? 's' : ''}`);
  if (hours > 0) parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
  if (minutes > 0) parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
  
  return parts.join(', ') || '0 minutes';
};

// ============================================================================
// ADDRESS FORMATTING
// ============================================================================

/**
 * Format address
 * @param {object} address - Address object
 * @returns {string} Formatted address
 */
export const formatAddress = (address) => {
  const {
    addressLine1,
    addressLine2,
    city,
    state,
    postalCode,
    country
  } = address;
  
  const lines = [
    addressLine1,
    addressLine2,
    [city, state].filter(Boolean).join(', '),
    postalCode,
    country
  ].filter(Boolean);
  
  return lines.join('\n');
};

/**
 * Format address inline
 * @param {object} address - Address object
 * @returns {string} Inline address
 */
export const formatAddressInline = (address) => {
  return formatAddress(address).replace(/\n/g, ', ');
};

// ============================================================================
// NAME FORMATTING
// ============================================================================

/**
 * Format full name
 * @param {object} name - Name object
 * @returns {string} Full name
 */
export const formatFullName = (name) => {
  const { firstName, middleName, lastName, suffix } = name;
  
  const parts = [
    firstName,
    middleName,
    lastName,
    suffix
  ].filter(Boolean);
  
  return parts.join(' ');
};

/**
 * Format name with initials
 * @param {string} firstName - First name
 * @param {string} lastName - Last name
 * @returns {string} Name with initial
 */
export const formatNameWithInitial = (firstName, lastName) => {
  if (!firstName || !lastName) return firstName || lastName || '';
  
  return `${firstName} ${lastName.charAt(0)}.`;
};

// ============================================================================
// LIST FORMATTING
// ============================================================================

/**
 * Format array as list
 * @param {array} items - Items
 * @param {string} conjunction - Conjunction word
 * @returns {string} Formatted list
 */
export const formatList = (items, conjunction = 'and') => {
  if (!items || items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`;
  
  const allButLast = items.slice(0, -1).join(', ');
  const last = items[items.length - 1];
  
  return `${allButLast}, ${conjunction} ${last}`;
};

/**
 * Format list with bullets
 * @param {array} items - Items
 * @returns {string} Bulleted list
 */
export const formatBulletList = (items) => {
  return items.map(item => `• ${item}`).join('\n');
};

/**
 * Format numbered list
 * @param {array} items - Items
 * @returns {string} Numbered list
 */
export const formatNumberedList = (items) => {
  return items.map((item, index) => `${index + 1}. ${item}`).join('\n');
};

// ============================================================================
// TABLE FORMATTING
// ============================================================================

/**
 * Format data as ASCII table
 * @param {array} data - Table data
 * @param {array} headers - Column headers
 * @returns {string} ASCII table
 */
export const formatTable = (data, headers) => {
  const colWidths = headers.map((header, i) => {
    const values = data.map(row => String(row[i] || ''));
    return Math.max(header.length, ...values.map(v => v.length));
  });
  
  const separator = colWidths.map(w => '-'.repeat(w + 2)).join('+');
  
  const formatRow = (row) => {
    return row.map((cell, i) => {
      return ` ${String(cell).padEnd(colWidths[i])} `;
    }).join('|');
  };
  
  const lines = [
    separator,
    formatRow(headers),
    separator,
    ...data.map(row => formatRow(row)),
    separator
  ];
  
  return lines.join('\n');
};

// ============================================================================
// JSON & XML FORMATTING
// ============================================================================

/**
 * Pretty print JSON
 * @param {object} obj - Object
 * @param {number} indent - Indent spaces
 * @returns {string} Formatted JSON
 */
export const formatJSON = (obj, indent = 2) => {
  return JSON.stringify(obj, null, indent);
};

/**
 * Format JSON compact
 * @param {object} obj - Object
 * @returns {string} Compact JSON
 */
export const formatJSONCompact = (obj) => {
  return JSON.stringify(obj);
};

/**
 * Pretty print XML
 * @param {string} xml - XML string
 * @returns {string} Formatted XML
 */
export const formatXML = (xml) => {
  const PADDING = '  ';
  const reg = /(>)(<)(\/*)/g;
  let formatted = '';
  let pad = 0;
  
  xml = xml.replace(reg, '$1\n$2$3');
  
  xml.split('\n').forEach((node) => {
    let indent = 0;
    if (node.match(/.+<\/\w[^>]*>$/)) {
      indent = 0;
    } else if (node.match(/^<\/\w/)) {
      if (pad !== 0) {
        pad -= 1;
      }
    } else if (node.match(/^<\w([^>]*[^\/])?>.*$/)) {
      indent = 1;
    } else {
      indent = 0;
    }
    
    formatted += PADDING.repeat(pad) + node + '\n';
    pad += indent;
  });
  
  return formatted.trim();
};

// ============================================================================
// COLOR FORMATTING
// ============================================================================

/**
 * Format hex color to RGB
 * @param {string} hex - Hex color
 * @returns {object} RGB object
 */
export const hexToRGB = (hex) => {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? {
    r: parseInt(result[1], 16),
    g: parseInt(result[2], 16),
    b: parseInt(result[3], 16)
  } : null;
};

/**
 * Format RGB to hex
 * @param {number} r - Red
 * @param {number} g - Green
 * @param {number} b - Blue
 * @returns {string} Hex color
 */
export const rgbToHex = (r, g, b) => {
  return '#' + [r, g, b].map(x => {
    const hex = x.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  }).join('');
};

// ============================================================================
// UNIT CONVERSION FORMATTING
// ============================================================================

/**
 * Format temperature
 * @param {number} celsius - Celsius
 * @param {string} unit - Target unit (C, F, K)
 * @returns {string} Formatted temperature
 */
export const formatTemperature = (celsius, unit = 'C') => {
  let value = celsius;
  
  if (unit === 'F') {
    value = (celsius * 9/5) + 32;
  } else if (unit === 'K') {
    value = celsius + 273.15;
  }
  
  return `${formatNumber(value, { decimals: 1 })}°${unit}`;
};

/**
 * Format distance
 * @param {number} meters - Distance in meters
 * @param {string} unit - Target unit (m, km, mi, ft)
 * @returns {string} Formatted distance
 */
export const formatDistance = (meters, unit = 'km') => {
  const conversions = {
    m: { factor: 1, label: 'm' },
    km: { factor: 1000, label: 'km' },
    mi: { factor: 1609.34, label: 'mi' },
    ft: { factor: 0.3048, label: 'ft' }
  };
  
  const { factor, label } = conversions[unit];
  const value = meters / factor;
  
  return `${formatNumber(value, { decimals: 2 })} ${label}`;
};

/**
 * Format weight
 * @param {number} grams - Weight in grams
 * @param {string} unit - Target unit (g, kg, lb, oz)
 * @returns {string} Formatted weight
 */
export const formatWeight = (grams, unit = 'kg') => {
  const conversions = {
    g: { factor: 1, label: 'g' },
    kg: { factor: 1000, label: 'kg' },
    lb: { factor: 453.592, label: 'lb' },
    oz: { factor: 28.3495, label: 'oz' }
  };
  
  const { factor, label } = conversions[unit];
  const value = grams / factor;
  
  return `${formatNumber(value, { decimals: 2 })} ${label}`;
};

// ============================================================================
// TEXT FORMATTING
// ============================================================================

/**
 * Format text with ellipsis
 * @param {string} text - Text
 * @param {number} maxLength - Max length
 * @returns {string} Truncated text
 */
export const truncateText = (text, maxLength = 100) => {
  if (!text || text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
};

/**
 * Format line breaks as HTML
 * @param {string} text - Text with line breaks
 * @returns {string} HTML with <br> tags
 */
export const nl2br = (text) => {
  return text.replace(/\n/g, '<br>');
};

/**
 * Format code block
 * @param {string} code - Code
 * @param {string} language - Language
 * @returns {string} Formatted code block
 */
export const formatCodeBlock = (code, language = '') => {
  return '```' + language + '\n' + code + '\n```';
};

// ============================================================================
// SPECIAL FORMATTING
// ============================================================================

/**
 * Format version number
 * @param {string} version - Version string
 * @returns {string} Formatted version
 */
export const formatVersion = (version) => {
  const parts = version.split('.');
  return `v${parts.join('.')}`;
};

/**
 * Format hash/ID (shortened)
 * @param {string} hash - Hash string
 * @param {number} length - Display length
 * @returns {string} Shortened hash
 */
export const formatHash = (hash, length = 8) => {
  if (!hash || hash.length <= length) return hash;
  return hash.substring(0, length);
};

/**
 * Format username/handle
 * @param {string} username - Username
 * @returns {string} Formatted username
 */
export const formatUsername = (username) => {
  return username.startsWith('@') ? username : `@${username}`;
};

/**
 * Format count with label
 * @param {number} count - Count
 * @param {string} singular - Singular form
 * @param {string} plural - Plural form
 * @returns {string} Formatted count
 */
export const formatCount = (count, singular, plural = null) => {
  const label = count === 1 ? singular : (plural || singular + 's');
  return `${formatNumber(count, { decimals: 0 })} ${label}`;
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Date & Time
  formatDateString,
  formatDateTime,
  formatTime,
  formatRelativeTime,
  formatDateWithTimezone,
  formatISO,
  
  // Numbers
  formatNumber,
  formatPercentage,
  formatOrdinal,
  formatCompactNumber,
  
  // Currency
  formatCurrency,
  formatPrice,
  formatCrypto,
  
  // Phone
  formatPhoneUS,
  formatPhoneInternational,
  
  // Credit Card
  formatCreditCard,
  formatMaskedCard,
  
  // File Size
  formatFileSize,
  formatSpeed,
  
  // Duration
  formatDuration,
  formatTimeHMS,
  formatUptime,
  
  // Address
  formatAddress,
  formatAddressInline,
  
  // Name
  formatFullName,
  formatNameWithInitial,
  
  // Lists
  formatList,
  formatBulletList,
  formatNumberedList,
  
  // Tables
  formatTable,
  
  // JSON & XML
  formatJSON,
  formatJSONCompact,
  formatXML,
  
  // Colors
  hexToRGB,
  rgbToHex,
  
  // Units
  formatTemperature,
  formatDistance,
  formatWeight,
  
  // Text
  truncateText,
  nl2br,
  formatCodeBlock,
  
  // Special
  formatVersion,
  formatHash,
  formatUsername,
  formatCount
};
