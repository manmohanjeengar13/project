/**
 * Application Constants
 * Central location for all constant values used throughout the application
 */

/**
 * HTTP Status Codes
 */
export const HTTP_STATUS = {
  // Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  // Redirection
  MOVED_PERMANENTLY: 301,
  FOUND: 302,
  NOT_MODIFIED: 304,

  // Client Errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  NOT_ACCEPTABLE: 406,
  CONFLICT: 409,
  GONE: 410,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,

  // Server Errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
};

/**
 * User Roles
 */
export const USER_ROLES = {
  CUSTOMER: 'customer',
  MODERATOR: 'moderator',
  ADMIN: 'admin',
  DEVELOPER: 'developer',
  SUPER_ADMIN: 'super_admin'
};

/**
 * Role Hierarchy (for permission checking)
 */
export const ROLE_HIERARCHY = {
  [USER_ROLES.CUSTOMER]: 1,
  [USER_ROLES.MODERATOR]: 2,
  [USER_ROLES.ADMIN]: 3,
  [USER_ROLES.DEVELOPER]: 4,
  [USER_ROLES.SUPER_ADMIN]: 5
};

/**
 * Permissions
 */
export const PERMISSIONS = {
  // User permissions
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',

  // Product permissions
  PRODUCT_CREATE: 'product:create',
  PRODUCT_READ: 'product:read',
  PRODUCT_UPDATE: 'product:update',
  PRODUCT_DELETE: 'product:delete',

  // Order permissions
  ORDER_CREATE: 'order:create',
  ORDER_READ: 'order:read',
  ORDER_UPDATE: 'order:update',
  ORDER_DELETE: 'order:delete',

  // Review permissions
  REVIEW_CREATE: 'review:create',
  REVIEW_READ: 'review:read',
  REVIEW_UPDATE: 'review:update',
  REVIEW_DELETE: 'review:delete',
  REVIEW_MODERATE: 'review:moderate',

  // Admin permissions
  ADMIN_PANEL_ACCESS: 'admin:panel',
  ADMIN_SETTINGS: 'admin:settings',
  ADMIN_USERS: 'admin:users',
  ADMIN_SECURITY: 'admin:security',
  ADMIN_LOGS: 'admin:logs',
  ADMIN_BACKUP: 'admin:backup'
};

/**
 * Order Status
 */
export const ORDER_STATUS = {
  PENDING: 'pending',
  PROCESSING: 'processing',
  SHIPPED: 'shipped',
  DELIVERED: 'delivered',
  CANCELLED: 'cancelled',
  REFUNDED: 'refunded'
};

/**
 * Payment Status
 */
export const PAYMENT_STATUS = {
  PENDING: 'pending',
  PAID: 'paid',
  FAILED: 'failed',
  REFUNDED: 'refunded',
  CANCELLED: 'cancelled'
};

/**
 * Payment Methods
 */
export const PAYMENT_METHODS = {
  CREDIT_CARD: 'credit_card',
  DEBIT_CARD: 'debit_card',
  PAYPAL: 'paypal',
  STRIPE: 'stripe',
  BANK_TRANSFER: 'bank_transfer',
  CASH_ON_DELIVERY: 'cash_on_delivery'
};

/**
 * Notification Types
 */
export const NOTIFICATION_TYPES = {
  INFO: 'info',
  SUCCESS: 'success',
  WARNING: 'warning',
  ERROR: 'error',
  SECURITY: 'security',
  ORDER: 'order',
  REVIEW: 'review',
  SYSTEM: 'system'
};

/**
 * Attack Types (for logging)
 */
export const ATTACK_TYPES = {
  // SQL Injection
  SQLI_CLASSIC: 'sqli_classic',
  SQLI_UNION: 'sqli_union',
  SQLI_BLIND: 'sqli_blind',
  SQLI_TIME_BASED: 'sqli_time_based',
  SQLI_SECOND_ORDER: 'sqli_second_order',
  SQLI_ERROR_BASED: 'sqli_error_based',

  // XSS
  XSS_STORED: 'xss_stored',
  XSS_REFLECTED: 'xss_reflected',
  XSS_DOM: 'xss_dom',

  // Injection
  COMMAND_INJECTION: 'command_injection',
  LDAP_INJECTION: 'ldap_injection',
  XML_INJECTION: 'xml_injection',
  XXE: 'xxe',
  SSTI: 'ssti',
  NOSQL_INJECTION: 'nosql_injection',

  // Access Control
  IDOR: 'idor',
  PATH_TRAVERSAL: 'path_traversal',
  FORCED_BROWSING: 'forced_browsing',
  PRIVILEGE_ESCALATION: 'privilege_escalation',

  // Authentication
  BRUTE_FORCE: 'brute_force',
  CREDENTIAL_STUFFING: 'credential_stuffing',
  SESSION_FIXATION: 'session_fixation',
  SESSION_HIJACKING: 'session_hijacking',
  JWT_BYPASS: 'jwt_bypass',

  // Business Logic
  RACE_CONDITION: 'race_condition',
  MASS_ASSIGNMENT: 'mass_assignment',
  PRICE_MANIPULATION: 'price_manipulation',
  INSECURE_DESERIALIZATION: 'insecure_deserialization',

  // Other
  CSRF: 'csrf',
  SSRF: 'ssrf',
  OPEN_REDIRECT: 'open_redirect',
  INFORMATION_DISCLOSURE: 'information_disclosure',
  FILE_UPLOAD_BYPASS: 'file_upload_bypass',
  DOS: 'dos',
  REDOS: 'redos'
};

/**
 * Attack Severity Levels
 */
export const ATTACK_SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

/**
 * Security Event Types
 */
export const SECURITY_EVENTS = {
  LOGIN_SUCCESS: 'login_success',
  LOGIN_FAILURE: 'login_failure',
  LOGOUT: 'logout',
  PASSWORD_CHANGE: 'password_change',
  PASSWORD_RESET: 'password_reset',
  ACCOUNT_LOCKED: 'account_locked',
  ACCOUNT_UNLOCKED: 'account_unlocked',
  TWO_FACTOR_ENABLED: '2fa_enabled',
  TWO_FACTOR_DISABLED: '2fa_disabled',
  PERMISSION_DENIED: 'permission_denied',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  IP_BLOCKED: 'ip_blocked',
  IP_UNBLOCKED: 'ip_unblocked'
};

/**
 * Audit Actions
 */
export const AUDIT_ACTIONS = {
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
  LOGIN: 'login',
  LOGOUT: 'logout',
  EXPORT: 'export',
  IMPORT: 'import',
  APPROVE: 'approve',
  REJECT: 'reject'
};

/**
 * File Types
 */
export const FILE_TYPES = {
  IMAGE: 'image',
  DOCUMENT: 'document',
  VIDEO: 'video',
  AUDIO: 'audio',
  ARCHIVE: 'archive',
  OTHER: 'other'
};

/**
 * MIME Type Categories
 */
export const MIME_TYPES = {
  images: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
    'image/bmp'
  ],
  documents: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'text/csv'
  ],
  videos: [
    'video/mp4',
    'video/mpeg',
    'video/quicktime',
    'video/x-msvideo',
    'video/webm'
  ],
  audio: [
    'audio/mpeg',
    'audio/wav',
    'audio/ogg',
    'audio/webm'
  ]
};

/**
 * Date/Time Formats
 */
export const DATE_FORMATS = {
  ISO: 'YYYY-MM-DDTHH:mm:ss.SSSZ',
  DATE: 'YYYY-MM-DD',
  TIME: 'HH:mm:ss',
  DATETIME: 'YYYY-MM-DD HH:mm:ss',
  DISPLAY_DATE: 'MMM DD, YYYY',
  DISPLAY_DATETIME: 'MMM DD, YYYY HH:mm',
  FULL: 'dddd, MMMM Do YYYY, h:mm:ss a'
};

/**
 * Pagination Defaults
 */
export const PAGINATION = {
  DEFAULT_PAGE: 1,
  DEFAULT_LIMIT: 20,
  MAX_LIMIT: 100,
  MIN_LIMIT: 1
};

/**
 * Sort Orders
 */
export const SORT_ORDER = {
  ASC: 'ASC',
  DESC: 'DESC'
};

/**
 * Cache Keys (prefixes)
 */
export const CACHE_KEYS = {
  USER: 'user:',
  PRODUCT: 'product:',
  CATEGORY: 'category:',
  ORDER: 'order:',
  SESSION: 'session:',
  RATE_LIMIT: 'ratelimit:',
  BLACKLIST: 'blacklist:',
  TOKEN: 'token:'
};

/**
 * Cache TTL (Time To Live in seconds)
 */
export const CACHE_TTL = {
  SHORT: 300,        // 5 minutes
  MEDIUM: 1800,      // 30 minutes
  LONG: 3600,        // 1 hour
  VERY_LONG: 86400   // 24 hours
};

/**
 * Regular Expressions
 */
export const REGEX = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  USERNAME: /^[a-zA-Z0-9_-]{3,50}$/,
  PHONE: /^\+?[\d\s\-()]+$/,
  URL: /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/,
  IP_V4: /^(\d{1,3}\.){3}\d{1,3}$/,
  IP_V6: /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i,
  HEX_COLOR: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
  CREDIT_CARD: /^\d{13,19}$/,
  ZIP_CODE: /^\d{5}(-\d{4})?$/,
  ALPHA: /^[a-zA-Z]+$/,
  ALPHANUMERIC: /^[a-zA-Z0-9]+$/,
  NUMERIC: /^\d+$/,
  SLUG: /^[a-z0-9-]+$/
};

/**
 * Error Codes
 */
export const ERROR_CODES = {
  // General
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  FORBIDDEN: 'FORBIDDEN',
  UNAUTHORIZED: 'UNAUTHORIZED',

  // Authentication
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_DISABLED: 'ACCOUNT_DISABLED',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TWO_FACTOR_REQUIRED: '2FA_REQUIRED',

  // Database
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
  FOREIGN_KEY_CONSTRAINT: 'FOREIGN_KEY_CONSTRAINT',
  DATABASE_ERROR: 'DATABASE_ERROR',

  // Business Logic
  INSUFFICIENT_STOCK: 'INSUFFICIENT_STOCK',
  INVALID_COUPON: 'INVALID_COUPON',
  PAYMENT_FAILED: 'PAYMENT_FAILED',
  ORDER_ALREADY_PROCESSED: 'ORDER_ALREADY_PROCESSED',

  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',

  // Security
  ATTACK_DETECTED: 'ATTACK_DETECTED',
  IP_BLOCKED: 'IP_BLOCKED',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY'
};

/**
 * Success Messages
 */
export const SUCCESS_MESSAGES = {
  // General
  SUCCESS: 'Operation completed successfully',
  CREATED: 'Resource created successfully',
  UPDATED: 'Resource updated successfully',
  DELETED: 'Resource deleted successfully',

  // Authentication
  LOGIN_SUCCESS: 'Login successful',
  LOGOUT_SUCCESS: 'Logout successful',
  REGISTRATION_SUCCESS: 'Registration successful',
  PASSWORD_CHANGED: 'Password changed successfully',
  PASSWORD_RESET: 'Password reset successful',

  // Orders
  ORDER_PLACED: 'Order placed successfully',
  ORDER_UPDATED: 'Order updated successfully',
  ORDER_CANCELLED: 'Order cancelled successfully'
};

/**
 * Error Messages
 */
export const ERROR_MESSAGES = {
  // General
  INTERNAL_ERROR: 'An internal error occurred',
  NOT_FOUND: 'Resource not found',
  FORBIDDEN: 'Access forbidden',
  UNAUTHORIZED: 'Authentication required',
  VALIDATION_ERROR: 'Validation failed',

  // Authentication
  INVALID_CREDENTIALS: 'Invalid username or password',
  ACCOUNT_LOCKED: 'Account is locked due to too many failed login attempts',
  ACCOUNT_DISABLED: 'Account has been disabled',
  EMAIL_NOT_VERIFIED: 'Email address not verified',
  INVALID_TOKEN: 'Invalid or expired token',
  TWO_FACTOR_REQUIRED: 'Two-factor authentication required',

  // Database
  DUPLICATE_ENTRY: 'Record already exists',
  DATABASE_ERROR: 'Database operation failed',

  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later',

  // Security
  ATTACK_DETECTED: 'Potential security threat detected',
  IP_BLOCKED: 'Your IP address has been blocked'
};

/**
 * Webhook Events
 */
export const WEBHOOK_EVENTS = {
  USER_CREATED: 'user.created',
  USER_UPDATED: 'user.updated',
  USER_DELETED: 'user.deleted',
  ORDER_CREATED: 'order.created',
  ORDER_UPDATED: 'order.updated',
  ORDER_SHIPPED: 'order.shipped',
  ORDER_DELIVERED: 'order.delivered',
  PAYMENT_SUCCESS: 'payment.success',
  PAYMENT_FAILED: 'payment.failed',
  REVIEW_CREATED: 'review.created',
  ATTACK_DETECTED: 'security.attack_detected'
};

/**
 * Email Templates
 */
export const EMAIL_TEMPLATES = {
  WELCOME: 'welcome',
  EMAIL_VERIFICATION: 'email_verification',
  PASSWORD_RESET: 'password_reset',
  ORDER_CONFIRMATION: 'order_confirmation',
  ORDER_SHIPPED: 'order_shipped',
  ORDER_DELIVERED: 'order_delivered',
  SECURITY_ALERT: 'security_alert',
  ACCOUNT_LOCKED: 'account_locked'
};

/**
 * Default Values
 */
export const DEFAULTS = {
  LANGUAGE: 'en',
  CURRENCY: 'USD',
  TIMEZONE: 'UTC',
  COUNTRY: 'US',
  THEME: 'light',
  PER_PAGE: 20
};

/**
 * Limits
 */
export const LIMITS = {
  MAX_LOGIN_ATTEMPTS: 5,
  MAX_PASSWORD_LENGTH: 255,
  MIN_PASSWORD_LENGTH: 8,
  MAX_USERNAME_LENGTH: 50,
  MIN_USERNAME_LENGTH: 3,
  MAX_EMAIL_LENGTH: 100,
  MAX_UPLOAD_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_CONCURRENT_SESSIONS: 3,
  MAX_CART_ITEMS: 100,
  MAX_WISHLIST_ITEMS: 200,
  MAX_REVIEWS_PER_PRODUCT_PER_USER: 1
};

/**
 * Time Constants (in milliseconds)
 */
export const TIME = {
  SECOND: 1000,
  MINUTE: 60 * 1000,
  HOUR: 60 * 60 * 1000,
  DAY: 24 * 60 * 60 * 1000,
  WEEK: 7 * 24 * 60 * 60 * 1000,
  MONTH: 30 * 24 * 60 * 60 * 1000,
  YEAR: 365 * 24 * 60 * 60 * 1000
};

/**
 * API Versions
 */
export const API_VERSIONS = {
  V1: 'v1',
  V2: 'v2',
  CURRENT: 'v1'
};

/**
 * Feature Flags
 */
export const FEATURE_FLAGS = {
  ENABLE_2FA: false,
  ENABLE_WEBHOOKS: true,
  ENABLE_ANALYTICS: true,
  ENABLE_NOTIFICATIONS: true,
  ENABLE_RATE_LIMITING: true,
  ENABLE_ATTACK_DETECTION: true,
  ENABLE_CACHING: true,
  ENABLE_EMAIL: false
};

/**
 * Environment Types
 */
export const ENVIRONMENTS = {
  DEVELOPMENT: 'development',
  STAGING: 'staging',
  PRODUCTION: 'production',
  TEST: 'test'
};

/**
 * Log Levels
 */
export const LOG_LEVELS = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  HTTP: 'http',
  VERBOSE: 'verbose',
  DEBUG: 'debug',
  SILLY: 'silly'
};

/**
 * Vulnerability Categories (for educational purposes)
 */
export const VULNERABILITY_CATEGORIES = {
  INJECTION: 'Injection',
  BROKEN_AUTH: 'Broken Authentication',
  SENSITIVE_DATA: 'Sensitive Data Exposure',
  XXE: 'XML External Entities (XXE)',
  BROKEN_ACCESS: 'Broken Access Control',
  SECURITY_MISCONFIG: 'Security Misconfiguration',
  XSS: 'Cross-Site Scripting (XSS)',
  INSECURE_DESERIALIZATION: 'Insecure Deserialization',
  VULNERABLE_COMPONENTS: 'Using Components with Known Vulnerabilities',
  INSUFFICIENT_LOGGING: 'Insufficient Logging & Monitoring'
};

/**
 * OWASP Top 10 (2021)
 */
export const OWASP_TOP_10 = [
  'A01:2021 – Broken Access Control',
  'A02:2021 – Cryptographic Failures',
  'A03:2021 – Injection',
  'A04:2021 – Insecure Design',
  'A05:2021 – Security Misconfiguration',
  'A06:2021 – Vulnerable and Outdated Components',
  'A07:2021 – Identification and Authentication Failures',
  'A08:2021 – Software and Data Integrity Failures',
  'A09:2021 – Security Logging and Monitoring Failures',
  'A10:2021 – Server-Side Request Forgery (SSRF)'
];

/**
 * Export all constants
 */
export default {
  HTTP_STATUS,
  USER_ROLES,
  ROLE_HIERARCHY,
  PERMISSIONS,
  ORDER_STATUS,
  PAYMENT_STATUS,
  PAYMENT_METHODS,
  NOTIFICATION_TYPES,
  ATTACK_TYPES,
  ATTACK_SEVERITY,
  SECURITY_EVENTS,
  AUDIT_ACTIONS,
  FILE_TYPES,
  MIME_TYPES,
  DATE_FORMATS,
  PAGINATION,
  SORT_ORDER,
  CACHE_KEYS,
  CACHE_TTL,
  REGEX,
  ERROR_CODES,
  SUCCESS_MESSAGES,
  ERROR_MESSAGES,
  WEBHOOK_EVENTS,
  EMAIL_TEMPLATES,
  DEFAULTS,
  LIMITS,
  TIME,
  API_VERSIONS,
  FEATURE_FLAGS,
  ENVIRONMENTS,
  LOG_LEVELS,
  VULNERABILITY_CATEGORIES,
  OWASP_TOP_10
};
