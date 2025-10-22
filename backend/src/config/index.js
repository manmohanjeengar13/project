/**
 * Configuration Module Exports
 * Central export point for all configuration modules
 */

// Main configuration
export { Config, validateConfig } from './environment.js';

// Database configuration
export { 
  databaseConfig, 
  tables, 
  views, 
  procedures,
  commonQueries,
  isolationLevels,
  transactionOptions,
  getDatabaseConnectionString,
  validateDatabaseConfig
} from './database.js';

// Security configuration
export {
  securityMode,
  authConfig,
  rateLimitConfig,
  corsConfig,
  helmetConfig,
  validationConfig,
  csrfConfig,
  attackDetectionConfig,
  fileUploadConfig,
  encryptionConfig,
  auditConfig
} from './security.js';

// Constants
export {
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
} from './constants.js';

/**
 * Get all configuration
 */
export const getAllConfig = () => ({
  app: Config.app,
  security: Config.security,
  database: Config.database,
  redis: Config.redis,
  session: Config.session,
  jwt: Config.jwt,
  auth: Config.auth,
  rateLimit: Config.rateLimit,
  cors: Config.cors,
  upload: Config.upload,
  email: Config.email,
  logging: Config.logging,
  helmet: Config.helmet,
  hsts: Config.hsts,
  csp: Config.csp
});

/**
 * Validate all configurations
 */
export const validateAllConfigs = () => {
  const errors = [];
  
  // Validate main config
  if (!validateConfig()) {
    errors.push('Main configuration validation failed');
  }
  
  // Validate database config
  const dbValidation = validateDatabaseConfig();
  if (!dbValidation.valid) {
    errors.push(...dbValidation.errors);
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

export default {
  Config,
  getAllConfig,
  validateAllConfigs
};
