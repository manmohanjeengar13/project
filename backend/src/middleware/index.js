/**
 * Middleware Module Exports
 * Central export point for all middleware
 */

// Attack Detection
export {
  attackDetectionMiddleware,
  checkIPBlacklist,
  honeypotDetection,
  detectRateLimitAbuse,
  detectAnomalousUserAgent,
  getIPAttackStats,
  clearAttackCounter,
  unblockIP
} from './attackDetection.js';

// Authentication
export {
  verifyJWT,
  verifySession,
  authenticate,
  optionalAuth,
  requireLogin,
  isAuthenticated,
  revokeToken,
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  refreshAccessToken
} from './authentication.js';

// Authorization
export {
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
} from './authorization.js';

// CSRF Protection
export {
  csrfMiddleware,
  initCsrfToken,
  getCsrfToken,
  refreshCsrfToken,
  csrfProtect,
  skipCsrf,
  csrfIf,
  doubleSubmitCookie,
  synchronizerToken,
  rotateCsrfToken,
  validateCsrfToken,
  generateCsrfToken,
  getCsrfStats
} from './csrf.js';

// Error Handler
export {
  errorHandler,
  notFoundHandler,
  asyncHandler,
  setupUnhandledRejectionHandler,
  setupUncaughtExceptionHandler,
  formatErrorResponse,
  createError,
  throwIf,
  assert,
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  DatabaseError,
  RateLimitError,
  AttackDetectedError
} from './errorHandler.js';

// Mode Switch
export {
  modeSwitchMiddleware,
  getCurrentMode,
  setSecurityMode,
  toggleSecurityMode,
  getModeHistory,
  clearModeHistory,
  getModeStats,
  requireMode,
  requireVulnerableMode,
  requireSecureMode,
  skipInMode,
  onlyInMode,
  getVulnerabilityStatus,
  toggleVulnerability,
  modeChangeController,
  toggleModeController,
  getModeInfoController,
  getModeHistoryController,
  includeModeInfo,
  warnVulnerableMode,
  withTemporaryMode,
  scheduleModeChange,
  resetToDefaultMode
} from './modeSwitch.js';

// Rate Limiting
export {
  rateLimitMiddleware,
  apiRateLimit,
  loginRateLimit,
  registrationRateLimit,
  passwordResetRateLimit,
  uploadRateLimit,
  searchRateLimit,
  commentRateLimit,
  roleBasedRateLimit,
  createEndpointLimiter,
  slowDown,
  adaptiveRateLimit,
  burstRateLimit,
  conditionalRateLimit,
  skipRateLimitForAuth,
  getRateLimitInfo,
  resetRateLimit,
  getRateLimitStats
} from './rateLimit.js';

// Sanitization
export {
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
} from './sanitization.js';

// Validation
export {
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
} from './validation.js';

/**
 * Middleware chains for common use cases
 */

// Standard API protection
export const protectAPI = [
  rateLimitMiddleware,
  authenticate,
  sanitizationMiddleware
];

// Admin-only routes
export const protectAdmin = [
  rateLimitMiddleware,
  authenticate,
  requireAdmin,
  sanitizationMiddleware
];

// Login protection
export const protectLogin = [
  loginRateLimit,
  sanitizationMiddleware
];

// Registration protection
export const protectRegistration = [
  registrationRateLimit,
  sanitizationMiddleware
];

// File upload protection
export const protectUpload = [
  uploadRateLimit,
  authenticate,
  sanitizationMiddleware
];

// Public API (no auth required)
export const protectPublic = [
  apiRateLimit,
  sanitizationMiddleware
];

/**
 * Middleware statistics aggregator
 */
export const getMiddlewareStats = async () => {
  const { getCsrfStats } = await import('./csrf.js');
  const { getRateLimitStats } = await import('./rateLimit.js');
  const { getSanitizationStats } = await import('./sanitization.js');
  const { getValidationStats } = await import('./validation.js');
  const { getModeStats } = await import('./modeSwitch.js');

  return {
    csrf: await getCsrfStats(),
    rateLimit: await getRateLimitStats(),
    sanitization: getSanitizationStats(),
    validation: getValidationStats(),
    mode: getModeStats()
  };
};

/**
 * Initialize all middleware
 */
export const initializeMiddleware = async () => {
  const { Logger } = await import('../core/Logger.js');
  const logger = Logger.getInstance();

  logger.info('🛡️  Initializing middleware...');

  // Setup error handlers
  const { setupUnhandledRejectionHandler, setupUncaughtExceptionHandler } = await import('./errorHandler.js');
  setupUnhandledRejectionHandler();
  setupUncaughtExceptionHandler();

  logger.info('✅ Middleware initialized');
};

export default {
  // Attack Detection
  attackDetectionMiddleware,
  checkIPBlacklist,
  honeypotDetection,
  
  // Authentication
  authenticate,
  verifyJWT,
  verifySession,
  optionalAuth,
  requireLogin,
  
  // Authorization
  requireRole,
  requireAdmin,
  requireModerator,
  
  // CSRF
  csrfMiddleware,
  initCsrfToken,
  
  // Error Handling
  errorHandler,
  notFoundHandler,
  asyncHandler,
  
  // Mode Switch
  modeSwitchMiddleware,
  getCurrentMode,
  setSecurityMode,
  toggleSecurityMode,
  
  // Rate Limiting
  rateLimitMiddleware,
  apiRateLimit,
  loginRateLimit,
  
  // Sanitization
  sanitizationMiddleware,
  sanitizeHTML,
  sanitizeEmail,
  
  // Validation
  validate,
  validateSchema,
  schemas,
  rules,
  
  // Chains
  protectAPI,
  protectAdmin,
  protectLogin,
  protectRegistration,
  protectUpload,
  protectPublic,
  
  // Utilities
  getMiddlewareStats,
  initializeMiddleware
};
