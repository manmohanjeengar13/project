/**
 * Mode Switch Middleware
 * Dynamically switch between vulnerable and secure modes
 */

import { Logger } from '../core/Logger.js';
import { Cache } from '../core/Cache.js';
import { Config } from '../config/environment.js';
import { securityMode } from '../config/security.js';
import { HTTP_STATUS, USER_ROLES } from '../config/constants.js';

const logger = Logger.getInstance();
const cache = Cache.getInstance();

// Current mode state
let currentMode = Config.security.mode;
let modeHistory = [];

/**
 * Mode Switch Middleware
 * Injects mode information into request
 */
export const modeSwitchMiddleware = (req, res, next) => {
  // Attach current mode to request
  req.securityMode = currentMode;
  req.isVulnerable = currentMode === 'vulnerable';
  req.isSecure = currentMode === 'secure';
  
  // Add mode info to response headers
  res.setHeader('X-Security-Mode', currentMode.toUpperCase());
  res.setHeader('X-Vulnerabilities-Enabled', req.isVulnerable ? 'true' : 'false');
  
  next();
};

/**
 * Get current security mode
 */
export const getCurrentMode = () => {
  return {
    mode: currentMode,
    isVulnerable: currentMode === 'vulnerable',
    isSecure: currentMode === 'secure',
    changedAt: modeHistory.length > 0 ? modeHistory[modeHistory.length - 1].timestamp : null,
    changedBy: modeHistory.length > 0 ? modeHistory[modeHistory.length - 1].changedBy : null
  };
};

/**
 * Set security mode
 */
export const setSecurityMode = async (mode, changedBy = 'system') => {
  const validModes = ['vulnerable', 'secure'];
  
  if (!validModes.includes(mode)) {
    throw new Error(`Invalid mode: ${mode}. Must be 'vulnerable' or 'secure'`);
  }

  const previousMode = currentMode;
  currentMode = mode;

  // Update security mode object
  securityMode.current = mode;
  securityMode.isVulnerable = mode === 'vulnerable';
  securityMode.isSecure = mode === 'secure';

  // Log mode change
  logger.info(`Security mode changed: ${previousMode} → ${mode}`, {
    changedBy,
    timestamp: new Date().toISOString()
  });

  // Add to history
  modeHistory.push({
    previousMode,
    newMode: mode,
    changedBy,
    timestamp: new Date().toISOString()
  });

  // Keep only last 100 changes
  if (modeHistory.length > 100) {
    modeHistory = modeHistory.slice(-100);
  }

  // Clear cache on mode change
  try {
    await cache.clear();
    logger.info('Cache cleared after mode change');
  } catch (error) {
    logger.error('Failed to clear cache:', error);
  }

  // Broadcast mode change via WebSocket
  try {
    const { WebSocket } = await import('../core/WebSocket.js');
    const ws = WebSocket.getInstance();
    if (ws.io) {
      await ws.broadcast('mode_changed', {
        previousMode,
        newMode: mode,
        changedBy,
        timestamp: new Date().toISOString()
      });
    }
  } catch (error) {
    // WebSocket not available
  }

  return {
    success: true,
    previousMode,
    newMode: mode,
    message: `Security mode changed to ${mode}`
  };
};

/**
 * Toggle security mode
 */
export const toggleSecurityMode = async (changedBy = 'system') => {
  const newMode = currentMode === 'vulnerable' ? 'secure' : 'vulnerable';
  return await setSecurityMode(newMode, changedBy);
};

/**
 * Get mode history
 */
export const getModeHistory = (limit = 50) => {
  return modeHistory.slice(-limit).reverse();
};

/**
 * Clear mode history
 */
export const clearModeHistory = () => {
  modeHistory = [];
  logger.info('Mode history cleared');
  return { success: true, message: 'Mode history cleared' };
};

/**
 * Get mode statistics
 */
export const getModeStats = () => {
  const vulnerableCount = modeHistory.filter(h => h.newMode === 'vulnerable').length;
  const secureCount = modeHistory.filter(h => h.newMode === 'secure').length;
  
  return {
    currentMode,
    totalChanges: modeHistory.length,
    vulnerableActivations: vulnerableCount,
    secureActivations: secureCount,
    lastChange: modeHistory.length > 0 ? modeHistory[modeHistory.length - 1] : null,
    uptime: process.uptime()
  };
};

/**
 * Require specific mode
 */
export const requireMode = (requiredMode) => {
  return (req, res, next) => {
    if (currentMode !== requiredMode) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: 'WRONG_MODE',
        message: `This endpoint requires ${requiredMode} mode. Current mode: ${currentMode}`,
        currentMode,
        requiredMode
      });
    }
    next();
  };
};

/**
 * Require vulnerable mode
 */
export const requireVulnerableMode = requireMode('vulnerable');

/**
 * Require secure mode
 */
export const requireSecureMode = requireMode('secure');

/**
 * Skip in mode
 */
export const skipInMode = (mode, ...middleware) => {
  return (req, res, next) => {
    if (currentMode === mode) {
      return next();
    }
    
    // Apply middleware chain
    let index = 0;
    const runNext = (err) => {
      if (err) return next(err);
      if (index >= middleware.length) return next();
      
      const currentMiddleware = middleware[index++];
      currentMiddleware(req, res, runNext);
    };
    runNext();
  };
};

/**
 * Apply only in mode
 */
export const onlyInMode = (mode, ...middleware) => {
  return (req, res, next) => {
    if (currentMode !== mode) {
      return next();
    }
    
    // Apply middleware chain
    let index = 0;
    const runNext = (err) => {
      if (err) return next(err);
      if (index >= middleware.length) return next();
      
      const currentMiddleware = middleware[index++];
      currentMiddleware(req, res, runNext);
    };
    runNext();
  };
};

/**
 * Get vulnerability status
 */
export const getVulnerabilityStatus = () => {
  return {
    mode: currentMode,
    vulnerabilities: {
      sqli: securityMode.vulnerabilities.sqli && currentMode === 'vulnerable',
      xss: securityMode.vulnerabilities.xss && currentMode === 'vulnerable',
      csrf: securityMode.vulnerabilities.csrf && currentMode === 'vulnerable',
      idor: securityMode.vulnerabilities.idor && currentMode === 'vulnerable',
      commandInjection: securityMode.vulnerabilities.commandInjection && currentMode === 'vulnerable',
      pathTraversal: securityMode.vulnerabilities.pathTraversal && currentMode === 'vulnerable',
      xxe: securityMode.vulnerabilities.xxe && currentMode === 'vulnerable',
      ssrf: securityMode.vulnerabilities.ssrf && currentMode === 'vulnerable'
    }
  };
};

/**
 * Toggle specific vulnerability
 */
export const toggleVulnerability = (vulnerabilityType, enabled) => {
  if (!securityMode.vulnerabilities.hasOwnProperty(vulnerabilityType)) {
    throw new Error(`Unknown vulnerability type: ${vulnerabilityType}`);
  }

  securityMode.vulnerabilities[vulnerabilityType] = enabled;

  logger.info(`Vulnerability ${vulnerabilityType} ${enabled ? 'enabled' : 'disabled'}`);

  return {
    success: true,
    vulnerability: vulnerabilityType,
    enabled,
    message: `${vulnerabilityType} vulnerability ${enabled ? 'enabled' : 'disabled'}`
  };
};

/**
 * Mode change controller (API endpoint handler)
 */
export const modeChangeController = async (req, res) => {
  try {
    const { mode } = req.body;
    const changedBy = req.user ? `${req.user.username} (${req.user.id})` : 'anonymous';

    // Require admin role for mode change
    if (req.user && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Only administrators can change security mode'
      });
    }

    const result = await setSecurityMode(mode, changedBy);

    res.json({
      success: true,
      ...result,
      vulnerabilities: getVulnerabilityStatus().vulnerabilities
    });
  } catch (error) {
    logger.error('Mode change error:', error);
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: 'MODE_CHANGE_FAILED',
      message: error.message
    });
  }
};

/**
 * Toggle mode controller
 */
export const toggleModeController = async (req, res) => {
  try {
    const changedBy = req.user ? `${req.user.username} (${req.user.id})` : 'anonymous';

    // Require admin role
    if (req.user && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      return res.status(HTTP_STATUS.FORBIDDEN).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Only administrators can toggle security mode'
      });
    }

    const result = await toggleSecurityMode(changedBy);

    res.json({
      success: true,
      ...result,
      vulnerabilities: getVulnerabilityStatus().vulnerabilities
    });
  } catch (error) {
    logger.error('Mode toggle error:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: 'MODE_TOGGLE_FAILED',
      message: error.message
    });
  }
};

/**
 * Get mode info controller
 */
export const getModeInfoController = (req, res) => {
  res.json({
    success: true,
    ...getCurrentMode(),
    stats: getModeStats(),
    vulnerabilities: getVulnerabilityStatus().vulnerabilities
  });
};

/**
 * Get mode history controller
 */
export const getModeHistoryController = (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  
  res.json({
    success: true,
    history: getModeHistory(limit),
    total: modeHistory.length
  });
};

/**
 * Mode info response middleware
 */
export const includeModeInfo = (req, res, next) => {
  const originalJson = res.json.bind(res);
  
  res.json = function(data) {
    if (data && typeof data === 'object') {
      data._mode = {
        current: currentMode,
        isVulnerable: currentMode === 'vulnerable'
      };
    }
    return originalJson(data);
  };
  
  next();
};

/**
 * Warn if in vulnerable mode
 */
export const warnVulnerableMode = (req, res, next) => {
  if (currentMode === 'vulnerable') {
    res.setHeader('X-Warning', 'VULNERABLE MODE ACTIVE - FOR EDUCATIONAL PURPOSES ONLY');
    logger.debug('Request processed in vulnerable mode', {
      path: req.path,
      method: req.method,
      ip: req.ip
    });
  }
  next();
};

/**
 * Temporary mode switch (for testing)
 */
export const withTemporaryMode = async (mode, callback) => {
  const originalMode = currentMode;
  
  try {
    await setSecurityMode(mode, 'temporary');
    const result = await callback();
    await setSecurityMode(originalMode, 'restore');
    return result;
  } catch (error) {
    await setSecurityMode(originalMode, 'restore');
    throw error;
  }
};

/**
 * Schedule mode change
 */
export const scheduleModeChange = (mode, delayMs) => {
  return new Promise((resolve) => {
    setTimeout(async () => {
      const result = await setSecurityMode(mode, 'scheduled');
      resolve(result);
    }, delayMs);
  });
};

/**
 * Reset to default mode
 */
export const resetToDefaultMode = async () => {
  const defaultMode = Config.security.mode;
  return await setSecurityMode(defaultMode, 'reset');
};

/**
 * Export mode utilities
 */
export default {
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
};
