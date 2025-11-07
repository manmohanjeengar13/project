/**
 * ============================================================================
 * ACCESS CONTROL VULNERABILITIES - CENTRAL INDEX
 * ============================================================================
 * 
 * Enterprise-Grade Access Control Vulnerability Suite
 * Centralized export for all access control vulnerability modules
 * 
 * @module vulnerabilities/access
 * @category Security Training - OWASP A01:2021
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * MODULE OVERVIEW:
 * ============================================================================
 * This module provides a unified interface for all access control
 * vulnerability demonstrations including:
 * 
 * 1. IDOR (Insecure Direct Object References)
 * 2. Force Browsing (Forced Directory Browsing)
 * 3. Path Traversal (Directory Traversal)
 * 4. Privilege Escalation (Vertical & Horizontal)
 * 
 * All modules follow military-grade enterprise standards with:
 * - Comprehensive attack detection
 * - Real-time monitoring and logging
 * - Statistical analysis and reporting
 * - Secure reference implementations
 * - OWASP compliance
 * 
 * @author Elite Security Research Team
 */

// Import all access control vulnerability modules
import { Idor, getIdor, createVulnerableHandler as createIdorHandler } from './idor.js';
import { 
  ForceBrowsing, 
  getForceBrowsing, 
  createVulnerableHandler as createForceBrowsingHandler 
} from './forceBrowsing.js';
import { 
  PathTraversal, 
  getPathTraversal, 
  createVulnerableHandler as createPathTraversalHandler 
} from './pathTraversal.js';
import { 
  PrivilegeEscalation, 
  getPrivilegeEscalation, 
  createVulnerableHandler as createPrivilegeEscalationHandler 
} from './privilegeEscalation.js';

import { Logger } from '../../core/Logger.js';

const logger = Logger.getInstance();

// ============================================================================
// VULNERABILITY REGISTRY
// ============================================================================

/**
 * Registry of all access control vulnerabilities
 * Provides metadata and instance management
 */
export const ACCESS_VULNERABILITIES = {
  IDOR: {
    id: 'IDOR',
    name: 'Insecure Direct Object References',
    class: Idor,
    getInstance: getIdor,
    createHandler: createIdorHandler,
    cvssScore: 8.2,
    owaspId: 'A01:2021',
    cweId: 'CWE-639',
    enabled: true
  },
  
  FORCE_BROWSING: {
    id: 'FORCE_BROWSING',
    name: 'Force Browsing',
    class: ForceBrowsing,
    getInstance: getForceBrowsing,
    createHandler: createForceBrowsingHandler,
    cvssScore: 8.6,
    owaspId: 'A01:2021',
    cweId: 'CWE-425',
    enabled: true
  },
  
  PATH_TRAVERSAL: {
    id: 'PATH_TRAVERSAL',
    name: 'Path Traversal',
    class: PathTraversal,
    getInstance: getPathTraversal,
    createHandler: createPathTraversalHandler,
    cvssScore: 9.1,
    owaspId: 'A01:2021',
    cweId: 'CWE-22',
    enabled: true
  },
  
  PRIVILEGE_ESCALATION: {
    id: 'PRIVILEGE_ESCALATION',
    name: 'Privilege Escalation',
    class: PrivilegeEscalation,
    getInstance: getPrivilegeEscalation,
    createHandler: createPrivilegeEscalationHandler,
    cvssScore: 9.8,
    owaspId: 'A01:2021',
    cweId: 'CWE-269',
    enabled: true
  }
};

// ============================================================================
// UNIFIED INTERFACE
// ============================================================================

/**
 * Get all access vulnerability instances
 * @returns {object} Map of vulnerability instances
 */
export const getAllAccessVulnerabilities = () => {
  const instances = {};
  
  for (const [key, vuln] of Object.entries(ACCESS_VULNERABILITIES)) {
    if (vuln.enabled) {
      instances[key] = vuln.getInstance();
    }
  }
  
  return instances;
};

/**
 * Get specific vulnerability instance by ID
 * @param {string} vulnerabilityId - Vulnerability ID
 * @returns {object} Vulnerability instance
 */
export const getAccessVulnerability = (vulnerabilityId) => {
  const vuln = ACCESS_VULNERABILITIES[vulnerabilityId];
  
  if (!vuln) {
    throw new Error(`Vulnerability ${vulnerabilityId} not found`);
  }
  
  if (!vuln.enabled) {
    throw new Error(`Vulnerability ${vulnerabilityId} is disabled`);
  }
  
  return vuln.getInstance();
};

/**
 * Get combined statistics from all access vulnerabilities
 * @returns {object} Combined statistics
 */
export const getAllAccessStatistics = () => {
  const instances = getAllAccessVulnerabilities();
  const combinedStats = {
    totalAttempts: 0,
    successfulAttacks: 0,
    blockedAttempts: 0,
    byVulnerability: {},
    timestamp: new Date().toISOString()
  };
  
  for (const [key, instance] of Object.entries(instances)) {
    const stats = instance.getStatistics();
    combinedStats.byVulnerability[key] = stats;
    combinedStats.totalAttempts += stats.totalAttempts || 0;
    combinedStats.successfulAttacks += (stats.successfulAccess || stats.successfulEscalations || stats.successfulTraversals || 0);
    combinedStats.blockedAttempts += stats.blockedAttempts || 0;
  }
  
  combinedStats.successRate = combinedStats.totalAttempts > 0
    ? ((combinedStats.successfulAttacks / combinedStats.totalAttempts) * 100).toFixed(2) + '%'
    : '0%';
  
  return combinedStats;
};

/**
 * Get combined vulnerability information
 * @returns {array} Array of vulnerability information
 */
export const getAllAccessVulnerabilityInfo = () => {
  const instances = getAllAccessVulnerabilities();
  const vulnerabilityInfo = [];
  
  for (const [key, instance] of Object.entries(instances)) {
    vulnerabilityInfo.push({
      id: key,
      ...instance.getVulnerabilityInfo()
    });
  }
  
  return vulnerabilityInfo;
};

/**
 * Reset all access vulnerability statistics
 * @returns {object} Reset confirmation
 */
export const resetAllAccessStatistics = () => {
  const instances = getAllAccessVulnerabilities();
  let resetCount = 0;
  
  for (const instance of Object.values(instances)) {
    if (typeof instance.resetStatistics === 'function') {
      instance.resetStatistics();
      resetCount++;
    }
  }
  
  logger.info('Access vulnerability statistics reset', { resetCount });
  
  return {
    success: true,
    message: `Reset statistics for ${resetCount} vulnerabilities`,
    timestamp: new Date().toISOString()
  };
};

/**
 * Generate comprehensive access vulnerability report
 * @param {Date} startDate - Report start date
 * @param {Date} endDate - Report end date
 * @returns {Promise<object>} Comprehensive report
 */
export const generateAccessVulnerabilityReport = async (startDate, endDate) => {
  const instances = getAllAccessVulnerabilities();
  const report = {
    period: {
      start: startDate,
      end: endDate
    },
    summary: getAllAccessStatistics(),
    vulnerabilities: {},
    timestamp: new Date().toISOString()
  };
  
  // Generate individual reports
  for (const [key, instance] of Object.entries(instances)) {
    if (typeof instance.generateAttackReport === 'function') {
      try {
        report.vulnerabilities[key] = await instance.generateAttackReport(startDate, endDate);
      } catch (error) {
        logger.error(`Failed to generate report for ${key}`, { error: error.message });
        report.vulnerabilities[key] = { error: error.message };
      }
    }
  }
  
  return report;
};

/**
 * Check if specific vulnerability is enabled
 * @param {string} vulnerabilityId - Vulnerability ID
 * @returns {boolean} Enabled status
 */
export const isAccessVulnerabilityEnabled = (vulnerabilityId) => {
  const vuln = ACCESS_VULNERABILITIES[vulnerabilityId];
  return vuln ? vuln.enabled : false;
};

/**
 * Enable/disable specific vulnerability
 * @param {string} vulnerabilityId - Vulnerability ID
 * @param {boolean} enabled - Enable/disable
 * @returns {object} Update result
 */
export const setAccessVulnerabilityStatus = (vulnerabilityId, enabled) => {
  const vuln = ACCESS_VULNERABILITIES[vulnerabilityId];
  
  if (!vuln) {
    throw new Error(`Vulnerability ${vulnerabilityId} not found`);
  }
  
  vuln.enabled = enabled;
  
  logger.info(`Access vulnerability ${vulnerabilityId} ${enabled ? 'enabled' : 'disabled'}`);
  
  return {
    success: true,
    vulnerabilityId,
    enabled,
    timestamp: new Date().toISOString()
  };
};

// ============================================================================
// EXPORTS
// ============================================================================

// Export individual vulnerability classes
export { Idor, getIdor, createIdorHandler };
export { ForceBrowsing, getForceBrowsing, createForceBrowsingHandler };
export { PathTraversal, getPathTraversal, createPathTraversalHandler };
export { PrivilegeEscalation, getPrivilegeEscalation, createPrivilegeEscalationHandler };

// Export unified interface functions
export {
  getAllAccessVulnerabilities,
  getAccessVulnerability,
  getAllAccessStatistics,
  getAllAccessVulnerabilityInfo,
  resetAllAccessStatistics,
  generateAccessVulnerabilityReport,
  isAccessVulnerabilityEnabled,
  setAccessVulnerabilityStatus
};

// Default export
export default {
  // Registry
  ACCESS_VULNERABILITIES,
  
  // Classes
  Idor,
  ForceBrowsing,
  PathTraversal,
  PrivilegeEscalation,
  
  // Factory functions
  getIdor,
  getForceBrowsing,
  getPathTraversal,
  getPrivilegeEscalation,
  
  // Handler creators
  createIdorHandler,
  createForceBrowsingHandler,
  createPathTraversalHandler,
  createPrivilegeEscalationHandler,
  
  // Unified interface
  getAllAccessVulnerabilities,
  getAccessVulnerability,
  getAllAccessStatistics,
  getAllAccessVulnerabilityInfo,
  resetAllAccessStatistics,
  generateAccessVulnerabilityReport,
  isAccessVulnerabilityEnabled,
  setAccessVulnerabilityStatus
};

// ============================================================================
// INITIALIZATION
// ============================================================================

logger.info('✅ Access Control Vulnerabilities Module Loaded', {
  vulnerabilities: Object.keys(ACCESS_VULNERABILITIES),
  enabled: Object.values(ACCESS_VULNERABILITIES).filter(v => v.enabled).length,
  total: Object.keys(ACCESS_VULNERABILITIES).length
});
