/**
 * ============================================================================
 * SQL INJECTION VULNERABILITIES - MODULE INDEX
 * ============================================================================
 * 
 * Central export point for all SQL injection vulnerability modules
 * 
 * @module vulnerabilities/sqli
 * @category Security Training
 * @version 3.0.0
 * 
 * ============================================================================
 * AVAILABLE MODULES:
 * ============================================================================
 * 1. Classic SQL Injection - Direct string concatenation attacks
 * 2. Union-Based SQL Injection - UNION SELECT data exfiltration
 * 3. Blind SQL Injection - Boolean-based inference attacks
 * 4. Time-Based Blind SQL Injection - Timing-based data extraction
 * 5. Second-Order SQL Injection - Delayed execution attacks
 * 
 * ============================================================================
 * USAGE:
 * ============================================================================
 * import { 
 *   ClassicSQLInjection,
 *   UnionSQLInjection,
 *   BlindSQLInjection,
 *   TimeBasedSQLInjection,
 *   SecondOrderSQLInjection,
 *   getAllSQLiModules,
 *   getSQLiStatistics
 * } from './vulnerabilities/sqli/index.js';
 * 
 * @author Security Research Team
 */

// Import all SQLi modules
import { 
  ClassicSQLInjection, 
  getClassicSQLInjection,
  createVulnerableHandler as createClassicHandler
} from './classic.sqli.js';

import { 
  UnionSQLInjection, 
  getUnionSQLInjection,
  createUnionHandler
} from './union.sqli.js';

import { 
  BlindSQLInjection, 
  getBlindSQLInjection,
  createBlindHandler
} from './blind.sqli.js';

import { 
  TimeBasedSQLInjection, 
  getTimeBasedSQLInjection,
  createTimeBasedHandler
} from './timebased.sqli.js';

import { 
  SecondOrderSQLInjection, 
  getSecondOrderSQLInjection,
  createSecondOrderHandler
} from './secondorder.sqli.js';

import { Logger } from '../../core/Logger.js';
import { ATTACK_SEVERITY } from '../../config/constants.js';

const logger = Logger.getInstance();

// ============================================================================
// MODULE REGISTRY
// ============================================================================

const SQLI_MODULES = {
  CLASSIC: {
    name: 'Classic SQL Injection',
    class: ClassicSQLInjection,
    getInstance: getClassicSQLInjection,
    createHandler: createClassicHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.8,
    description: 'Direct string concatenation in SQL queries',
    enabled: true
  },
  UNION: {
    name: 'Union-Based SQL Injection',
    class: UnionSQLInjection,
    getInstance: getUnionSQLInjection,
    createHandler: createUnionHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.9,
    description: 'UNION SELECT for data exfiltration',
    enabled: true
  },
  BLIND: {
    name: 'Blind SQL Injection',
    class: BlindSQLInjection,
    getInstance: getBlindSQLInjection,
    createHandler: createBlindHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 8.6,
    description: 'Boolean-based inference attacks',
    enabled: true
  },
  TIME_BASED: {
    name: 'Time-Based Blind SQL Injection',
    class: TimeBasedSQLInjection,
    getInstance: getTimeBasedSQLInjection,
    createHandler: createTimeBasedHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 7.5,
    description: 'Timing-based data extraction',
    enabled: true
  },
  SECOND_ORDER: {
    name: 'Second-Order SQL Injection',
    class: SecondOrderSQLInjection,
    getInstance: getSecondOrderSQLInjection,
    createHandler: createSecondOrderHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.1,
    description: 'Delayed execution through stored data',
    enabled: true
  }
};

// ============================================================================
// AGGREGATED FUNCTIONS
// ============================================================================

/**
 * Get all SQLi module instances
 * 
 * @returns {object} All SQLi module instances
 */
export const getAllSQLiModules = () => {
  return {
    classic: getClassicSQLInjection(),
    union: getUnionSQLInjection(),
    blind: getBlindSQLInjection(),
    timeBased: getTimeBasedSQLInjection(),
    secondOrder: getSecondOrderSQLInjection()
  };
};

/**
 * Get aggregated statistics from all SQLi modules
 * 
 * @returns {object} Combined statistics
 */
export const getSQLiStatistics = () => {
  const modules = getAllSQLiModules();
  
  return {
    classic: modules.classic.getStatistics(),
    union: modules.union.getStatistics(),
    blind: modules.blind.getStatistics(),
    timeBased: modules.timeBased.getStatistics(),
    secondOrder: modules.secondOrder.getStatistics(),
    summary: {
      totalModules: Object.keys(modules).length,
      totalAttempts: Object.values(modules).reduce((sum, m) => 
        sum + (m.attackStats?.totalAttempts || 0), 0
      ),
      criticalModules: Object.entries(SQLI_MODULES)
        .filter(([_, m]) => m.severity === ATTACK_SEVERITY.CRITICAL).length,
      averageCVSS: (Object.values(SQLI_MODULES)
        .reduce((sum, m) => sum + m.cvssScore, 0) / Object.keys(SQLI_MODULES).length
      ).toFixed(2)
    }
  };
};

/**
 * Reset all SQLi module statistics
 * 
 * @returns {object} Reset confirmation
 */
export const resetAllSQLiStatistics = () => {
  const modules = getAllSQLiModules();
  const results = {};
  
  Object.entries(modules).forEach(([name, module]) => {
    try {
      module.resetStatistics();
      results[name] = { success: true };
    } catch (error) {
      results[name] = { success: false, error: error.message };
      logger.error(`Failed to reset ${name} statistics`, { error: error.message });
    }
  });
  
  logger.info('All SQLi statistics reset', results);
  
  return {
    success: true,
    results,
    timestamp: new Date().toISOString()
  };
};

/**
 * Get vulnerability information for all modules
 * 
 * @returns {object} All vulnerability information
 */
export const getAllVulnerabilityInfo = () => {
  const modules = getAllSQLiModules();
  
  return {
    modules: Object.entries(modules).map(([key, module]) => ({
      key,
      ...module.getVulnerabilityInfo()
    })),
    registry: SQLI_MODULES,
    metadata: {
      totalModules: Object.keys(modules).length,
      generatedAt: new Date().toISOString()
    }
  };
};

/**
 * Get module by key
 * 
 * @param {string} moduleKey - Module key (classic, union, blind, etc.)
 * @returns {object} Module instance
 */
export const getSQLiModule = (moduleKey) => {
  const modules = getAllSQLiModules();
  const module = modules[moduleKey];
  
  if (!module) {
    throw new Error(`SQLi module '${moduleKey}' not found`);
  }
  
  return module;
};

/**
 * Check if module is enabled
 * 
 * @param {string} moduleKey - Module key
 * @returns {boolean} Enabled status
 */
export const isSQLiModuleEnabled = (moduleKey) => {
  const moduleConfig = Object.entries(SQLI_MODULES)
    .find(([key]) => key.toLowerCase() === moduleKey.toLowerCase());
  
  return moduleConfig ? moduleConfig[1].enabled : false;
};

/**
 * Get module registry
 * 
 * @returns {object} Module registry
 */
export const getSQLiRegistry = () => {
  return {
    ...SQLI_MODULES,
    metadata: {
      totalModules: Object.keys(SQLI_MODULES).length,
      enabledModules: Object.values(SQLI_MODULES).filter(m => m.enabled).length,
      criticalModules: Object.values(SQLI_MODULES)
        .filter(m => m.severity === ATTACK_SEVERITY.CRITICAL).length
    }
  };
};

/**
 * Generate comprehensive SQLi report
 * 
 * @param {Date} startDate - Report start date
 * @param {Date} endDate - Report end date
 * @returns {Promise<object>} Comprehensive report
 */
export const generateComprehensiveSQLiReport = async (startDate, endDate) => {
  const modules = getAllSQLiModules();
  const reports = {};
  
  // Generate reports for each module
  for (const [key, module] of Object.entries(modules)) {
    try {
      if (typeof module.generateAttackReport === 'function') {
        reports[key] = await module.generateAttackReport(startDate, endDate);
      } else if (typeof module.generateUnionAttackReport === 'function') {
        reports[key] = await module.generateUnionAttackReport(startDate, endDate);
      }
    } catch (error) {
      logger.error(`Failed to generate report for ${key}`, { error: error.message });
      reports[key] = { error: error.message };
    }
  }
  
  return {
    period: { start: startDate, end: endDate },
    reports,
    statistics: getSQLiStatistics(),
    vulnerabilityInfo: getAllVulnerabilityInfo(),
    generatedAt: new Date().toISOString()
  };
};

// ============================================================================
// EXPORTS
// ============================================================================

// Export classes
export {
  ClassicSQLInjection,
  UnionSQLInjection,
  BlindSQLInjection,
  TimeBasedSQLInjection,
  SecondOrderSQLInjection
};

// Export factory functions
export {
  getClassicSQLInjection,
  getUnionSQLInjection,
  getBlindSQLInjection,
  getTimeBasedSQLInjection,
  getSecondOrderSQLInjection
};

// Export handler creators
export {
  createClassicHandler,
  createUnionHandler,
  createBlindHandler,
  createTimeBasedHandler,
  createSecondOrderHandler
};

// Default export
export default {
  // Classes
  ClassicSQLInjection,
  UnionSQLInjection,
  BlindSQLInjection,
  TimeBasedSQLInjection,
  SecondOrderSQLInjection,
  
  // Factory functions
  getClassicSQLInjection,
  getUnionSQLInjection,
  getBlindSQLInjection,
  getTimeBasedSQLInjection,
  getSecondOrderSQLInjection,
  
  // Handler creators
  createClassicHandler,
  createUnionHandler,
  createBlindHandler,
  createTimeBasedHandler,
  createSecondOrderHandler,
  
  // Aggregated functions
  getAllSQLiModules,
  getSQLiStatistics,
  resetAllSQLiStatistics,
  getAllVulnerabilityInfo,
  getSQLiModule,
  isSQLiModuleEnabled,
  getSQLiRegistry,
  generateComprehensiveSQLiReport,
  
  // Registry
  SQLI_MODULES
};

// Log module initialization
logger.info('✅ SQLi vulnerability modules loaded', {
  modules: Object.keys(SQLI_MODULES),
  count: Object.keys(SQLI_MODULES).length
});
