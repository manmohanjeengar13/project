/**
 * ============================================================================
 * XSS VULNERABILITIES - MODULE INDEX
 * ============================================================================
 * 
 * Central export point for all XSS vulnerability modules
 * 
 * @module vulnerabilities/xss
 * @category Security Training
 * @version 3.0.0
 * 
 * ============================================================================
 * AVAILABLE MODULES:
 * ============================================================================
 * 1. Stored XSS - Persistent script injection
 * 2. Reflected XSS - Non-persistent parameter reflection
 * 3. DOM-Based XSS - Client-side JavaScript vulnerabilities
 * 
 * @author Security Research Team
 */

import { StoredXSS, getStoredXSS, createStoredXSSHandler } from './stored.xss.js';
import { ReflectedXSS, getReflectedXSS, createReflectedXSSHandler } from './reflected.xss.js';
import { DOMBasedXSS, getDOMBasedXSS, createDOMXSSHandler } from './dom.xss.js';
import { Logger } from '../../core/Logger.js';
import { ATTACK_SEVERITY } from '../../config/constants.js';

const logger = Logger.getInstance();

// ============================================================================
// MODULE REGISTRY
// ============================================================================

const XSS_MODULES = {
  STORED: {
    name: 'Stored XSS (Persistent)',
    class: StoredXSS,
    getInstance: getStoredXSS,
    createHandler: createStoredXSSHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 8.8,
    description: 'Persistent malicious scripts stored in database',
    enabled: true,
    owaspId: 'A03:2021',
    cweId: 'CWE-79',
  },
  REFLECTED: {
    name: 'Reflected XSS (Non-Persistent)',
    class: ReflectedXSS,
    getInstance: getReflectedXSS,
    createHandler: createReflectedXSSHandler,
    severity: ATTACK_SEVERITY.MEDIUM,
    cvssScore: 7.1,
    description: 'Immediate reflection of user input without encoding',
    enabled: true,
    owaspId: 'A03:2021',
    cweId: 'CWE-79',
  },
  DOM_BASED: {
    name: 'DOM-Based XSS',
    class: DOMBasedXSS,
    getInstance: getDOMBasedXSS,
    createHandler: createDOMXSSHandler,
    severity: ATTACK_SEVERITY.MEDIUM,
    cvssScore: 7.3,
    description: 'Client-side JavaScript vulnerabilities',
    enabled: true,
    owaspId: 'A03:2021',
    cweId: 'CWE-79',
  },
};

// ============================================================================
// AGGREGATED FUNCTIONS
// ============================================================================

export const getAllXSSModules = () => {
  return {
    stored: getStoredXSS(),
    reflected: getReflectedXSS(),
    domBased: getDOMBasedXSS(),
  };
};

export const getXSSStatistics = () => {
  const modules = getAllXSSModules();
  
  return {
    stored: modules.stored.getStatistics(),
    reflected: modules.reflected.getStatistics(),
    domBased: modules.domBased.getStatistics(),
    summary: {
      totalModules: Object.keys(modules).length,
      totalAttempts: Object.values(modules).reduce((sum, m) => 
        sum + (m.attackStats?.totalAttempts || 0), 0
      ),
      highSeverityModules: Object.entries(XSS_MODULES)
        .filter(([_, m]) => m.severity === ATTACK_SEVERITY.HIGH).length,
      averageCVSS: (Object.values(XSS_MODULES)
        .reduce((sum, m) => sum + m.cvssScore, 0) / Object.keys(XSS_MODULES).length
      ).toFixed(2),
    },
  };
};

export const resetAllXSSStatistics = () => {
  const modules = getAllXSSModules();
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
  
  logger.info('All XSS statistics reset', results);
  
  return {
    success: true,
    results,
    timestamp: new Date().toISOString(),
  };
};

export const getAllVulnerabilityInfo = () => {
  const modules = getAllXSSModules();
  
  return {
    modules: Object.entries(modules).map(([key, module]) => ({
      key,
      ...module.getVulnerabilityInfo(),
    })),
    registry: XSS_MODULES,
    metadata: {
      totalModules: Object.keys(modules).length,
      generatedAt: new Date().toISOString(),
    },
  };
};

export const getXSSModule = (moduleKey) => {
  const modules = getAllXSSModules();
  const module = modules[moduleKey];
  
  if (!module) {
    throw new Error(`XSS module '${moduleKey}' not found`);
  }
  
  return module;
};

export const isXSSModuleEnabled = (moduleKey) => {
  const moduleConfig = Object.entries(XSS_MODULES)
    .find(([key]) => key.toLowerCase() === moduleKey.toLowerCase());
  
  return moduleConfig ? moduleConfig[1].enabled : false;
};

export const getXSSRegistry = () => {
  return {
    ...XSS_MODULES,
    metadata: {
      totalModules: Object.keys(XSS_MODULES).length,
      enabledModules: Object.values(XSS_MODULES).filter(m => m.enabled).length,
      highSeverityModules: Object.values(XSS_MODULES)
        .filter(m => m.severity === ATTACK_SEVERITY.HIGH).length,
    },
  };
};

// ============================================================================
// EXPORTS
// ============================================================================

export {
  StoredXSS,
  ReflectedXSS,
  DOMBasedXSS,
};

export {
  getStoredXSS,
  getReflectedXSS,
  getDOMBasedXSS,
};

export {
  createStoredXSSHandler,
  createReflectedXSSHandler,
  createDOMXSSHandler,
};

export default {
  StoredXSS,
  ReflectedXSS,
  DOMBasedXSS,
  getStoredXSS,
  getReflectedXSS,
  getDOMBasedXSS,
  createStoredXSSHandler,
  createReflectedXSSHandler,
  createDOMXSSHandler,
  getAllXSSModules,
  getXSSStatistics,
  resetAllXSSStatistics,
  getAllVulnerabilityInfo,
  getXSSModule,
  isXSSModuleEnabled,
  getXSSRegistry,
  XSS_MODULES,
};

logger.info('✅ XSS vulnerability modules loaded', {
  modules: Object.keys(XSS_MODULES),
  count: Object.keys(XSS_MODULES).length,
});
