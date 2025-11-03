/**
 * ============================================================================
 * INJECTION VULNERABILITIES - MODULE INDEX
 * ============================================================================
 * 
 * Central export point for all injection vulnerability modules
 * 
 * @module vulnerabilities/injection
 * @category Security Training
 * @version 3.0.0
 * 
 * ============================================================================
 * AVAILABLE MODULES:
 * ============================================================================
 * 1. Command Injection - OS command execution attacks
 * 2. LDAP Injection - Directory service manipulation
 * 3. XML/XXE Injection - XML external entity attacks
 * 4. Template Injection - Server-side template injection (SSTI)
 * 
 * ============================================================================
 * USAGE:
 * ============================================================================
 * import { 
 *   CommandInjection,
 *   LDAPInjection,
 *   XMLInjection,
 *   TemplateInjection,
 *   getAllInjectionModules,
 *   getInjectionStatistics
 * } from './vulnerabilities/injection/index.js';
 * 
 * @author Security Research Team
 */

// Import all injection modules
import { 
  CommandInjection, 
  getCommandInjection,
  createCommandHandler
} from './command.injection.js';

import { 
  LDAPInjection, 
  getLDAPInjection,
  createLDAPHandler
} from './ldap.injection.js';

import { 
  XMLInjection, 
  getXMLInjection,
  createXMLHandler
} from './xml.injection.js';

import { 
  TemplateInjection, 
  getTemplateInjection,
  createTemplateHandler
} from './template.injection.js';

import { Logger } from '../../core/Logger.js';
import { ATTACK_SEVERITY } from '../../config/constants.js';

const logger = Logger.getInstance();

// ============================================================================
// MODULE REGISTRY
// ============================================================================

const INJECTION_MODULES = {
  COMMAND: {
    name: 'OS Command Injection',
    class: CommandInjection,
    getInstance: getCommandInjection,
    createHandler: createCommandHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.8,
    description: 'Execute arbitrary operating system commands',
    enabled: true,
    owaspId: 'A03:2021',
    cweId: 'CWE-78',
  },
  LDAP: {
    name: 'LDAP Injection',
    class: LDAPInjection,
    getInstance: getLDAPInjection,
    createHandler: createLDAPHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 8.1,
    description: 'Manipulate LDAP queries for authentication bypass',
    enabled: true,
    owaspId: 'A03:2021',
    cweId: 'CWE-90',
  },
  XML: {
    name: 'XML/XXE Injection',
    class: XMLInjection,
    getInstance: getXMLInjection,
    createHandler: createXMLHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.1,
    description: 'XML External Entity attacks for file disclosure and SSRF',
    enabled: true,
    owaspId: 'A03:2021, A05:2021',
    cweId: 'CWE-611',
  },
  TEMPLATE: {
    name: 'Server-Side Template Injection',
    class: TemplateInjection,
    getInstance: getTemplateInjection,
    createHandler: createTemplateHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.8,
    description: 'Inject malicious code into server-side templates',
    enabled: true,
    owaspId: 'A03:2021',
    cweId: 'CWE-94',
  },
};

// ============================================================================
// AGGREGATED FUNCTIONS
// ============================================================================

/**
 * Get all injection module instances
 * 
 * @returns {object} All injection module instances
 */
export const getAllInjectionModules = () => {
  return {
    command: getCommandInjection(),
    ldap: getLDAPInjection(),
    xml: getXMLInjection(),
    template: getTemplateInjection(),
  };
};

/**
 * Get aggregated statistics from all injection modules
 * 
 * @returns {object} Combined statistics
 */
export const getInjectionStatistics = () => {
  const modules = getAllInjectionModules();
  
  return {
    command: modules.command.getStatistics(),
    ldap: modules.ldap.getStatistics(),
    xml: modules.xml.getStatistics(),
    template: modules.template.getStatistics(),
    summary: {
      totalModules: Object.keys(modules).length,
      totalAttempts: Object.values(modules).reduce((sum, m) => 
        sum + (m.attackStats?.totalAttempts || 0), 0
      ),
      criticalModules: Object.entries(INJECTION_MODULES)
        .filter(([_, m]) => m.severity === ATTACK_SEVERITY.CRITICAL).length,
      averageCVSS: (Object.values(INJECTION_MODULES)
        .reduce((sum, m) => sum + m.cvssScore, 0) / Object.keys(INJECTION_MODULES).length
      ).toFixed(2),
    },
  };
};

/**
 * Reset all injection module statistics
 * 
 * @returns {object} Reset confirmation
 */
export const resetAllInjectionStatistics = () => {
  const modules = getAllInjectionModules();
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
  
  logger.info('All injection statistics reset', results);
  
  return {
    success: true,
    results,
    timestamp: new Date().toISOString(),
  };
};

/**
 * Get vulnerability information for all modules
 * 
 * @returns {object} All vulnerability information
 */
export const getAllVulnerabilityInfo = () => {
  const modules = getAllInjectionModules();
  
  return {
    modules: Object.entries(modules).map(([key, module]) => ({
      key,
      ...module.getVulnerabilityInfo(),
    })),
    registry: INJECTION_MODULES,
    metadata: {
      totalModules: Object.keys(modules).length,
      generatedAt: new Date().toISOString(),
    },
  };
};

/**
 * Get module by key
 * 
 * @param {string} moduleKey - Module key (command, ldap, xml, template)
 * @returns {object} Module instance
 */
export const getInjectionModule = (moduleKey) => {
  const modules = getAllInjectionModules();
  const module = modules[moduleKey];
  
  if (!module) {
    throw new Error(`Injection module '${moduleKey}' not found`);
  }
  
  return module;
};

/**
 * Check if module is enabled
 * 
 * @param {string} moduleKey - Module key
 * @returns {boolean} Enabled status
 */
export const isInjectionModuleEnabled = (moduleKey) => {
  const moduleConfig = Object.entries(INJECTION_MODULES)
    .find(([key]) => key.toLowerCase() === moduleKey.toLowerCase());
  
  return moduleConfig ? moduleConfig[1].enabled : false;
};

/**
 * Get module registry
 * 
 * @returns {object} Module registry
 */
export const getInjectionRegistry = () => {
  return {
    ...INJECTION_MODULES,
    metadata: {
      totalModules: Object.keys(INJECTION_MODULES).length,
      enabledModules: Object.values(INJECTION_MODULES).filter(m => m.enabled).length,
      criticalModules: Object.values(INJECTION_MODULES)
        .filter(m => m.severity === ATTACK_SEVERITY.CRITICAL).length,
    },
  };
};

/**
 * Generate comprehensive injection report
 * 
 * @param {Date} startDate - Report start date
 * @param {Date} endDate - Report end date
 * @returns {Promise<object>} Comprehensive report
 */
export const generateComprehensiveInjectionReport = async (startDate, endDate) => {
  const modules = getAllInjectionModules();
  const reports = {};
  
  // Generate reports for each module
  for (const [key, module] of Object.entries(modules)) {
    try {
      if (typeof module.generateAttackReport === 'function') {
        reports[key] = await module.generateAttackReport(startDate, endDate);
      } else {
        reports[key] = {
          statistics: module.getStatistics(),
          vulnerabilityInfo: module.getVulnerabilityInfo(),
        };
      }
    } catch (error) {
      logger.error(`Failed to generate report for ${key}`, { error: error.message });
      reports[key] = { error: error.message };
    }
  }
  
  return {
    period: { start: startDate, end: endDate },
    reports,
    statistics: getInjectionStatistics(),
    vulnerabilityInfo: getAllVulnerabilityInfo(),
    generatedAt: new Date().toISOString(),
  };
};

/**
 * Test all injection modules with sample payloads
 * 
 * @returns {Promise<object>} Test results
 */
export const testAllInjectionModules = async () => {
  const modules = getAllInjectionModules();
  const testResults = {};

  for (const [key, module] of Object.entries(modules)) {
    try {
      const testPayload = getTestPayloadForModule(key);
      
      // Run basic detection test
      const detectionMethod = getDetectionMethodForModule(key);
      if (typeof module[detectionMethod] === 'function') {
        const result = module[detectionMethod](testPayload);
        testResults[key] = {
          success: true,
          detected: result.isAttack,
          severity: result.severity,
          patterns: result.patterns?.length || 0,
        };
      } else {
        testResults[key] = {
          success: false,
          error: 'Detection method not found',
        };
      }
    } catch (error) {
      testResults[key] = {
        success: false,
        error: error.message,
      };
    }
  }

  return {
    testResults,
    timestamp: new Date().toISOString(),
  };
};

/**
 * Get test payload for module
 */
function getTestPayloadForModule(moduleKey) {
  const payloads = {
    command: '127.0.0.1; cat /etc/passwd',
    ldap: '*)(objectClass=*',
    xml: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    template: '{{constructor.constructor("return process")()}}',
  };
  return payloads[moduleKey] || 'test';
}

/**
 * Get detection method name for module
 */
function getDetectionMethodForModule(moduleKey) {
  const methods = {
    command: 'detectCommandInjection',
    ldap: 'detectLDAPInjection',
    xml: 'detectXXE',
    template: 'detectSSTI',
  };
  return methods[moduleKey] || 'detect';
}

/**
 * Get attack examples for all modules
 * 
 * @returns {object} Attack examples categorized by module
 */
export const getAllAttackExamples = () => {
  const modules = getAllInjectionModules();
  const examples = {};

  for (const [key, module] of Object.entries(modules)) {
    if (typeof module.getExamplePayloads === 'function') {
      examples[key] = module.getExamplePayloads();
    } else if (typeof module.getExampleFilters === 'function') {
      examples[key] = module.getExampleFilters();
    }
  }

  return examples;
};

/**
 * Get mitigation strategies for all modules
 * 
 * @returns {object} Mitigation strategies
 */
export const getAllMitigationStrategies = () => {
  const modules = getAllInjectionModules();
  const strategies = {};

  for (const [key, module] of Object.entries(modules)) {
    const vulnInfo = module.getVulnerabilityInfo();
    strategies[key] = {
      name: vulnInfo.name,
      remediation: vulnInfo.remediation || [],
      references: vulnInfo.references || [],
    };
  }

  return strategies;
};

// ============================================================================
// EXPORTS
// ============================================================================

// Export classes
export {
  CommandInjection,
  LDAPInjection,
  XMLInjection,
  TemplateInjection,
};

// Export factory functions
export {
  getCommandInjection,
  getLDAPInjection,
  getXMLInjection,
  getTemplateInjection,
};

// Export handler creators
export {
  createCommandHandler,
  createLDAPHandler,
  createXMLHandler,
  createTemplateHandler,
};

// Default export
export default {
  // Classes
  CommandInjection,
  LDAPInjection,
  XMLInjection,
  TemplateInjection,
  
  // Factory functions
  getCommandInjection,
  getLDAPInjection,
  getXMLInjection,
  getTemplateInjection,
  
  // Handler creators
  createCommandHandler,
  createLDAPHandler,
  createXMLHandler,
  createTemplateHandler,
  
  // Aggregated functions
  getAllInjectionModules,
  getInjectionStatistics,
  resetAllInjectionStatistics,
  getAllVulnerabilityInfo,
  getInjectionModule,
  isInjectionModuleEnabled,
  getInjectionRegistry,
  generateComprehensiveInjectionReport,
  testAllInjectionModules,
  getAllAttackExamples,
  getAllMitigationStrategies,
  
  // Registry
  INJECTION_MODULES,
};

// Log module initialization
logger.info('✅ Injection vulnerability modules loaded', {
  modules: Object.keys(INJECTION_MODULES),
  count: Object.keys(INJECTION_MODULES).length,
});
