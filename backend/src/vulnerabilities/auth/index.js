/**
 * ============================================================================
 * AUTHENTICATION VULNERABILITIES - MODULE INDEX
 * ============================================================================
 * 
 * Central export point for all authentication vulnerability modules
 * 
 * @module vulnerabilities/auth
 * @category Security Training
 * @version 3.0.0
 * 
 * ============================================================================
 * AVAILABLE MODULES:
 * ============================================================================
 * 1. Brute Force - Password guessing and account enumeration
 * 2. Session Fixation - Session management vulnerabilities
 * 3. JWT Bypass - JSON Web Token security flaws
 * 4. OAuth - OAuth 2.0 implementation vulnerabilities
 * 
 * @author Security Research Team
 */

import { 
  BruteForceAttack, 
  getBruteForceAttack,
  createBruteForceHandler
} from './bruteForce.js';

import { 
  SessionFixation, 
  getSessionFixation,
  createSessionHandler
} from './sessionFixation.js';

import { 
  JWTBypass, 
  getJWTBypass,
  createJWTHandler
} from './jwtBypass.js';

import { 
  OAuthVulnerabilities, 
  getOAuthVulnerabilities,
  createOAuthHandler
} from './oauth.js';

import { Logger } from '../../core/Logger.js';
import { ATTACK_SEVERITY } from '../../config/constants.js';

const logger = Logger.getInstance();

// ============================================================================
// MODULE REGISTRY
// ============================================================================

const AUTH_MODULES = {
  BRUTE_FORCE: {
    name: 'Brute Force Attack',
    class: BruteForceAttack,
    getInstance: getBruteForceAttack,
    createHandler: createBruteForceHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 7.5,
    description: 'Systematic credential guessing and enumeration',
    enabled: true,
    owaspId: 'A07:2021',
    cweId: 'CWE-307',
  },
  SESSION_FIXATION: {
    name: 'Session Fixation',
    class: SessionFixation,
    getInstance: getSessionFixation,
    createHandler: createSessionHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 8.1,
    description: 'Session management and hijacking vulnerabilities',
    enabled: true,
    owaspId: 'A07:2021',
    cweId: 'CWE-384',
  },
  JWT_BYPASS: {
    name: 'JWT Bypass',
    class: JWTBypass,
    getInstance: getJWTBypass,
    createHandler: createJWTHandler,
    severity: ATTACK_SEVERITY.CRITICAL,
    cvssScore: 9.1,
    description: 'JSON Web Token security vulnerabilities',
    enabled: true,
    owaspId: 'A07:2021',
    cweId: 'CWE-287',
  },
  OAUTH: {
    name: 'OAuth Vulnerabilities',
    class: OAuthVulnerabilities,
    getInstance: getOAuthVulnerabilities,
    createHandler: createOAuthHandler,
    severity: ATTACK_SEVERITY.HIGH,
    cvssScore: 8.2,
    description: 'OAuth 2.0 implementation flaws',
    enabled: true,
    owaspId: 'A07:2021',
    cweId: 'CWE-352',
  },
};

// ============================================================================
// AGGREGATED FUNCTIONS
// ============================================================================

export const getAllAuthModules = () => {
  return {
    bruteForce: getBruteForceAttack(),
    sessionFixation: getSessionFixation(),
    jwtBypass: getJWTBypass(),
    oauth: getOAuthVulnerabilities(),
  };
};

export const getAuthStatistics = () => {
  const modules = getAllAuthModules();
  
  return {
    bruteForce: modules.bruteForce.getStatistics(),
    sessionFixation: modules.sessionFixation.getStatistics(),
    jwtBypass: modules.jwtBypass.getStatistics(),
    oauth: modules.oauth.getStatistics(),
    summary: {
      totalModules: Object.keys(modules).length,
      totalAttempts: Object.values(modules).reduce((sum, m) => 
        sum + (m.attackStats?.totalAttempts || 0), 0
      ),
      criticalModules: Object.entries(AUTH_MODULES)
        .filter(([_, m]) => m.severity === ATTACK_SEVERITY.CRITICAL).length,
      averageCVSS: (Object.values(AUTH_MODULES)
        .reduce((sum, m) => sum + m.cvssScore, 0) / Object.keys(AUTH_MODULES).length
      ).toFixed(2),
    },
  };
};

export const resetAllAuthStatistics = () => {
  const modules = getAllAuthModules();
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
  
  logger.info('All auth statistics reset', results);
  
  return {
    success: true,
    results,
    timestamp: new Date().toISOString(),
  };
};

export const getAllVulnerabilityInfo = () => {
  const modules = getAllAuthModules();
  
  return {
    modules: Object.entries(modules).map(([key, module]) => ({
      key,
      ...module.getVulnerabilityInfo(),
    })),
    registry: AUTH_MODULES,
    metadata: {
      totalModules: Object.keys(modules).length,
      generatedAt: new Date().toISOString(),
    },
  };
};

export const getAuthModule = (moduleKey) => {
  const modules = getAllAuthModules();
  const module = modules[moduleKey];
  
  if (!module) {
    throw new Error(`Auth module '${moduleKey}' not found`);
  }
  
  return module;
};

export const isAuthModuleEnabled = (moduleKey) => {
  const moduleConfig = Object.entries(AUTH_MODULES)
    .find(([key]) => key.toLowerCase() === moduleKey.toLowerCase());
  
  return moduleConfig ? moduleConfig[1].enabled : false;
};

export const getAuthRegistry = () => {
  return {
    ...AUTH_MODULES,
    metadata: {
      totalModules: Object.keys(AUTH_MODULES).length,
      enabledModules: Object.values(AUTH_MODULES).filter(m => m.enabled).length,
      criticalModules: Object.values(AUTH_MODULES)
        .filter(m => m.severity === ATTACK_SEVERITY.CRITICAL).length,
    },
  };
};

// ============================================================================
// EXPORTS
// ============================================================================

export {
  BruteForceAttack,
  SessionFixation,
  JWTBypass,
  OAuthVulnerabilities,
};

export {
  getBruteForceAttack,
  getSessionFixation,
  getJWTBypass,
  getOAuthVulnerabilities,
};

export {
  createBruteForceHandler,
  createSessionHandler,
  createJWTHandler,
  createOAuthHandler,
};

export default {
  BruteForceAttack,
  SessionFixation,
  JWTBypass,
  OAuthVulnerabilities,
  getBruteForceAttack,
  getSessionFixation,
  getJWTBypass,
  getOAuthVulnerabilities,
  createBruteForceHandler,
  createSessionHandler,
  createJWTHandler,
  createOAuthHandler,
  getAllAuthModules,
  getAuthStatistics,
  resetAllAuthStatistics,
  getAllVulnerabilityInfo,
  getAuthModule,
  isAuthModuleEnabled,
  getAuthRegistry,
  AUTH_MODULES,
};

logger.info('✅ Auth vulnerability modules loaded', {
  modules: Object.keys(AUTH_MODULES),
  count: Object.keys(AUTH_MODULES).length,
});
