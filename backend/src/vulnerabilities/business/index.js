/**
 * ============================================================================
 * BUSINESS LOGIC VULNERABILITIES - CENTRAL INDEX
 * ============================================================================
 * 
 * Enterprise-Grade Business Logic Vulnerability Suite
 * Centralized export for all business logic vulnerability modules
 * 
 * @module vulnerabilities/business
 * @category Security Training - OWASP A04:2021
 * @version 3.0.0
 * @license MIT
 * 
 * @author Elite Security Research Team
 */

import { 
  RaceCondition, 
  getRaceCondition, 
  createVulnerableHandler as createRaceConditionHandler 
} from './raceCondition.js';

import { 
  MassAssignment, 
  getMassAssignment, 
  createVulnerableHandler as createMassAssignmentHandler 
} from './massAssignment.js';

import { 
  PriceTampering, 
  getPriceTampering, 
  createVulnerableHandler as createPriceTamperingHandler 
} from './priceTampering.js';

import { 
  LogicFlaws, 
  getLogicFlaws, 
  createVulnerableHandler as createLogicFlawsHandler 
} from './logicFlaws.js';

import { Logger } from '../../core/Logger.js';

const logger = Logger.getInstance();

// ============================================================================
// VULNERABILITY REGISTRY
// ============================================================================

export const BUSINESS_VULNERABILITIES = {
  RACE_CONDITION: {
    id: 'RACE_CONDITION',
    name: 'Race Condition / TOCTOU',
    class: RaceCondition,
    getInstance: getRaceCondition,
    createHandler: createRaceConditionHandler,
    cvssScore: 8.8,
    owaspId: 'A04:2021',
    cweId: 'CWE-362',
    enabled: true
  },
  
  MASS_ASSIGNMENT: {
    id: 'MASS_ASSIGNMENT',
    name: 'Mass Assignment',
    class: MassAssignment,
    getInstance: getMassAssignment,
    createHandler: createMassAssignmentHandler,
    cvssScore: 8.5,
    owaspId: 'A04:2021',
    cweId: 'CWE-915',
    enabled: true
  },
  
  PRICE_TAMPERING: {
    id: 'PRICE_TAMPERING',
    name: 'Price Tampering',
    class: PriceTampering,
    getInstance: getPriceTampering,
    createHandler: createPriceTamperingHandler,
    cvssScore: 8.6,
    owaspId: 'A04:2021',
    cweId: 'CWE-840',
    enabled: true
  },
  
  LOGIC_FLAWS: {
    id: 'LOGIC_FLAWS',
    name: 'Business Logic Flaws',
    class: LogicFlaws,
    getInstance: getLogicFlaws,
    createHandler: createLogicFlawsHandler,
    cvssScore: 8.9,
    owaspId: 'A04:2021',
    cweId: 'CWE-840',
    enabled: true
  }
};

// ============================================================================
// UNIFIED INTERFACE
// ============================================================================

export const getAllBusinessVulnerabilities = () => {
  const instances = {};
  for (const [key, vuln] of Object.entries(BUSINESS_VULNERABILITIES)) {
    if (vuln.enabled) {
      instances[key] = vuln.getInstance();
    }
  }
  return instances;
};

export const getBusinessVulnerability = (vulnerabilityId) => {
  const vuln = BUSINESS_VULNERABILITIES[vulnerabilityId];
  if (!vuln || !vuln.enabled) {
    throw new Error(`Vulnerability ${vulnerabilityId} not found or disabled`);
  }
  return vuln.getInstance();
};

export const getAllBusinessStatistics = () => {
  const instances = getAllBusinessVulnerabilities();
  const combinedStats = {
    totalAttempts: 0,
    successfulAttacks: 0,
    byVulnerability: {},
    timestamp: new Date().toISOString()
  };
  
  for (const [key, instance] of Object.entries(instances)) {
    const stats = instance.getStatistics();
    combinedStats.byVulnerability[key] = stats;
    combinedStats.totalAttempts += stats.totalAttempts || 0;
    combinedStats.successfulAttacks += (stats.successfulRaces || stats.successfulAssignments || stats.successfulAttacks || 0);
  }
  
  return combinedStats;
};

export const resetAllBusinessStatistics = () => {
  const instances = getAllBusinessVulnerabilities();
  let resetCount = 0;
  
  for (const instance of Object.values(instances)) {
    if (typeof instance.resetStatistics === 'function') {
      instance.resetStatistics();
      resetCount++;
    }
  }
  
  logger.info('Business vulnerability statistics reset', { resetCount });
  
  return {
    success: true,
    message: `Reset statistics for ${resetCount} vulnerabilities`,
    timestamp: new Date().toISOString()
  };
};

// Export individual classes
export { RaceCondition, getRaceCondition, createRaceConditionHandler };
export { MassAssignment, getMassAssignment, createMassAssignmentHandler };
export { PriceTamperingAndLogicFlaws, getPriceTamperingAndLogicFlaws, createPriceTamperingHandler };

export default {
  BUSINESS_VULNERABILITIES,
  RaceCondition,
  MassAssignment,
  PriceTamperingAndLogicFlaws,
  getRaceCondition,
  getMassAssignment,
  getPriceTamperingAndLogicFlaws,
  getAllBusinessVulnerabilities,
  getBusinessVulnerability,
  getAllBusinessStatistics,
  resetAllBusinessStatistics
};

logger.info('✅ Business Logic Vulnerabilities Module Loaded', {
  vulnerabilities: Object.keys(BUSINESS_VULNERABILITIES),
  enabled: Object.values(BUSINESS_VULNERABILITIES).filter(v => v.enabled).length
});
