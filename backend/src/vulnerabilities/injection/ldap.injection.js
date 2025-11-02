/**
 * ============================================================================
 * LDAP INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade LDAP Injection Demonstration Platform
 * Implements Lightweight Directory Access Protocol injection vulnerabilities
 * 
 * @module vulnerabilities/injection/ldap
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates LDAP injection vulnerabilities:
 * - Filter injection in LDAP queries
 * - Authentication bypass via LDAP
 * - Wildcard (*) exploitation
 * - Boolean logic manipulation (|, &, !)
 * - Attribute extraction
 * - Blind LDAP injection
 * - DN (Distinguished Name) injection
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to unauthorized access and data disclosure
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Authentication Bypass (* or *)(objectClass=*)
 * 2. OR Logic Injection (|)
 * 3. AND Logic Injection (&)
 * 4. NOT Logic Injection (!)
 * 5. Wildcard Exploitation (*)
 * 6. Attribute Enumeration
 * 7. Blind LDAP Injection
 * 8. Distinguished Name Injection
 * 9. Filter Component Injection
 * 10. Search Scope Manipulation
 * 
 * ============================================================================
 * LDAP FILTER SYNTAX:
 * ============================================================================
 * - (attribute=value) - Equality
 * - (attribute=value*) - Substring
 * - (attribute>=value) - Greater than or equal
 * - (attribute<=value) - Less than or equal
 * - (attribute=*) - Presence (any value)
 * - (!(attribute=value)) - NOT
 * - (&(cond1)(cond2)) - AND
 * - (|(cond1)(cond2)) - OR
 * 
 * ============================================================================
 * ATTACK VECTORS:
 * ============================================================================
 * - *
 * - *)(objectClass=*)
 * - admin*)(|(uid=*
 * - *)(uid=*))(|(uid=*
 * - *))%00
 * - )(cn=*))(&(objectClass=*
 * - *)(userPassword=*)
 * 
 * @requires ldapjs
 * @requires Database
 * @requires Logger
 */

import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { 
  HTTP_STATUS, 
  ATTACK_TYPES,
  ATTACK_SEVERITY,
  ERROR_CODES 
} from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// LDAP INJECTION CONSTANTS
// ============================================================================

const LDAP_PATTERNS = {
  // LDAP operators and special characters
  OPERATORS: [
    /\*/,                          // Wildcard
    /\|/,                          // OR operator
    /&/,                           // AND operator
    /!/,                           // NOT operator
    /\(/,                          // Opening parenthesis
    /\)/,                          // Closing parenthesis
    /=/,                           // Equals
    /~/,                           // Approximate match
    /</,                           // Less than
    />/,                           // Greater than
  ],

  // LDAP injection payloads
  INJECTION_SIGNATURES: [
    /\*\s*\)\s*\(\s*objectClass\s*=\s*\*/i,
    /\*\s*\)\s*\(\s*\|\s*\(/i,
    /\*\s*\)\s*\(\s*&\s*\(/i,
    /\*\s*\)\s*\(\s*uid\s*=\s*\*/i,
    /\*\s*\)\s*\(\s*cn\s*=\s*\*/i,
    /\*\s*\)\s*\(\s*mail\s*=\s*\*/i,
    /\)\s*\)\s*%00/,
  ],

  // Common LDAP attributes
  SENSITIVE_ATTRIBUTES: [
    /userPassword/i,
    /unicodePwd/i,
    /ntPassword/i,
    /lmPassword/i,
    /sambaNTPassword/i,
    /sambaLMPassword/i,
    /shadowLastChange/i,
    /shadowMax/i,
    /memberOf/i,
    /adminCount/i,
  ],

  // Filter bypass patterns
  BYPASS_PATTERNS: [
    /\*\s*\)\s*\(/,
    /\)\s*\(\s*\|/,
    /\)\s*\(\s*&/,
    /\*\s*\)\s*\|\s*\(/,
    /admin\s*\)\s*\(/i,
  ],

  // Boolean blind LDAP
  BOOLEAN_BLIND: [
    /\*\)\s*\(\s*cn\s*=\s*\w+/i,
    /\*\)\s*\(\s*uid\s*=\s*\w+/i,
    /\)\s*\(\s*[a-z]+\s*=\s*\*/i,
  ],
};

const LDAP_SPECIAL_CHARS = ['*', '(', ')', '\\', '|', '&', '!', '=', '<', '>', '~', '/', '\0'];

const LDAP_OBJECT_CLASSES = [
  'person', 'organizationalPerson', 'inetOrgPerson', 'user',
  'group', 'groupOfNames', 'posixAccount', 'posixGroup',
  'domain', 'organizationalUnit', 'organization', 'dcObject'
];

const COMMON_ATTRIBUTES = [
  'uid', 'cn', 'sn', 'givenName', 'mail', 'userPassword',
  'telephoneNumber', 'description', 'memberOf', 'dn',
  'objectClass', 'distinguishedName', 'displayName'
];

// ============================================================================
// LDAP INJECTION CLASS
// ============================================================================

export class LDAPInjection {
  constructor() {
    this.name = 'LDAP Injection';
    this.category = 'Injection';
    this.cvssScore = 8.1;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-90';
    
    this.attackStats = {
      totalAttempts: 0,
      authenticationBypasses: 0,
      filterInjections: 0,
      attributeEnumerations: 0,
      blindInjections: 0,
      wildcardExploits: 0,
      successfulExtractions: 0,
      blockedAttempts: 0,
    };

    // Simulated LDAP directory for demonstration
    this.mockLDAPDirectory = this.initializeMockDirectory();
  }

  // ==========================================================================
  // MOCK LDAP DIRECTORY (For Demonstration)
  // ==========================================================================

  /**
   * Initialize mock LDAP directory structure
   */
  initializeMockDirectory() {
    return [
      {
        dn: 'uid=admin,ou=users,dc=example,dc=com',
        uid: 'admin',
        cn: 'Administrator',
        sn: 'Admin',
        mail: 'admin@example.com',
        userPassword: '{SSHA}hashed_admin_password_here',
        objectClass: ['inetOrgPerson', 'posixAccount'],
        memberOf: ['cn=admins,ou=groups,dc=example,dc=com'],
        uidNumber: '1000',
        gidNumber: '1000',
        homeDirectory: '/home/admin',
        loginShell: '/bin/bash',
      },
      {
        dn: 'uid=john.doe,ou=users,dc=example,dc=com',
        uid: 'john.doe',
        cn: 'John Doe',
        sn: 'Doe',
        givenName: 'John',
        mail: 'john.doe@example.com',
        userPassword: '{SSHA}hashed_user_password_here',
        objectClass: ['inetOrgPerson', 'posixAccount'],
        memberOf: ['cn=users,ou=groups,dc=example,dc=com'],
        uidNumber: '1001',
        gidNumber: '1001',
        homeDirectory: '/home/john.doe',
        loginShell: '/bin/bash',
        telephoneNumber: '+1-555-0100',
      },
      {
        dn: 'uid=jane.smith,ou=users,dc=example,dc=com',
        uid: 'jane.smith',
        cn: 'Jane Smith',
        sn: 'Smith',
        givenName: 'Jane',
        mail: 'jane.smith@example.com',
        userPassword: '{SSHA}hashed_jane_password_here',
        objectClass: ['inetOrgPerson', 'posixAccount'],
        memberOf: ['cn=users,ou=groups,dc=example,dc=com', 'cn=developers,ou=groups,dc=example,dc=com'],
        uidNumber: '1002',
        gidNumber: '1002',
        homeDirectory: '/home/jane.smith',
        loginShell: '/bin/bash',
        telephoneNumber: '+1-555-0101',
      },
      {
        dn: 'cn=admins,ou=groups,dc=example,dc=com',
        cn: 'admins',
        objectClass: ['groupOfNames'],
        member: ['uid=admin,ou=users,dc=example,dc=com'],
        description: 'System Administrators',
      },
      {
        dn: 'cn=users,ou=groups,dc=example,dc=com',
        cn: 'users',
        objectClass: ['groupOfNames'],
        member: [
          'uid=john.doe,ou=users,dc=example,dc=com',
          'uid=jane.smith,ou=users,dc=example,dc=com',
        ],
        description: 'Regular Users',
      },
    ];
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: LDAP Authentication - Direct Filter Construction
   * 
   * Attack vectors:
   * - username: * password: *
   * - username: *)(objectClass=* password: anything
   * - username: admin*)(|(uid=* password: anything
   * 
   * @param {string} username - Username (VULNERABLE)
   * @param {string} password - Password (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Authentication result
   */
  async vulnerableLDAPAuth(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectLDAPInjection(username + password);
      
      if (attackDetection.isAttack) {
        await this.logLDAPAttack({
          type: 'LDAP_AUTH_INJECTION',
          severity: attackDetection.severity,
          payload: { username, password: '***' },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.authenticationBypasses++;
      }

      // ⚠️ VULNERABLE: Direct string concatenation in LDAP filter
      const ldapFilter = `(&(uid=${username})(userPassword=${password}))`;

      logger.warn('🚨 VULNERABLE LDAP AUTHENTICATION', {
        ldapFilter,
        username,
        attackDetection,
      });

      // Simulate LDAP search
      const results = this.simulateLDAPSearch(ldapFilter);
      const duration = Date.now() - startTime;

      const authenticated = results.length > 0;

      if (authenticated && attackDetection.isAttack) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        authenticated,
        user: authenticated ? this.sanitizeUserForResponse(results[0]) : null,
        ldapFilter,
        resultsCount: results.length,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          bypassTechnique: attackDetection.techniques,
        },
      };

    } catch (error) {
      return this.handleLDAPError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: User Search - Filter Injection
   * 
   * Attack vectors:
   * - *
   * - *)(objectClass=*)
   * - admin*)(|(uid=*)
   * 
   * @param {string} searchTerm - Search term (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Search results
   */
  async vulnerableUserSearch(searchTerm, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.filterInjections++;

      const attackDetection = this.detectLDAPInjection(searchTerm);
      
      if (attackDetection.isAttack) {
        await this.logLDAPAttack({
          type: 'LDAP_SEARCH_INJECTION',
          severity: attackDetection.severity,
          payload: { searchTerm },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: User input directly in LDAP filter
      const ldapFilter = `(|(uid=${searchTerm})(cn=${searchTerm})(mail=${searchTerm}))`;

      logger.warn('🚨 VULNERABLE LDAP SEARCH', {
        ldapFilter,
        searchTerm,
        attackDetection,
      });

      const results = this.simulateLDAPSearch(ldapFilter);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && results.length > 0) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        results: results.map(r => this.sanitizeUserForResponse(r)),
        totalResults: results.length,
        ldapFilter,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          injectionType: 'SEARCH_FILTER',
        },
      };

    } catch (error) {
      return this.handleLDAPError(error, searchTerm, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Attribute-Based Search
   * 
   * Attack vectors:
   * - attribute: uid, value: *)(userPassword=*)
   * - attribute: cn, value: *)(objectClass=*)
   * 
   * @param {string} attribute - Attribute name (VULNERABLE)
   * @param {string} value - Search value (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Search results
   */
  async vulnerableAttributeSearch(attribute, value, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.attributeEnumerations++;

      const attackDetection = this.detectLDAPInjection(attribute + value);
      
      if (attackDetection.isAttack) {
        await this.logLDAPAttack({
          type: 'LDAP_ATTRIBUTE_INJECTION',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { attribute, value },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: Both attribute and value are user-controlled
      const ldapFilter = `(${attribute}=${value})`;

      logger.warn('🚨 VULNERABLE ATTRIBUTE SEARCH', {
        ldapFilter,
        attribute,
        value,
        attackDetection,
      });

      const results = this.simulateLDAPSearch(ldapFilter);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        results: results.map(r => this.sanitizeUserForResponse(r)),
        totalResults: results.length,
        ldapFilter,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          injectionType: 'ATTRIBUTE_BASED',
          sensitiveData: this.containsSensitiveAttributes(results),
        },
      };

    } catch (error) {
      return this.handleLDAPError(error, attribute, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Blind LDAP Injection - Boolean-Based
   * 
   * Attack vectors:
   * - username: admin*)(cn=a* returns true if admin exists and cn starts with 'a'
   * 
   * @param {string} username - Username (VULNERABLE)
   * @param {string} condition - Additional condition (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Boolean result
   */
  async vulnerableBlindLDAP(username, condition, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.blindInjections++;

      const attackDetection = this.detectLDAPInjection(username + condition);
      
      if (attackDetection.isAttack) {
        await this.logLDAPAttack({
          type: 'BLIND_LDAP_INJECTION',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { username, condition },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: Blind LDAP injection
      const ldapFilter = `(&(uid=${username})(${condition}))`;

      logger.warn('🚨 BLIND LDAP INJECTION', {
        ldapFilter,
        username,
        condition,
        attackDetection,
      });

      const results = this.simulateLDAPSearch(ldapFilter);
      const duration = Date.now() - startTime;

      const conditionTrue = results.length > 0;

      if (attackDetection.isAttack) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        conditionTrue,
        message: conditionTrue ? '✅ Condition evaluated to TRUE' : '❌ Condition evaluated to FALSE',
        ldapFilter,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          injectionType: 'BLIND_BOOLEAN',
          resultsCount: results.length,
        },
      };

    } catch (error) {
      return this.handleLDAPError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Wildcard Exploitation
   * 
   * Attack vectors:
   * - prefix: * (returns all entries)
   * - prefix: a* (returns entries starting with 'a')
   * 
   * @param {string} prefix - Search prefix (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Search results
   */
  async vulnerableWildcardSearch(prefix, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.wildcardExploits++;

      const attackDetection = this.detectLDAPInjection(prefix);
      
      if (attackDetection.isAttack) {
        await this.logLDAPAttack({
          type: 'LDAP_WILDCARD_EXPLOIT',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { prefix },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: Wildcard exploitation
      const ldapFilter = `(uid=${prefix}*)`;

      logger.warn('🚨 WILDCARD EXPLOITATION', {
        ldapFilter,
        prefix,
        attackDetection,
      });

      const results = this.simulateLDAPSearch(ldapFilter);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && results.length > 0) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        results: results.map(r => this.sanitizeUserForResponse(r)),
        totalResults: results.length,
        ldapFilter,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          injectionType: 'WILDCARD_EXPLOIT',
        },
      };

    } catch (error) {
      return this.handleLDAPError(error, prefix, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: DN (Distinguished Name) Injection
   * 
   * Attack vectors:
   * - ou: users,dc=example,dc=com)(objectClass=*
   * 
   * @param {string} ou - Organizational Unit (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Search results
   */
  async vulnerableDNSearch(ou, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectLDAPInjection(ou);
      
      if (attackDetection.isAttack) {
        await this.logLDAPAttack({
          type: 'LDAP_DN_INJECTION',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { ou },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: DN construction with user input
      const baseDN = `ou=${ou},dc=example,dc=com`;
      const ldapFilter = '(objectClass=*)';

      logger.warn('🚨 DN INJECTION', {
        baseDN,
        ldapFilter,
        ou,
        attackDetection,
      });

      // Simulate LDAP search with DN
      const results = this.mockLDAPDirectory.filter(entry => 
        entry.dn.includes(ou) || ldapFilter === '(objectClass=*)'
      );

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && results.length > 0) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        baseDN,
        ldapFilter,
        results: results.map(r => this.sanitizeUserForResponse(r)),
        totalResults: results.length,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          injectionType: 'DN_INJECTION',
        },
      };

    } catch (error) {
      return this.handleLDAPError(error, ou, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // LDAP SIMULATION HELPERS
  // ==========================================================================

  /**
   * Simulate LDAP search (for demonstration purposes)
   */
  simulateLDAPSearch(filter) {
    try {
      // Parse and evaluate LDAP filter
      const parsed = this.parseLDAPFilter(filter);
      
      // Filter mock directory based on parsed filter
      return this.mockLDAPDirectory.filter(entry => {
        return this.evaluateFilter(parsed, entry);
      });

    } catch (error) {
      logger.error('LDAP filter parsing error', { filter, error: error.message });
      return [];
    }
  }

  /**
   * Parse LDAP filter (simplified)
   */
  parseLDAPFilter(filter) {
    // Wildcard match (returns all)
    if (filter === '(*)' || filter.includes('(objectClass=*)')) {
      return { type: 'wildcard', matchAll: true };
    }

    // OR logic
    if (filter.startsWith('(|')) {
      return { type: 'or', conditions: this.extractConditions(filter) };
    }

    // AND logic
    if (filter.startsWith('(&')) {
      return { type: 'and', conditions: this.extractConditions(filter) };
    }

    // Simple equality
    const match = filter.match(/\(([^=]+)=([^)]+)\)/);
    if (match) {
      return { type: 'equality', attribute: match[1], value: match[2] };
    }

    return { type: 'unknown', filter };
  }

  /**
   * Extract conditions from compound filter
   */
  extractConditions(filter) {
    const conditions = [];
    let depth = 0;
    let current = '';
    
    for (let i = 2; i < filter.length - 1; i++) {
      const char = filter[i];
      
      if (char === '(') {
        depth++;
        current += char;
      } else if (char === ')') {
        depth--;
        current += char;
        
        if (depth === 0 && current) {
          conditions.push(this.parseLDAPFilter(current));
          current = '';
        }
      } else {
        current += char;
      }
    }
    
    return conditions;
  }

  /**
   * Evaluate filter against entry
   */
  evaluateFilter(parsed, entry) {
    switch (parsed.type) {
      case 'wildcard':
        return true;

      case 'equality': {
        const entryValue = entry[parsed.attribute];
        if (!entryValue) return false;

        // Handle wildcards in value
        if (parsed.value === '*') return true;
        if (parsed.value.endsWith('*')) {
          const prefix = parsed.value.slice(0, -1);
          return String(entryValue).startsWith(prefix);
        }
        if (parsed.value.startsWith('*')) {
          const suffix = parsed.value.slice(1);
          return String(entryValue).endsWith(suffix);
        }

        // Handle array attributes (like objectClass)
        if (Array.isArray(entryValue)) {
          return entryValue.some(v => String(v) === parsed.value);
        }

        return String(entryValue) === parsed.value;
      }

      case 'or':
        return parsed.conditions.some(cond => this.evaluateFilter(cond, entry));

      case 'and':
        return parsed.conditions.every(cond => this.evaluateFilter(cond, entry));

      default:
        return false;
    }
  }

  /**
   * Sanitize user object for response
   */
  sanitizeUserForResponse(entry) {
    const sanitized = { ...entry };
    
    // Remove sensitive attributes
    delete sanitized.userPassword;
    delete sanitized.unicodePwd;
    delete sanitized.ntPassword;
    
    return sanitized;
  }

  /**
   * Check if results contain sensitive attributes
   */
  containsSensitiveAttributes(results) {
    const sensitiveAttrs = ['userPassword', 'unicodePwd', 'ntPassword', 'lmPassword'];
    
    return results.some(entry => 
      sensitiveAttrs.some(attr => entry.hasOwnProperty(attr))
    );
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: LDAP Authentication with Proper Escaping
   * 
   * @param {string} username - Username (SAFE)
   * @param {string} password - Password (SAFE)
   * @returns {Promise<object>} Authentication result
   */
  async secureLDAPAuth(username, password) {
    const startTime = Date.now();

    try {
      // ✅ Validate input
      if (typeof username !== 'string' || username.length > 50) {
        throw new AppError('Invalid username', HTTP_STATUS.BAD_REQUEST);
      }

      if (typeof password !== 'string' || password.length > 100) {
        throw new AppError('Invalid password', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Escape LDAP special characters
      const escapedUsername = this.escapeLDAPFilter(username);
      const escapedPassword = this.escapeLDAPFilter(password);

      // ✅ Construct safe LDAP filter
      const ldapFilter = `(&(uid=${escapedUsername})(userPassword=${escapedPassword}))`;

      logger.info('✅ SECURE LDAP AUTHENTICATION', {
        ldapFilter,
        username: escapedUsername,
      });

      const results = this.simulateLDAPSearch(ldapFilter);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        authenticated: results.length > 0,
        user: results.length > 0 ? this.sanitizeUserForResponse(results[0]) : null,
        metadata: {
          executionTime: duration,
          method: 'ESCAPED_FILTER',
          securityLevel: 'HIGH',
        },
      };

    } catch (error) {
      logger.error('Secure LDAP auth error', { error: error.message });
      throw error;
    }
  }

  /**
   * Escape LDAP filter special characters
   */
  escapeLDAPFilter(input) {
    const escapeMap = {
      '*': '\\2a',
      '(': '\\28',
      ')': '\\29',
      '\\': '\\5c',
      '\0': '\\00',
      '/': '\\2f',
    };

    return String(input).split('').map(char => escapeMap[char] || char).join('');
  }

  /**
   * Escape LDAP DN special characters
   */
  escapeLDAPDN(input) {
    const escapeMap = {
      ',': '\\,',
      '+': '\\+',
      '"': '\\"',
      '\\': '\\\\',
      '<': '\\<',
      '>': '\\>',
      ';': '\\;',
      '=': '\\=',
      '\0': '\\00',
    };

    return String(input).split('').map(char => escapeMap[char] || char).join('');
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect LDAP injection patterns
   */
  detectLDAPInjection(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;
    const techniques = [];

    // Check for LDAP operators
    let operatorCount = 0;
    for (const pattern of LDAP_PATTERNS.OPERATORS) {
      if (pattern.test(input)) {
        operatorCount++;
      }
    }

    if (operatorCount >= 3) {
      detectedPatterns.push({
        category: 'LDAP_OPERATORS',
        count: operatorCount,
        matched: true,
      });
      score += operatorCount * 2;
      techniques.push('OPERATOR_INJECTION');
    }

    // Check for injection signatures
    for (const pattern of LDAP_PATTERNS.INJECTION_SIGNATURES) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'INJECTION_SIGNATURE',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 15;
        severity = ATTACK_SEVERITY.CRITICAL;
        techniques.push('FILTER_BYPASS');
      }
    }

    // Check for sensitive attributes
    for (const pattern of LDAP_PATTERNS.SENSITIVE_ATTRIBUTES) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'SENSITIVE_ATTRIBUTE',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 10;
        severity = ATTACK_SEVERITY.CRITICAL;
        techniques.push('ATTRIBUTE_EXTRACTION');
      }
    }

    // Check for bypass patterns
    for (const pattern of LDAP_PATTERNS.BYPASS_PATTERNS) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'BYPASS_PATTERN',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 12;
        techniques.push('AUTHENTICATION_BYPASS');
      }
    }

    // Check for boolean blind patterns
    for (const pattern of LDAP_PATTERNS.BOOLEAN_BLIND) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'BOOLEAN_BLIND',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 8;
        techniques.push('BLIND_INJECTION');
      }
    }

    // Wildcard detection
    const wildcardCount = (input.match(/\*/g) || []).length;
    if (wildcardCount > 0) {
      detectedPatterns.push({
        category: 'WILDCARD_USAGE',
        count: wildcardCount,
        matched: true,
      });
      score += wildcardCount * 3;
      techniques.push('WILDCARD_EXPLOIT');
    }

    // Adjust severity based on score
    if (score >= 20) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 10) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 5) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.attackStats.blockedAttempts++;
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      techniques: [...new Set(techniques)],
      input: input.substring(0, 200),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log LDAP injection attack
   */
  async logLDAPAttack(attackData) {
    try {
      const {
        type,
        severity,
        payload,
        patterns,
        context,
        timestamp = new Date(),
      } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          type,
          severity,
          JSON.stringify(payload),
          JSON.stringify(patterns),
          context.ip || null,
          context.userAgent || null,
          context.userId || null,
          context.endpoint || null,
          timestamp,
        ]
      );

      logger.attack('LDAP Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context,
      });

    } catch (error) {
      logger.error('Failed to log LDAP attack', { error: error.message });
    }
  }

  /**
   * Handle LDAP errors
   */
  handleLDAPError(error, input, duration) {
    logger.error('LDAP Injection Error', {
      message: error.message,
      code: error.code,
      input,
      duration,
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
      },
      metadata: {
        executionTime: duration,
        errorType: 'LDAP_QUERY_ERROR',
      },
    };
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  /**
   * Get attack statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      successRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulExtractions / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%',
    };
  }

  /**
   * Get vulnerability information
   */
  getVulnerabilityInfo() {
    return {
      name: this.name,
      category: this.category,
      cvssScore: this.cvssScore,
      severity: this.severity,
      owaspId: this.owaspId,
      cweId: this.cweId,
      description: 'LDAP Injection allows attackers to manipulate LDAP queries to bypass authentication or extract sensitive directory information',
      impact: [
        'Authentication bypass',
        'Unauthorized directory access',
        'User enumeration',
        'Sensitive data disclosure',
        'Privilege escalation',
        'Directory structure mapping',
        'Account compromise',
      ],
      commonTargets: [
        'Active Directory authentication',
        'Corporate directory services',
        'Single Sign-On (SSO) systems',
        'Email address lookups',
        'Employee directory searches',
      ],
      remediation: [
        'Use parameterized LDAP queries',
        'Escape all special LDAP characters',
        'Implement input validation (whitelist)',
        'Use LDAP libraries with built-in escaping',
        'Apply principle of least privilege',
        'Implement rate limiting',
        'Monitor LDAP query patterns',
        'Use bind operations instead of filter-based auth',
        'Regular security audits',
      ],
      references: [
        'https://owasp.org/www-community/attacks/LDAP_Injection',
        'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',
        'CWE-90: Improper Neutralization of Special Elements used in an LDAP Query',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      authenticationBypasses: 0,
      filterInjections: 0,
      attributeEnumerations: 0,
      blindInjections: 0,
      wildcardExploits: 0,
      successfulExtractions: 0,
      blockedAttempts: 0,
    };
  }

  /**
   * Get LDAP filter examples
   */
  getExampleFilters() {
    return {
      legitimate: [
        '(uid=john.doe)',
        '(&(objectClass=person)(mail=*@example.com))',
        '(|(cn=Admin*)(uid=admin*))',
      ],
      vulnerable: [
        '(uid=*)',
        '(uid=*)(objectClass=*)',
        '(uid=admin*)(|(uid=*))',
        '(uid=*))(&(objectClass=*)',
        '(uid=*)(userPassword=*)',
      ],
      bypasses: [
        { input: '*', description: 'Match all entries' },
        { input: '*)(objectClass=*', description: 'Filter bypass with OR' },
        { input: 'admin*)(|(uid=*', description: 'Complex bypass' },
      ],
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getLDAPInjection = () => {
  if (!instance) {
    instance = new LDAPInjection();
  }
  return instance;
};

export const createLDAPHandler = (method) => {
  return async (req, res, next) => {
    try {
      const injection = getLDAPInjection();
      
      if (Config.security.mode !== 'vulnerable') {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.FORBIDDEN,
          message: 'This endpoint is only available in vulnerable mode',
        });
      }

      const context = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.user?.id,
        endpoint: req.path,
      };

      const params = { ...req.body, ...req.query, ...req.params };
      const result = await injection[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  LDAPInjection,
  getLDAPInjection,
  createLDAPHandler,
};
