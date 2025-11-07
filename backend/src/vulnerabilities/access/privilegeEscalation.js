/**
 * ============================================================================
 * PRIVILEGE ESCALATION VULNERABILITY - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Privilege Escalation Attack Demonstration Platform
 * Implements vertical & horizontal privilege escalation vulnerabilities
 * 
 * @module vulnerabilities/access/privilegeEscalation
 * @category Security Training - OWASP A01:2021 (Broken Access Control)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING - CRITICAL SEVERITY:
 * ============================================================================
 * This module contains INTENTIONAL CRITICAL security vulnerabilities:
 * - Missing authorization checks on privileged operations
 * - Role manipulation through parameter tampering
 * - Insecure direct object references (IDOR)
 * - Mass assignment vulnerabilities
 * - Function-level access control bypass
 * - Session fixation enabling privilege escalation
 * - JWT payload manipulation
 * - Cookie-based privilege escalation
 * - API endpoint privilege bypass
 * - Database-level privilege escalation
 * 
 * ⚠️  EXTREME DANGER: Can grant unauthorized administrative access
 * ⚠️  FOR ISOLATED SECURITY TRAINING ONLY
 * ⚠️  Must run in controlled sandbox environments
 * ⚠️  Never deploy on systems with real user data
 * ⚠️  Implement comprehensive access control in production
 * 
 * ============================================================================
 * VULNERABILITY TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Vertical Privilege Escalation (User → Admin)
 * 2. Horizontal Privilege Escalation (User A → User B)
 * 3. Role Manipulation via Parameter Tampering
 * 4. Missing Function-Level Access Control
 * 5. Insecure Direct Object Reference (IDOR)
 * 6. Mass Assignment Vulnerability
 * 7. JWT Role Claim Manipulation
 * 8. Session Privilege Injection
 * 9. API Key Privilege Bypass
 * 10. SQL Injection for Privilege Escalation
 * 11. Cookie Privilege Manipulation
 * 12. Path-Based Access Control Bypass
 * 13. HTTP Verb Tampering
 * 14. GraphQL Privilege Escalation
 * 15. Forced Browsing to Admin Functions
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - POST /api/users/123 {role: "admin"}
 * - PUT /api/profile {isAdmin: true}
 * - PATCH /api/users/456 {permissions: ["*"]}
 * - GET /api/admin/users (no auth check)
 * - POST /api/elevate {userId: 123, role: "superadmin"}
 * - Cookie: role=admin
 * - JWT: {role: "admin", permissions: ["all"]}
 * - GET /api/users/other_user_id/private_data
 * 
 * ============================================================================
 * COMPLIANCE & STANDARDS:
 * ============================================================================
 * - OWASP Top 10 2021: A01 - Broken Access Control
 * - CWE-269: Improper Privilege Management
 * - CWE-284: Improper Access Control
 * - CWE-862: Missing Authorization
 * - CWE-863: Incorrect Authorization
 * - NIST 800-53: AC-2, AC-3, AC-6
 * - PCI-DSS: Requirement 7 (Restrict Access)
 * - ISO 27001: A.9.2.3 Management of Privileged Access Rights
 * 
 * @requires Database
 * @requires Logger
 * @requires Cache
 * @requires JWT
 */

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import {
  HTTP_STATUS,
  ATTACK_TYPES,
  ATTACK_SEVERITY,
  ERROR_CODES,
  ERROR_MESSAGES,
  USER_ROLES,
  PERMISSIONS
} from '../../config/constants.js';
import { AppError, AccessDeniedError, AuthenticationError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VULNERABILITY CONSTANTS & PATTERNS
// ============================================================================

const PRIVILEGE_ESCALATION_PATTERNS = {
  // Role manipulation
  ROLE_TAMPERING: [
    /role.*admin/i,
    /isAdmin.*true/i,
    /is_admin.*1/i,
    /userRole.*admin/i,
    /privilege.*elevated/i,
    /access_level.*[5-9]/i
  ],

  // Permission manipulation
  PERMISSION_TAMPERING: [
    /permissions.*\*/,
    /permissions.*all/i,
    /permissions.*admin/i,
    /access.*full/i,
    /grant.*admin/i
  ],

  // Mass assignment
  MASS_ASSIGNMENT: [
    /isActive.*true/i,
    /verified.*true/i,
    /approved.*true/i,
    /status.*approved/i,
    /balance.*\d{5,}/
  ],

  // IDOR patterns
  IDOR: [
    /userId=\d+/,
    /user_id=\d+/,
    /id=\d+/,
    /accountId=\d+/
  ]
};

const SENSITIVE_OPERATIONS = [
  'deleteUser',
  'updateUserRole',
  'grantPermissions',
  'viewAllUsers',
  'modifySettings',
  'accessLogs',
  'exportData',
  'executeCommand',
  'modifyDatabase',
  'viewCredentials'
];

const ROLE_HIERARCHY = {
  [USER_ROLES.GUEST]: 0,
  [USER_ROLES.CUSTOMER]: 10,
  [USER_ROLES.MODERATOR]: 50,
  [USER_ROLES.ADMIN]: 100,
  [USER_ROLES.SUPERADMIN]: 1000
};

// ============================================================================
// PRIVILEGE ESCALATION VULNERABILITY CLASS
// ============================================================================

export class PrivilegeEscalation {
  constructor() {
    this.name = 'Privilege Escalation';
    this.category = 'Access Control';
    this.cvssScore = 9.8;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A01:2021';
    this.cweId = 'CWE-269';
    
    // Attack statistics
    this.attackStats = {
      totalAttempts: 0,
      successfulEscalations: 0,
      blockedAttempts: 0,
      verticalEscalations: 0,
      horizontalEscalations: 0,
      roleManipulations: 0,
      permissionTampering: 0,
      massAssignments: 0,
      idorAttempts: 0,
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      targetedRoles: {},
      targetedOperations: {},
      escalationMethods: {},
      ipAddresses: new Set(),
      userAgents: new Set(),
      compromisedAccounts: new Set()
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Update User Profile with Mass Assignment
   * 
   * Allows users to modify privileged fields through mass assignment
   * Attack: POST {role: "admin", isActive: true, balance: 999999}
   * 
   * @param {number} userId - User ID
   * @param {object} updateData - User-supplied update data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Updated user data
   */
  async vulnerableUpdateProfile(userId, updateData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 MASS ASSIGNMENT UPDATE ATTEMPT', {
        userId,
        updateData,
        ip: context.ip,
        mode: Config.security.mode
      });

      // Detect attack
      const detection = this.detectPrivilegeEscalation(updateData, 'MASS_ASSIGNMENT', context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'MASS_ASSIGNMENT_ESCALATION',
          severity: detection.severity,
          userId,
          payload: updateData,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: No field whitelist - allows updating any field
      const fields = Object.keys(updateData);
      const values = Object.values(updateData);
      
      // Build dynamic update query
      const setClause = fields.map(field => `${field} = ?`).join(', ');

      // ⚠️ VULNERABLE: Direct mass assignment without validation
      const query = `
        UPDATE ${tables.USERS}
        SET ${setClause}, updated_at = NOW()
        WHERE id = ?
      `;

      await db.execute(query, [...values, userId]);

      // Get updated user
      const [users] = await db.execute(
        `SELECT id, username, email, role, is_active, balance, permissions
         FROM ${tables.USERS}
         WHERE id = ? LIMIT 1`,
        [userId]
      );

      const updatedUser = users[0];

      // Check if privilege escalation occurred
      if (updateData.role && updateData.role !== context.originalRole) {
        this.attackStats.successfulEscalations++;
        this.attackStats.verticalEscalations++;
        this.attackStats.roleManipulations++;
        this.attackStats.compromisedAccounts.add(userId);
      }

      const duration = Date.now() - startTime;

      logger.warn('🚨 PRIVILEGE ESCALATION SUCCESSFUL', {
        userId,
        originalRole: context.originalRole,
        newRole: updatedUser.role,
        updatedFields: fields
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          user: updatedUser,
          updatedFields: fields,
          warning: 'CRITICAL: Mass assignment allowed privilege escalation'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          escalationType: 'VERTICAL'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableUpdateProfile', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Change User Role without Authorization
   * 
   * Allows any user to change their own or others' roles
   * Attack: PUT /api/users/123/role {role: "admin"}
   * 
   * @param {number} targetUserId - Target user ID
   * @param {string} newRole - New role (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Role change result
   */
  async vulnerableChangeUserRole(targetUserId, newRole, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.roleManipulations++;

    try {
      logger.warn('🚨 UNAUTHORIZED ROLE CHANGE ATTEMPT', {
        targetUserId,
        newRole,
        requestedBy: context.userId,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPrivilegeEscalation({ role: newRole }, 'ROLE_TAMPERING', context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'ROLE_MANIPULATION',
          severity: ATTACK_SEVERITY.CRITICAL,
          userId: targetUserId,
          payload: { newRole },
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: No authorization check - anyone can change roles
      // Get original role
      const [originalUsers] = await db.execute(
        'SELECT role FROM users WHERE id = ? LIMIT 1',
        [targetUserId]
      );

      const originalRole = originalUsers[0]?.role;

      // ⚠️ VULNERABLE: Direct role update without permission check
      await db.execute(
        `UPDATE ${tables.USERS}
         SET role = ?, updated_at = NOW()
         WHERE id = ?`,
        [newRole, targetUserId]
      );

      // Get updated user
      const [users] = await db.execute(
        `SELECT id, username, email, role, permissions
         FROM ${tables.USERS}
         WHERE id = ? LIMIT 1`,
        [targetUserId]
      );

      this.attackStats.successfulEscalations++;
      this.attackStats.verticalEscalations++;
      this.attackStats.compromisedAccounts.add(targetUserId);

      const duration = Date.now() - startTime;

      logger.warn('🚨 ROLE ESCALATION SUCCESSFUL', {
        targetUserId,
        originalRole,
        newRole,
        performedBy: context.userId
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          user: users[0],
          originalRole,
          newRole,
          warning: 'CRITICAL: Unauthorized role change successful'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          escalationType: 'VERTICAL'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableChangeUserRole', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Access Other User's Private Data (IDOR)
   * 
   * Horizontal privilege escalation - access other users' data
   * Attack: GET /api/users/456/private (when authenticated as user 123)
   * 
   * @param {number} targetUserId - Target user ID (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Private user data (EXPOSED)
   */
  async vulnerableAccessUserPrivateData(targetUserId, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.idorAttempts++;

    try {
      logger.warn('🚨 IDOR ATTEMPT - ACCESSING OTHER USER DATA', {
        targetUserId,
        requestedBy: context.userId,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPrivilegeEscalation(
        { targetUserId, requesterId: context.userId }, 
        'IDOR', 
        context
      );
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'IDOR_HORIZONTAL_ESCALATION',
          severity: ATTACK_SEVERITY.HIGH,
          userId: targetUserId,
          payload: { targetUserId, requesterId: context.userId },
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: No ownership verification
      const [users] = await db.execute(
        `SELECT 
          u.id, u.username, u.email, u.phone, u.address,
          u.date_of_birth, u.ssn, u.credit_card_number,
          u.bank_account, u.password_reset_token,
          u.two_factor_secret, u.api_key, u.balance,
          u.last_login_ip, u.session_id
         FROM ${tables.USERS} u
         WHERE u.id = ?
         LIMIT 1`,
        [targetUserId]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          error: 'User not found',
          metadata: {
            executionTime: Date.now() - startTime,
            attackDetected: detection.isAttack
          }
        };
      }

      // Check if horizontal escalation occurred
      if (targetUserId !== context.userId) {
        this.attackStats.successfulEscalations++;
        this.attackStats.horizontalEscalations++;
        this.attackStats.compromisedAccounts.add(targetUserId);
      }

      const duration = Date.now() - startTime;

      logger.warn('🚨 IDOR SUCCESSFUL - ACCESSED OTHER USER DATA', {
        targetUserId,
        accessedBy: context.userId,
        dataExposed: Object.keys(users[0])
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          user: users[0],
          warning: 'CRITICAL: IDOR allowed access to other user\'s private data'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.HIGH,
          attackDetected: detection.isAttack,
          escalationType: 'HORIZONTAL'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableAccessUserPrivateData', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Grant Admin Permissions
   * 
   * Allows users to grant themselves admin permissions
   * Attack: POST /api/permissions/grant {permissions: ["*"]}
   * 
   * @param {number} userId - User ID
   * @param {array} permissions - Permissions to grant (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Permission grant result
   */
  async vulnerableGrantPermissions(userId, permissions, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.permissionTampering++;

    try {
      logger.warn('🚨 UNAUTHORIZED PERMISSION GRANT ATTEMPT', {
        userId,
        permissions,
        requestedBy: context.userId,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPrivilegeEscalation(
        { permissions }, 
        'PERMISSION_TAMPERING', 
        context
      );
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'PERMISSION_ESCALATION',
          severity: ATTACK_SEVERITY.CRITICAL,
          userId,
          payload: { permissions },
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: No authorization check before granting permissions
      await db.execute(
        `UPDATE ${tables.USERS}
         SET permissions = ?, updated_at = NOW()
         WHERE id = ?`,
        [JSON.stringify(permissions), userId]
      );

      // Get updated user
      const [users] = await db.execute(
        `SELECT id, username, role, permissions
         FROM ${tables.USERS}
         WHERE id = ? LIMIT 1`,
        [userId]
      );

      this.attackStats.successfulEscalations++;
      this.attackStats.verticalEscalations++;
      this.attackStats.compromisedAccounts.add(userId);

      const duration = Date.now() - startTime;

      logger.warn('🚨 PERMISSION ESCALATION SUCCESSFUL', {
        userId,
        grantedPermissions: permissions,
        performedBy: context.userId
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          user: users[0],
          grantedPermissions: permissions,
          warning: 'CRITICAL: Unauthorized permission escalation'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          escalationType: 'VERTICAL'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableGrantPermissions', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Perform Admin Operation without Check
   * 
   * Allows any user to perform admin operations
   * Attack: DELETE /api/admin/users/123 (from regular user account)
   * 
   * @param {string} operation - Admin operation name
   * @param {object} operationData - Operation parameters (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Operation result
   */
  async vulnerablePerformAdminOperation(operation, operationData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 UNAUTHORIZED ADMIN OPERATION ATTEMPT', {
        operation,
        operationData,
        requestedBy: context.userId,
        userRole: context.userRole,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPrivilegeEscalation(
        { operation, ...operationData }, 
        'FUNCTION_LEVEL_BYPASS', 
        context
      );
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'ADMIN_FUNCTION_BYPASS',
          severity: ATTACK_SEVERITY.CRITICAL,
          operation,
          payload: operationData,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: No function-level access control
      let result = {};

      switch (operation) {
        case 'deleteUser':
          // ⚠️ VULNERABLE: Delete user without admin check
          await db.execute(
            `DELETE FROM ${tables.USERS} WHERE id = ?`,
            [operationData.userId]
          );
          result = { deleted: true, userId: operationData.userId };
          break;

        case 'viewAllUsers':
          // ⚠️ VULNERABLE: Expose all users without admin check
          const [users] = await db.execute(
            `SELECT id, username, email, role, password, api_key 
             FROM ${tables.USERS} 
             LIMIT 1000`
          );
          result = { users };
          break;

        case 'modifySettings':
          // ⚠️ VULNERABLE: Modify global settings without admin check
          await db.execute(
            `UPDATE ${tables.SETTINGS} 
             SET setting_value = ? 
             WHERE setting_key = ?`,
            [operationData.value, operationData.key]
          );
          result = { modified: true, setting: operationData.key };
          break;

        case 'exportData':
          // ⚠️ VULNERABLE: Export sensitive data without admin check
          const [orders] = await db.execute(
            `SELECT o.*, u.username, u.email 
             FROM ${tables.ORDERS} o 
             JOIN ${tables.USERS} u ON o.user_id = u.id 
             LIMIT 10000`
          );
          result = { orders, count: orders.length };
          break;

        default:
          result = { message: `Operation ${operation} executed` };
      }

      this.attackStats.successfulEscalations++;
      this.attackStats.verticalEscalations++;
      this.attackStats.targetedOperations[operation] = 
        (this.attackStats.targetedOperations[operation] || 0) + 1;

      const duration = Date.now() - startTime;

      logger.warn('🚨 ADMIN OPERATION BYPASS SUCCESSFUL', {
        operation,
        performedBy: context.userId,
        userRole: context.userRole
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          operation,
          result,
          warning: 'CRITICAL: Admin operation performed without authorization'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          escalationType: 'FUNCTION_LEVEL_BYPASS'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerablePerformAdminOperation', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: JWT Token Manipulation
   * 
   * Allows role manipulation through JWT claims
   * Attack: Modified JWT with {role: "admin"}
   * 
   * @param {object} tokenPayload - JWT payload (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Authentication result
   */
  async vulnerableJWTAuthentication(tokenPayload, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 JWT MANIPULATION ATTEMPT', {
        tokenPayload,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPrivilegeEscalation(
        tokenPayload, 
        'JWT_MANIPULATION', 
        context
      );
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'JWT_ROLE_MANIPULATION',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: tokenPayload,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Trust JWT payload without server-side validation
      const userId = tokenPayload.userId || tokenPayload.sub;
      const role = tokenPayload.role; // Directly from JWT - NOT validated against database
      const permissions = tokenPayload.permissions || [];

      // ⚠️ VULNERABLE: Create session based solely on JWT claims
      const sessionData = {
        userId,
        role, // DANGEROUS: Using role from JWT
        permissions,
        authenticated: true
      };

      if (role === USER_ROLES.ADMIN || role === USER_ROLES.SUPERADMIN) {
        this.attackStats.successfulEscalations++;
        this.attackStats.verticalEscalations++;
        this.attackStats.roleManipulations++;
      }

      const duration = Date.now() - startTime;

      logger.warn('🚨 JWT MANIPULATION SUCCESSFUL', {
        userId,
        claimedRole: role,
        claimedPermissions: permissions
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          session: sessionData,
          warning: 'CRITICAL: JWT role claims accepted without validation'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          escalationType: 'TOKEN_MANIPULATION'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableJWTAuthentication', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Update User Profile with Whitelist
   * 
   * @param {number} userId - User ID
   * @param {object} updateData - Update data (VALIDATED)
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} Updated user data
   */
  async secureUpdateProfile(userId, updateData, req) {
    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AuthenticationError('Authentication required');
      }

      // ✅ Ownership check
      if (req.user.id !== userId) {
        throw new AccessDeniedError('Can only update own profile');
      }

      // ✅ Field whitelist - only allow safe fields
      const allowedFields = ['first_name', 'last_name', 'phone', 'address', 'bio'];
      const sanitizedData = {};

      for (const field of allowedFields) {
        if (updateData[field] !== undefined) {
          sanitizedData[field] = updateData[field];
        }
      }

      // ✅ Validate each field
      if (sanitizedData.phone && !/^\+?[1-9]\d{1,14}$/.test(sanitizedData.phone)) {
        throw new AppError('Invalid phone number', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Build safe update query
      const fields = Object.keys(sanitizedData);
      const values = Object.values(sanitizedData);

      if (fields.length === 0) {
        throw new AppError('No valid fields to update', HTTP_STATUS.BAD_REQUEST);
      }

      const setClause = fields.map(field => `${field} = ?`).join(', ');

      await db.execute(
        `UPDATE ${tables.USERS} SET ${setClause}, updated_at = NOW() WHERE id = ?`,
        [...values, userId]
      );

      // ✅ Return safe fields only
      const [users] = await db.execute(
        `SELECT id, username, email, first_name, last_name, phone, address 
         FROM ${tables.USERS} WHERE id = ? LIMIT 1`,
        [userId]
      );

      return {
        success: true,
        vulnerable: false,
        data: { user: users[0] }
      };

    } catch (error) {
      logger.error('Secure update profile error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Change User Role with Authorization
   * 
   * @param {number} targetUserId - Target user ID
   * @param {string} newRole - New role
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} Role change result
   */
  async secureChangeUserRole(targetUserId, newRole, req) {
    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AuthenticationError('Authentication required');
      }

      // ✅ Authorization check - only admins can change roles
      if (req.user.role !== USER_ROLES.ADMIN && req.user.role !== USER_ROLES.SUPERADMIN) {
        throw new AccessDeniedError('Admin privileges required');
      }

      // ✅ Validate new role
      const validRoles = Object.values(USER_ROLES);
      if (!validRoles.includes(newRole)) {
        throw new AppError('Invalid role', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Prevent privilege escalation above own level
      const requesterLevel = ROLE_HIERARCHY[req.user.role] || 0;
      const targetLevel = ROLE_HIERARCHY[newRole] || 0;

      if (targetLevel >= requesterLevel) {
        throw new AccessDeniedError('Cannot assign role equal to or higher than your own');
      }

      // ✅ Prevent modifying superadmin accounts
      const [targetUsers] = await db.execute(
        'SELECT role FROM users WHERE id = ? LIMIT 1',
        [targetUserId]
      );

      if (targetUsers[0]?.role === USER_ROLES.SUPERADMIN && req.user.role !== USER_ROLES.SUPERADMIN) {
        throw new AccessDeniedError('Cannot modify superadmin accounts');
      }

      // ✅ Update role with audit logging
      await db.execute(
        `UPDATE ${tables.USERS} SET role = ?, updated_at = NOW() WHERE id = ?`,
        [newRole, targetUserId]
      );

      // ✅ Log the action
      await db.execute(
        `INSERT INTO ${tables.AUDIT_LOGS} (user_id, action, target_user_id, details, timestamp)
         VALUES (?, 'ROLE_CHANGE', ?, ?, NOW())`,
        [req.user.id, targetUserId, JSON.stringify({ newRole })]
      );

      const [users] = await db.execute(
        `SELECT id, username, email, role FROM ${tables.USERS} WHERE id = ? LIMIT 1`,
        [targetUserId]
      );

      return {
        success: true,
        vulnerable: false,
        data: { user: users[0] }
      };

    } catch (error) {
      logger.error('Secure role change error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Access User Data with Authorization
   * 
   * @param {number} targetUserId - Target user ID
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} User data
   */
  async secureAccessUserData(targetUserId, req) {
    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AuthenticationError('Authentication required');
      }

      // ✅ Ownership check
      const isOwner = req.user.id === targetUserId;
      const isAdmin = req.user.role === USER_ROLES.ADMIN || req.user.role === USER_ROLES.SUPERADMIN;

      if (!isOwner && !isAdmin) {
        throw new AccessDeniedError('Access denied');
      }

      // ✅ Return appropriate fields based on role
      let query, fields;

      if (isOwner) {
        // Owner can see their own private data
        fields = 'id, username, email, phone, address, balance, created_at';
      } else if (isAdmin) {
        // Admin can see user data but not sensitive fields
        fields = 'id, username, email, role, is_active, created_at';
      }

      const [users] = await db.execute(
        `SELECT ${fields} FROM ${tables.USERS} WHERE id = ? LIMIT 1`,
        [targetUserId]
      );

      if (users.length === 0) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND);
      }

      return {
        success: true,
        vulnerable: false,
        data: { user: users[0] }
      };

    } catch (error) {
      logger.error('Secure access user data error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & ANALYSIS
  // ==========================================================================

  /**
   * Detect privilege escalation attempts
   * 
   * @param {object} payload - Request payload
   * @param {string} escalationType - Type of escalation
   * @param {object} context - Request context
   * @returns {object} Detection results
   */
  detectPrivilegeEscalation(payload, escalationType, context = {}) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.LOW;
    let score = 0;

    const payloadString = JSON.stringify(payload).toLowerCase();

    // Check escalation type patterns
    const patterns = PRIVILEGE_ESCALATION_PATTERNS[escalationType] || [];
    
    for (const pattern of patterns) {
      if (pattern.test(payloadString)) {
        detectedPatterns.push({
          category: escalationType,
          pattern: pattern.toString(),
          matched: true
        });
        score += 15;
      }
    }

    // Check for role manipulation
    if (payload.role) {
      const targetRole = payload.role.toLowerCase();
      const privilegedRoles = ['admin', 'superadmin', 'moderator', 'root'];
      
      if (privilegedRoles.includes(targetRole)) {
        detectedPatterns.push({
          category: 'PRIVILEGED_ROLE_TARGET',
          role: payload.role,
          matched: true
        });
        score += 20;
        severity = ATTACK_SEVERITY.CRITICAL;
        this.attackStats.targetedRoles[payload.role] = 
          (this.attackStats.targetedRoles[payload.role] || 0) + 1;
      }
    }

    // Check for permission manipulation
    if (payload.permissions) {
      const dangerousPerms = ['*', 'all', 'admin', 'root', 'superuser'];
      const hasWildcard = Array.isArray(payload.permissions) 
        ? payload.permissions.some(p => dangerousPerms.includes(String(p).toLowerCase()))
        : dangerousPerms.includes(String(payload.permissions).toLowerCase());

      if (hasWildcard) {
        detectedPatterns.push({
          category: 'WILDCARD_PERMISSIONS',
          permissions: payload.permissions,
          matched: true
        });
        score += 20;
        severity = ATTACK_SEVERITY.CRITICAL;
      }
    }

    // Check for IDOR attempt
    if (payload.targetUserId && payload.requesterId) {
      if (payload.targetUserId !== payload.requesterId) {
        detectedPatterns.push({
          category: 'IDOR_ATTEMPT',
          targetUser: payload.targetUserId,
          requester: payload.requesterId,
          matched: true
        });
        score += 15;
      }
    }

    // Check for sensitive operations
    if (payload.operation && SENSITIVE_OPERATIONS.includes(payload.operation)) {
      detectedPatterns.push({
        category: 'SENSITIVE_OPERATION',
        operation: payload.operation,
        matched: true
      });
      score += 15;
    }

    // Check for mass assignment indicators
    const dangerousFields = ['isAdmin', 'is_admin', 'verified', 'approved', 'balance', 'credit'];
    const hasDangerousField = Object.keys(payload).some(key => 
      dangerousFields.some(df => key.toLowerCase().includes(df))
    );

    if (hasDangerousField) {
      detectedPatterns.push({
        category: 'DANGEROUS_FIELD_ASSIGNMENT',
        matched: true
      });
      score += 12;
    }

    // Determine final severity
    if (score >= 30) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 20) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 10) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.updateAttackStats(severity, escalationType);
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      escalationType,
      payload: JSON.stringify(payload).substring(0, 200),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Update attack statistics
   */
  updateAttackStats(severity, escalationType) {
    const severityMap = {
      [ATTACK_SEVERITY.CRITICAL]: 'critical',
      [ATTACK_SEVERITY.HIGH]: 'high',
      [ATTACK_SEVERITY.MEDIUM]: 'medium',
      [ATTACK_SEVERITY.LOW]: 'low'
    };

    const key = severityMap[severity];
    if (key) {
      this.attackStats.severityBreakdown[key]++;
    }

    this.attackStats.blockedAttempts++;
    
    // Track escalation method
    this.attackStats.escalationMethods[escalationType] = 
      (this.attackStats.escalationMethods[escalationType] || 0) + 1;
  }

  /**
   * Log attack attempt
   */
  async logAttack(attackData) {
    try {
      const { type, severity, userId, operation, payload, detection, context } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          type,
          severity,
          JSON.stringify(payload),
          JSON.stringify(detection.patterns),
          context.ip || null,
          context.userAgent || null,
          userId || context.userId || null,
          context.endpoint || null
        ]
      );

      // Cache attack for rate limiting
      const cacheKey = CacheKeyBuilder.custom('priv_esc_attacks:', context.ip);
      const recentAttacks = await cache.get(cacheKey) || [];
      recentAttacks.push({
        type,
        severity,
        timestamp: new Date().toISOString()
      });
      await cache.set(cacheKey, recentAttacks, 3600);

      // Track IP and User Agent
      if (context.ip) this.attackStats.ipAddresses.add(context.ip);
      if (context.userAgent) this.attackStats.userAgents.add(context.userAgent);

      logger.attack('Privilege Escalation Attack Detected', {
        type,
        severity,
        userId,
        operation,
        patterns: detection.patterns.map(p => p.category),
        context
      });

    } catch (error) {
      logger.error('Failed to log attack', { error: error.message });
    }
  }

  /**
   * Handle vulnerable errors
   */
  handleVulnerableError(error, method, duration) {
    logger.error('Privilege escalation error', {
      message: error.message,
      method,
      duration
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        method
      },
      metadata: {
        executionTime: duration,
        errorType: 'PRIVILEGE_ESCALATION_ERROR'
      }
    };
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  /**
   * Get comprehensive attack statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      ipAddresses: this.attackStats.ipAddresses.size,
      userAgents: this.attackStats.userAgents.size,
      compromisedAccounts: this.attackStats.compromisedAccounts.size,
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulEscalations / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%',
      verticalRate: this.attackStats.successfulEscalations > 0
        ? (this.attackStats.verticalEscalations / this.attackStats.successfulEscalations * 100).toFixed(2) + '%'
        : '0%',
      horizontalRate: this.attackStats.successfulEscalations > 0
        ? (this.attackStats.horizontalEscalations / this.attackStats.successfulEscalations * 100).toFixed(2) + '%'
        : '0%'
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
      description: 'Privilege Escalation allows attackers to gain higher privileges than intended, either vertically (to admin) or horizontally (to other users)',
      impact: [
        'Unauthorized access to administrative functions',
        'Complete system compromise',
        'Data theft and manipulation',
        'Access to other users\' private data',
        'Financial fraud',
        'Reputation damage',
        'Regulatory compliance violations'
      ],
      attackVectors: [
        'Mass Assignment: {role: "admin"}',
        'IDOR: /api/users/other_user_id/data',
        'JWT Manipulation: Modified role claims',
        'Parameter Tampering: ?isAdmin=true',
        'Function-Level Bypass: Accessing admin endpoints',
        'Role Injection: Modifying session cookies',
        'Permission Escalation: {permissions: ["*"]}'
      ],
      escalationTypes: {
        vertical: 'User → Admin (higher privileges)',
        horizontal: 'User A → User B (same level, different user)',
        functionLevel: 'Accessing privileged functions without authorization',
        dataLevel: 'Accessing data beyond authorized scope'
      },
      remediation: [
        'Implement proper authorization checks on all operations',
        'Use role-based access control (RBAC)',
        'Validate user permissions server-side',
        'Use field whitelisting for updates',
        'Implement ownership verification for data access',
        'Validate JWT claims against database',
        'Use indirect object references',
        'Implement principle of least privilege',
        'Audit and log all privilege changes',
        'Implement multi-factor authentication for sensitive operations'
      ]
    };
  }

  /**
   * Generate detailed attack report
   */
  async generateAttackReport(startDate, endDate) {
    try {
      const [attacks] = await db.execute(
        `SELECT 
          attack_type,
          severity,
          user_id,
          payload,
          ip_address,
          COUNT(*) as count,
          DATE(timestamp) as date
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%ESCALATION%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY attack_type, severity, user_id, DATE(timestamp)
         ORDER BY timestamp DESC`,
        [startDate, endDate]
      );

      const [compromisedAccounts] = await db.execute(
        `SELECT DISTINCT user_id, COUNT(*) as attack_count
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%ESCALATION%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY user_id
         ORDER BY attack_count DESC
         LIMIT 50`,
        [startDate, endDate]
      );

      return {
        period: { start: startDate, end: endDate },
        attacks,
        compromisedAccounts,
        statistics: this.getStatistics(),
        vulnerabilityInfo: this.getVulnerabilityInfo(),
        generatedAt: new Date().toISOString()
      };

    } catch (error) {
      logger.error('Failed to generate attack report', { error: error.message });
      throw error;
    }
  }

  /**
   * Check if role escalation is valid
   */
  isValidRoleEscalation(currentRole, targetRole) {
    const currentLevel = ROLE_HIERARCHY[currentRole] || 0;
    const targetLevel = ROLE_HIERARCHY[targetRole] || 0;
    
    return currentLevel >= targetLevel;
  }

  /**
   * Get role level
   */
  getRoleLevel(role) {
    return ROLE_HIERARCHY[role] || 0;
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulEscalations: 0,
      blockedAttempts: 0,
      verticalEscalations: 0,
      horizontalEscalations: 0,
      roleManipulations: 0,
      permissionTampering: 0,
      massAssignments: 0,
      idorAttempts: 0,
      severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
      targetedRoles: {},
      targetedOperations: {},
      escalationMethods: {},
      ipAddresses: new Set(),
      userAgents: new Set(),
      compromisedAccounts: new Set()
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getPrivilegeEscalation = () => {
  if (!instance) {
    instance = new PrivilegeEscalation();
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const pe = getPrivilegeEscalation();
      
      if (Config.security.mode !== 'vulnerable') {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.FORBIDDEN,
          message: 'This endpoint is only available in vulnerable mode'
        });
      }

      const context = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.user?.id,
        userRole: req.user?.role,
        originalRole: req.user?.role,
        endpoint: req.path
      };

      const result = await pe[method](...Object.values(req.body || req.query), context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  PrivilegeEscalation,
  getPrivilegeEscalation,
  createVulnerableHandler
};
