/**
 * ============================================================================
 * OAUTH 2.0 VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade OAuth 2.0 Demonstration Platform
 * Implements OAuth authentication flow vulnerabilities
 * 
 * @module vulnerabilities/auth/oauth
 * @category Security Training - OWASP A07:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ⚠️  FOR EDUCATIONAL PURPOSES ONLY
 * 
 * ATTACK TYPES:
 * - CSRF in OAuth flow
 * - Redirect URI manipulation
 * - Authorization code theft
 * - Token leakage
 * - Open redirect exploitation
 * 
 * @requires uuid
 * @requires Database
 * @requires Logger
 */

import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { HTTP_STATUS, ATTACK_SEVERITY, ERROR_CODES } from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

export class OAuthVulnerabilities {
  constructor() {
    this.name = 'OAuth 2.0 Vulnerabilities';
    this.category = 'Authentication';
    this.cvssScore = 8.2;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A07:2021';
    this.cweId = 'CWE-352';
    
    this.attackStats = {
      totalAttempts: 0,
      csrfAttacks: 0,
      redirectURIManipulations: 0,
      authCodeThefts: 0,
      openRedirects: 0,
      successfulExploits: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: No State Parameter (CSRF)
   */
  async vulnerableOAuthInitiate(clientId, redirectUri, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.csrfAttacks++;

      // ⚠️ VULNERABLE: No state parameter
      const authCode = uuidv4();
      
      await cache.set(`oauth_code:${authCode}`, JSON.stringify({
        clientId,
        redirectUri,
        createdAt: Date.now(),
      }), 600);

      logger.warn('🚨 OAUTH WITHOUT STATE PARAMETER', { clientId, redirectUri });

      return {
        success: true,
        vulnerable: true,
        authorizationUrl: `/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`,
        authCode,
        warning: '⚠️ No state parameter - vulnerable to CSRF',
        metadata: { executionTime: Date.now() - startTime },
      };
    } catch (error) {
      return this.handleOAuthError(error, clientId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Open Redirect in redirect_uri
   */
  async vulnerableRedirectURIValidation(authCode, redirectUri, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.redirectURIManipulations++;

      // ⚠️ VULNERABLE: No redirect URI validation
      const codeData = await cache.get(`oauth_code:${authCode}`);
      
      if (!codeData) {
        throw new AppError('Invalid auth code', HTTP_STATUS.UNAUTHORIZED);
      }

      const accessToken = uuidv4();
      
      logger.warn('🚨 UNVALIDATED REDIRECT URI', { redirectUri, authCode });

      this.attackStats.successfulExploits++;

      return {
        success: true,
        vulnerable: true,
        accessToken,
        redirectUri,
        warning: '⚠️ Redirect URI not validated - open redirect possible',
        metadata: { executionTime: Date.now() - startTime },
      };
    } catch (error) {
      return this.handleOAuthError(error, authCode, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ✅ SECURE: OAuth with State Parameter
   */
  async secureOAuthInitiate(clientId, redirectUri, context) {
    const startTime = Date.now();

    try {
      // ✅ Generate cryptographically secure state
      const state = crypto.randomBytes(32).toString('hex');
      const authCode = uuidv4();
      
      // ✅ Store state for validation
      await cache.set(`oauth_state:${state}`, JSON.stringify({
        clientId,
        redirectUri,
        createdAt: Date.now(),
      }), 600);

      await cache.set(`oauth_code:${authCode}`, JSON.stringify({
        clientId,
        redirectUri,
        state,
        createdAt: Date.now(),
      }), 600);

      // ✅ Validate redirect URI against whitelist
      if (!this.isValidRedirectURI(clientId, redirectUri)) {
        throw new AppError('Invalid redirect URI', HTTP_STATUS.BAD_REQUEST);
      }

      return {
        success: true,
        vulnerable: false,
        authorizationUrl: `/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=${state}`,
        state,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_OAUTH',
        },
      };
    } catch (error) {
      logger.error('Secure OAuth error', { error: error.message });
      throw error;
    }
  }

  /**
   * Validate redirect URI
   */
  isValidRedirectURI(clientId, redirectUri) {
    // Implement whitelist validation
    const allowedURIs = {
      'client123': ['https://app.example.com/callback'],
    };
    
    return allowedURIs[clientId]?.includes(redirectUri) || false;
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  getStatistics() {
    return {
      ...this.attackStats,
      exploitRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulExploits / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%',
    };
  }

  getVulnerabilityInfo() {
    return {
      name: this.name,
      category: this.category,
      cvssScore: this.cvssScore,
      severity: this.severity,
      owaspId: this.owaspId,
      cweId: this.cweId,
      description: 'OAuth 2.0 implementation vulnerabilities allow attackers to bypass authentication or steal access tokens',
      impact: [
        'Account takeover',
        'CSRF attacks',
        'Authorization code theft',
        'Token leakage',
        'Open redirects',
      ],
      remediation: [
        'Always use state parameter',
        'Validate redirect URIs against whitelist',
        'Use PKCE for public clients',
        'Short-lived authorization codes',
        'Secure token storage',
        'HTTPS only',
      ],
      references: [
        'https://datatracker.ietf.org/doc/html/rfc6749',
        'https://oauth.net/2/',
      ],
    };
  }

  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      csrfAttacks: 0,
      redirectURIManipulations: 0,
      authCodeThefts: 0,
      openRedirects: 0,
      successfulExploits: 0,
    };
  }

  handleOAuthError(error, identifier, duration) {
    logger.error('OAuth Attack Error', { message: error.message, identifier, duration });
    return {
      success: false,
      vulnerable: true,
      error: { message: error.message, code: error.code },
      metadata: { executionTime: duration, errorType: 'OAUTH_ERROR' },
    };
  }
}

let instance = null;

export const getOAuthVulnerabilities = () => {
  if (!instance) {
    instance = new OAuthVulnerabilities();
  }
  return instance;
};

export const createOAuthHandler = (method) => {
  return async (req, res, next) => {
    try {
      const oauthAttack = getOAuthVulnerabilities();
      
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
      const result = await oauthAttack[method](...Object.values(params), context);
      
      res.json(result);
    } catch (error) {
      next(error);
    }
  };
};

export default {
  OAuthVulnerabilities,
  getOAuthVulnerabilities,
  createOAuthHandler,
};
