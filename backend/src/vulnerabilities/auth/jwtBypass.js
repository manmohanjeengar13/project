/**
 * ============================================================================
 * JWT BYPASS VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade JWT Security Demonstration Platform
 * Implements JSON Web Token vulnerabilities and bypasses
 * 
 * @module vulnerabilities/auth/jwtBypass
 * @category Security Training - OWASP A07:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates JWT vulnerabilities:
 * - Algorithm Confusion (alg: none, HS256 to RS256)
 * - Weak Secret Keys
 * - Missing Signature Verification
 * - Token Tampering
 * - Key Confusion Attacks
 * - JWT Header Injection
 * - Expired Token Acceptance
 * - No Token Revocation
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to complete authentication bypass
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Algorithm None Attack - Remove signature verification
 * 2. Algorithm Confusion - Change RS256 to HS256
 * 3. Weak Secret - Brute force or guess signing key
 * 4. Key Confusion - Use public key as secret
 * 5. Token Tampering - Modify payload without detection
 * 6. JWT Header Injection - Inject malicious headers
 * 7. Expired Token Bypass - Accept expired tokens
 * 8. No Revocation - Stolen tokens remain valid
 * 9. JWK Header Injection - Inject attacker's key
 * 10. Kid Parameter Injection - Path traversal in key ID
 * 
 * @requires jsonwebtoken
 * @requires Database
 * @requires Logger
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
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
// JWT CONSTANTS
// ============================================================================

const JWT_CONFIG = {
  // Secret keys (WEAK for demonstration)
  WEAK_SECRET: 'secret',
  STRONG_SECRET: crypto.randomBytes(64).toString('hex'),
  
  // Token settings
  ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY: '7d',
  
  // Algorithm settings
  DEFAULT_ALGORITHM: 'HS256',
  ASYMMETRIC_ALGORITHM: 'RS256',
  
  // Validation settings
  VERIFY_EXPIRATION: true,
  VERIFY_ISSUER: true,
  VERIFY_AUDIENCE: true,
  
  // Issuer and audience
  ISSUER: 'sqli-demo-platform',
  AUDIENCE: 'sqli-demo-users',
};

const WEAK_SECRETS = [
  'secret', 'password', '123456', 'admin', 'jwt_secret',
  'your-secret-key', 'my-secret', 'secret123', 'supersecret',
];

// RSA key pair for asymmetric algorithms (for demonstration)
const RSA_KEYS = {
  privateKey: crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  }).privateKey,
  publicKey: crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  }).publicKey,
};

// ============================================================================
// JWT BYPASS CLASS
// ============================================================================

export class JWTBypass {
  constructor() {
    this.name = 'JWT Bypass';
    this.category = 'Authentication';
    this.cvssScore = 9.1;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A07:2021';
    this.cweId = 'CWE-287';
    
    this.attackStats = {
      totalAttempts: 0,
      algorithmNoneAttacks: 0,
      algorithmConfusion: 0,
      weakSecretExploits: 0,
      tamperedTokens: 0,
      expiredTokenAccepted: 0,
      successfulBypasses: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Algorithm None Attack
   * 
   * Attack: Set algorithm to "none" and remove signature
   * 
   * @param {object} payload - JWT payload
   * @param {object} context - Request context
   * @returns {Promise<object>} JWT token
   */
  async vulnerableAlgorithmNone(payload, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.algorithmNoneAttacks++;

      logger.warn('🚨 ALGORITHM NONE ATTACK', {
        payload,
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: Create token with "none" algorithm
      const header = {
        alg: 'none',
        typ: 'JWT'
      };

      const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
      const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');

      // ⚠️ VULNERABLE: No signature
      const token = `${encodedHeader}.${encodedPayload}.`;

      await this.logJWTAttack({
        type: 'ALGORITHM_NONE',
        severity: ATTACK_SEVERITY.CRITICAL,
        payload: { token, algorithm: 'none' },
        patterns: [],
        context,
      });

      return {
        success: true,
        vulnerable: true,
        token,
        warning: '⚠️ Algorithm "none" - no signature verification',
        decoded: {
          header,
          payload,
        },
        metadata: {
          executionTime: Date.now() - startTime,
          algorithm: 'none',
        },
      };

    } catch (error) {
      return this.handleJWTError(error, 'algorithm_none', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Verify Token with Algorithm None Accepted
   * 
   * @param {string} token - JWT token (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Verification result
   */
  async vulnerableVerifyAlgorithmNone(token, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      // ⚠️ VULNERABLE: Accept algorithm "none"
      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid token format',
        };
      }

      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

      if (header.alg === 'none') {
        logger.warn('🚨 ACCEPTING ALGORITHM NONE TOKEN', {
          payload,
          ip: context.ip,
        });

        this.attackStats.successfulBypasses++;

        await this.logJWTAttack({
          type: 'ALGORITHM_NONE_ACCEPTED',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { payload },
          patterns: [],
          context,
        });

        return {
          success: true,
          vulnerable: true,
          payload,
          warning: '⚠️ Token with algorithm "none" accepted - authentication bypassed',
          metadata: {
            executionTime: Date.now() - startTime,
          },
        };
      }

      return {
        success: false,
        vulnerable: true,
        message: 'Token verification failed',
      };

    } catch (error) {
      return this.handleJWTError(error, token, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Weak Secret Key
   * 
   * Attack: Use weak secret that can be brute-forced
   * 
   * @param {object} payload - JWT payload
   * @param {object} context - Request context
   * @returns {Promise<object>} JWT token
   */
  async vulnerableWeakSecret(payload, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.weakSecretExploits++;

      logger.warn('🚨 WEAK SECRET KEY USAGE', {
        secret: JWT_CONFIG.WEAK_SECRET,
        payload,
      });

      // ⚠️ VULNERABLE: Weak, easily guessable secret
      const token = jwt.sign(payload, JWT_CONFIG.WEAK_SECRET, {
        algorithm: 'HS256',
        expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
      });

      await this.logJWTAttack({
        type: 'WEAK_SECRET',
        severity: ATTACK_SEVERITY.HIGH,
        payload: { secret: JWT_CONFIG.WEAK_SECRET },
        patterns: [],
        context,
      });

      return {
        success: true,
        vulnerable: true,
        token,
        warning: `⚠️ Weak secret key: "${JWT_CONFIG.WEAK_SECRET}" - easily brute-forced`,
        bruteForceInfo: {
          secret: JWT_CONFIG.WEAK_SECRET,
          inCommonList: WEAK_SECRETS.includes(JWT_CONFIG.WEAK_SECRET),
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleJWTError(error, 'weak_secret', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Algorithm Confusion (RS256 → HS256)
   * 
   * Attack: Change asymmetric to symmetric algorithm
   * 
   * @param {object} payload - JWT payload
   * @param {string} publicKey - Public key (VULNERABLE - used as secret)
   * @param {object} context - Request context
   * @returns {Promise<object>} Forged token
   */
  async vulnerableAlgorithmConfusion(payload, publicKey, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.algorithmConfusion++;

      logger.warn('🚨 ALGORITHM CONFUSION ATTACK', {
        payload,
        attack: 'RS256 → HS256',
      });

      // ⚠️ VULNERABLE: Sign with public key using HMAC (HS256)
      const token = jwt.sign(payload, publicKey, {
        algorithm: 'HS256',
      });

      await this.logJWTAttack({
        type: 'ALGORITHM_CONFUSION',
        severity: ATTACK_SEVERITY.CRITICAL,
        payload: { algorithm: 'HS256', originalAlgorithm: 'RS256' },
        patterns: [],
        context,
      });

      this.attackStats.successfulBypasses++;

      return {
        success: true,
        vulnerable: true,
        token,
        warning: '⚠️ Algorithm confusion - public key used as HMAC secret',
        attack: {
          technique: 'RS256 to HS256 confusion',
          description: 'Server expects RS256 but verifies with HS256 using public key as secret',
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleJWTError(error, 'algorithm_confusion', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: No Signature Verification
   * 
   * Attack: Server doesn't verify signature at all
   * 
   * @param {string} token - JWT token
   * @param {object} context - Request context
   * @returns {Promise<object>} Verification result
   */
  async vulnerableNoVerification(token, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      logger.warn('🚨 NO SIGNATURE VERIFICATION', {
        token: token.substring(0, 50),
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: Just decode without verifying
      const decoded = jwt.decode(token, { complete: true });

      if (!decoded) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid token format',
        };
      }

      this.attackStats.successfulBypasses++;

      await this.logJWTAttack({
        type: 'NO_VERIFICATION',
        severity: ATTACK_SEVERITY.CRITICAL,
        payload: { payload: decoded.payload },
        patterns: [],
        context,
      });

      return {
        success: true,
        vulnerable: true,
        payload: decoded.payload,
        header: decoded.header,
        warning: '⚠️ No signature verification - any token accepted',
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleJWTError(error, token, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Expired Token Acceptance
   * 
   * Attack: Accept tokens past their expiration
   * 
   * @param {string} token - Expired JWT token
   * @param {object} context - Request context
   * @returns {Promise<object>} Verification result
   */
  async vulnerableAcceptExpired(token, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.expiredTokenAccepted++;

      logger.warn('🚨 ACCEPTING EXPIRED TOKEN', {
        token: token.substring(0, 50),
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: Verify without checking expiration
      const decoded = jwt.verify(token, JWT_CONFIG.STRONG_SECRET, {
        algorithms: ['HS256'],
        ignoreExpiration: true, // VULNERABLE
      });

      const now = Math.floor(Date.now() / 1000);
      const expired = decoded.exp && decoded.exp < now;
      const expiredFor = expired ? now - decoded.exp : 0;

      if (expired) {
        logger.warn('Expired token accepted', {
          expiredAt: new Date(decoded.exp * 1000).toISOString(),
          expiredForSeconds: expiredFor,
        });

        this.attackStats.successfulBypasses++;

        await this.logJWTAttack({
          type: 'EXPIRED_TOKEN_ACCEPTED',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { expiredForSeconds: expiredFor },
          patterns: [],
          context,
        });
      }

      return {
        success: true,
        vulnerable: true,
        payload: decoded,
        warning: expired ? '⚠️ Expired token accepted - no expiration check' : 'Token valid',
        expirationInfo: {
          expired,
          expiredAt: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null,
          expiredForSeconds: expiredFor,
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleJWTError(error, token, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Token Tampering (Payload Modification)
   * 
   * Attack: Modify token payload and re-sign with weak secret
   * 
   * @param {string} originalToken - Original JWT
   * @param {object} modifications - Payload modifications
   * @param {object} context - Request context
   * @returns {Promise<object>} Tampered token
   */
  async vulnerableTokenTampering(originalToken, modifications, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.tamperedTokens++;

      // Decode original token
      const decoded = jwt.decode(originalToken);

      if (!decoded) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid token',
        };
      }

      // ⚠️ VULNERABLE: Modify payload
      const tamperedPayload = { ...decoded, ...modifications };

      logger.warn('🚨 TOKEN TAMPERING', {
        original: decoded,
        tampered: tamperedPayload,
        modifications,
      });

      // Re-sign with weak secret (assuming attacker knows it)
      const tamperedToken = jwt.sign(tamperedPayload, JWT_CONFIG.WEAK_SECRET, {
        algorithm: 'HS256',
      });

      await this.logJWTAttack({
        type: 'TOKEN_TAMPERING',
        severity: ATTACK_SEVERITY.CRITICAL,
        payload: { modifications },
        patterns: [],
        context,
      });

      this.attackStats.successfulBypasses++;

      return {
        success: true,
        vulnerable: true,
        originalToken,
        tamperedToken,
        originalPayload: decoded,
        tamperedPayload,
        modifications,
        warning: '⚠️ Token tampered and re-signed - weak secret enables forgery',
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleJWTError(error, originalToken, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: No Token Revocation
   * 
   * Attack: Stolen tokens remain valid until expiration
   * 
   * @param {string} token - JWT token
   * @param {boolean} revoked - Revocation flag (ignored in vulnerable mode)
   * @param {object} context - Request context
   * @returns {Promise<object>} Verification result
   */
  async vulnerableNoRevocation(token, revoked, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      // ⚠️ VULNERABLE: No revocation check
      const decoded = jwt.verify(token, JWT_CONFIG.STRONG_SECRET, {
        algorithms: ['HS256'],
      });

      logger.warn('🚨 NO TOKEN REVOCATION CHECK', {
        userId: decoded.userId,
        revoked,
        token: token.substring(0, 50),
      });

      if (revoked) {
        await this.logJWTAttack({
          type: 'REVOKED_TOKEN_ACCEPTED',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { userId: decoded.userId },
          patterns: [],
          context,
        });

        this.attackStats.successfulBypasses++;
      }

      return {
        success: true,
        vulnerable: true,
        payload: decoded,
        warning: revoked ? '⚠️ Revoked token accepted - no blacklist check' : 'Token valid',
        revocationInfo: {
          shouldBeRevoked: revoked,
          accepted: true,
          reason: 'No revocation mechanism implemented',
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleJWTError(error, token, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Generate JWT with Strong Secret and Proper Claims
   */
  async secureGenerateToken(payload, type = 'access') {
    const startTime = Date.now();

    try {
      // ✅ Add security claims
      const securePayload = {
        ...payload,
        iss: JWT_CONFIG.ISSUER,
        aud: JWT_CONFIG.AUDIENCE,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomBytes(16).toString('hex'), // Unique token ID
      };

      const expiresIn = type === 'refresh' ? 
        JWT_CONFIG.REFRESH_TOKEN_EXPIRY : 
        JWT_CONFIG.ACCESS_TOKEN_EXPIRY;

      // ✅ Use strong secret
      const token = jwt.sign(securePayload, JWT_CONFIG.STRONG_SECRET, {
        algorithm: 'HS256',
        expiresIn,
      });

      return {
        success: true,
        vulnerable: false,
        token,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_JWT_GENERATION',
          algorithm: 'HS256',
          expiresIn,
        },
      };

    } catch (error) {
      logger.error('Secure JWT generation error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Verify JWT with All Security Checks
   */
  async secureVerifyToken(token, type = 'access') {
    const startTime = Date.now();

    try {
      // ✅ Comprehensive verification
      const decoded = jwt.verify(token, JWT_CONFIG.STRONG_SECRET, {
        algorithms: ['HS256'], // ✅ Explicit algorithm whitelist
        issuer: JWT_CONFIG.ISSUER,
        audience: JWT_CONFIG.AUDIENCE,
        clockTolerance: 0, // ✅ No clock skew tolerance
      });

      // ✅ Check token revocation
      const isRevoked = await this.isTokenRevoked(decoded.jti);
      if (isRevoked) {
        throw new AppError('Token has been revoked', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Verify token type
      if (decoded.type !== type) {
        throw new AppError('Invalid token type', HTTP_STATUS.UNAUTHORIZED);
      }

      return {
        success: true,
        vulnerable: false,
        payload: decoded,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_JWT_VERIFICATION',
        },
      };

    } catch (error) {
      logger.error('Secure JWT verification error', { error: error.message });
      throw error;
    }
  }

  /**
   * Check if token is revoked
   */
  async isTokenRevoked(jti) {
    const key = `revoked_token:${jti}`;
    return await cache.get(key) !== null;
  }

  /**
   * Revoke token
   */
  async revokeToken(jti, ttl = 86400) {
    const key = `revoked_token:${jti}`;
    await cache.set(key, 'revoked', ttl);
    logger.info('Token revoked', { jti });
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Log JWT attack
   */
  async logJWTAttack(attackData) {
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

      logger.attack('JWT Attack Detected', {
        type,
        severity,
        payload,
        context,
      });

    } catch (error) {
      logger.error('Failed to log JWT attack', { error: error.message });
    }
  }

  /**
   * Handle JWT errors
   */
  handleJWTError(error, identifier, duration) {
    logger.error('JWT Attack Error', {
      message: error.message,
      identifier,
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
        errorType: 'JWT_ERROR',
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
      bypassRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulBypasses / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
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
      description: 'JWT vulnerabilities allow attackers to bypass authentication, forge tokens, or maintain unauthorized access',
      impact: [
        'Complete authentication bypass',
        'Privilege escalation',
        'Account takeover',
        'Identity forgery',
        'Unauthorized access',
        'Data breach',
      ],
      attackTypes: [
        'Algorithm None - Remove signature',
        'Algorithm Confusion - RS256 to HS256',
        'Weak Secret - Brute force signing key',
        'Key Confusion - Use public key as secret',
        'Token Tampering - Modify payload',
        'Expired Token Bypass',
        'No Revocation - Stolen tokens remain valid',
        'JWK Header Injection',
        'Kid Parameter Injection',
      ],
      vulnerabilities: [
        'Accepting algorithm "none"',
        'No algorithm whitelisting',
        'Weak signing secrets',
        'No signature verification',
        'Algorithm confusion vulnerabilities',
        'No expiration checking',
        'No token revocation mechanism',
        'Missing security claims validation',
      ],
      remediation: [
        'Never accept algorithm "none"',
        'Use explicit algorithm whitelist',
        'Use strong, random secrets (256+ bits)',
        'Always verify signatures',
        'Validate all JWT claims (iss, aud, exp)',
        'Implement token revocation (blacklist)',
        'Use short-lived tokens',
        'Rotate signing keys regularly',
        'Separate access and refresh tokens',
        'Add unique token IDs (jti claim)',
        'Implement proper key management',
        'Monitor for suspicious JWT patterns',
      ],
      references: [
        'https://owasp.org/www-community/vulnerabilities/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java',
        'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
        'CWE-287: Improper Authentication',
        'https://jwt.io/',
        'RFC 7519: JSON Web Token (JWT)',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      algorithmNoneAttacks: 0,
      algorithmConfusion: 0,
      weakSecretExploits: 0,
      tamperedTokens: 0,
      expiredTokenAccepted: 0,
      successfulBypasses: 0,
    };
  }

  /**
   * Get weak secrets list
   */
  getWeakSecrets() {
    return WEAK_SECRETS;
  }

  /**
   * Brute force weak secret (demonstration)
   */
  async bruteForceSecret(token) {
    const startTime = Date.now();

    for (const secret of WEAK_SECRETS) {
      try {
        const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
        const duration = Date.now() - startTime;

        logger.warn('Secret brute-forced', {
          secret,
          timeTaken: `${duration}ms`,
        });

        return {
          success: true,
          secret,
          decoded,
          timeTaken: duration,
        };
      } catch (error) {
        // Continue trying
      }
    }

    return {
      success: false,
      message: 'Secret not found in common list',
      timeTaken: Date.now() - startTime,
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getJWTBypass = () => {
  if (!instance) {
    instance = new JWTBypass();
  }
  return instance;
};

export const createJWTHandler = (method) => {
  return async (req, res, next) => {
    try {
      const jwtAttack = getJWTBypass();
      
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
      const result = await jwtAttack[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  JWTBypass,
  getJWTBypass,
  createJWTHandler,
};
