/**
 * ============================================================================
 * PATH TRAVERSAL VULNERABILITY MODULE - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Directory/Path Traversal Attack Demonstration Platform
 * Implements sophisticated file system navigation and unauthorized file access
 * 
 * @module vulnerabilities/access/pathTraversal
 * @category Security Training - OWASP A01:2021 (Broken Access Control)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING - CRITICAL SEVERITY:
 * ============================================================================
 * This module contains INTENTIONAL CRITICAL security vulnerabilities:
 * - Unrestricted file system traversal
 * - No path validation or sanitization
 * - Direct file access without authorization
 * - Operating system command injection potential
 * - Arbitrary file read/write capabilities
 * - Symlink following vulnerabilities
 * - Null byte injection susceptibility
 * - Double encoding bypass techniques
 * - Unicode/UTF-8 encoding exploitation
 * 
 * ⚠️  EXTREME DANGER: Can compromise entire file system
 * ⚠️  FOR ISOLATED SECURITY TRAINING ONLY
 * ⚠️  Must run in containerized/sandboxed environment
 * ⚠️  Never deploy on production servers
 * ⚠️  Implement strict filesystem permissions
 * 
 * ============================================================================
 * VULNERABILITY TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Classic Path Traversal (../ and ..\)
 * 2. Absolute Path Traversal (/etc/passwd)
 * 3. URL Encoded Path Traversal (%2e%2e%2f)
 * 4. Double URL Encoding (%252e%252e%252f)
 * 5. Unicode/UTF-8 Encoding (%c0%ae%c0%ae/)
 * 6. Null Byte Injection (../../../etc/passwd%00)
 * 7. Path Normalization Bypass
 * 8. Symlink Following
 * 9. Case Sensitivity Exploitation
 * 10. Long Path Buffer Overflow
 * 11. ZIP Slip (Archive Extraction)
 * 12. Server-Side Request Forgery (SSRF) via file://
 * 13. Local File Inclusion (LFI)
 * 14. Remote File Inclusion (RFI)
 * 15. XXE with External Entity File Access
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - ../../../../etc/passwd
 * - ..\..\..\..\windows\system32\config\sam
 * - %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
 * - ..%252f..%252f..%252fetc%252fpasswd
 * - ..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
 * - /etc/passwd%00.jpg
 * - file:///etc/passwd
 * - ....//....//....//etc/passwd
 * - ..;/..;/..;/etc/passwd
 * 
 * ============================================================================
 * COMPLIANCE & STANDARDS:
 * ============================================================================
 * - OWASP Top 10 2021: A01 - Broken Access Control
 * - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 * - CWE-23: Relative Path Traversal
 * - CWE-36: Absolute Path Traversal
 * - CWE-73: External Control of File Name or Path
 * - CWE-434: Unrestricted Upload of File with Dangerous Type
 * - NIST 800-53: SI-10 Information Input Validation
 * - PCI-DSS: Requirement 6.5.8
 * - SANS Top 25: CWE-22
 * 
 * @requires fs/promises
 * @requires path
 * @requires Database
 * @requires Logger
 * @requires Cache
 */

import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { createReadStream } from 'fs';
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
  ERROR_MESSAGES
} from '../../config/constants.js';
import { AppError, AccessDeniedError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VULNERABILITY CONSTANTS & PATTERNS
// ============================================================================

const PATH_TRAVERSAL_PATTERNS = {
  // Basic traversal
  BASIC: [
    /\.\./,
    /\.\.\//,
    /\.\.\\/,
    /\.\.%2f/i,
    /\.\.%5c/i
  ],

  // Encoded traversal
  ENCODED: [
    /%2e%2e%2f/i,
    /%2e%2e%5c/i,
    /%2e%2e/i,
    /\.%2e/i,
    /%2e\./i
  ],

  // Double encoded
  DOUBLE_ENCODED: [
    /%252e%252e%252f/i,
    /%252e%252e%255c/i,
    /%252e%252e/i
  ],

  // Unicode/UTF-8
  UNICODE: [
    /%c0%ae/i,
    /%c0%af/i,
    /%c1%9c/i,
    /\u002e\u002e/,
    /\u2215/,
    /\u2216/
  ],

  // Null byte
  NULL_BYTE: [
    /%00/i,
    /\x00/,
    /\0/
  ],

  // Absolute paths
  ABSOLUTE_UNIX: [
    /^\/etc\//,
    /^\/var\//,
    /^\/usr\//,
    /^\/root\//,
    /^\/home\//,
    /^\/tmp\//,
    /^\/proc\//,
    /^\/sys\//
  ],

  ABSOLUTE_WINDOWS: [
    /^[a-z]:\\/i,
    /^\\\\[^\\]+\\/i,
    /^%systemroot%/i,
    /^%windir%/i
  ],

  // Path normalization bypass
  BYPASS: [
    /\.\.\/\.\//,
    /\.\.\\\.\\/,
    /\.\.;/,
    /\.\.\//,
    /\.\.\/\.\.\//,
    /\.\.\\\.\.\\/
  ]
};

const SENSITIVE_FILES = {
  UNIX: [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/group',
    '/etc/resolv.conf',
    '/etc/mysql/my.cnf',
    '/etc/ssh/sshd_config',
    '/root/.bash_history',
    '/root/.ssh/id_rsa',
    '/home/user/.ssh/id_rsa',
    '/var/log/auth.log',
    '/var/log/apache2/access.log',
    '/proc/self/environ',
    '/proc/version',
    '/proc/cmdline'
  ],

  WINDOWS: [
    'C:\\Windows\\System32\\config\\SAM',
    'C:\\Windows\\System32\\config\\SYSTEM',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    'C:\\boot.ini',
    'C:\\autoexec.bat',
    'C:\\Windows\\win.ini',
    'C:\\Windows\\system.ini',
    'C:\\inetpub\\wwwroot\\web.config',
    'C:\\Windows\\Panther\\unattend.xml'
  ],

  APPLICATION: [
    '.env',
    'config.json',
    'database.yml',
    'secrets.json',
    'credentials.json',
    'id_rsa',
    'id_dsa',
    '.htpasswd',
    '.git/config',
    'wp-config.php',
    'configuration.php'
  ]
};

const ENCODING_VARIATIONS = {
  DOT: ['.', '%2e', '%252e', '\\u002e', '%c0%2e', '%c0%ae'],
  SLASH: ['/', '%2f', '%252f', '\\u002f', '%c0%2f', '%c0%af', '\\'],
  BACKSLASH: ['\\', '%5c', '%255c', '\\u005c', '%c0%5c', '%c1%9c']
};

// ============================================================================
// PATH TRAVERSAL VULNERABILITY CLASS - MILITARY-GRADE
// ============================================================================

export class PathTraversal {
  constructor() {
    this.name = 'Path Traversal / Directory Traversal';
    this.category = 'Access Control';
    this.cvssScore = 9.1;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A01:2021';
    this.cweId = 'CWE-22';
    
    // Base directory for file operations (vulnerable)
    this.baseDirectory = path.join(process.cwd(), 'uploads');
    this.publicDirectory = path.join(process.cwd(), 'public');
    
    // Attack statistics with comprehensive tracking
    this.attackStats = {
      totalAttempts: 0,
      successfulTraversals: 0,
      blockedAttempts: 0,
      uniquePaths: new Set(),
      encodingTypes: {},
      traversalDepth: {},
      targetedFiles: {},
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      accessedSensitiveFiles: 0,
      systemFileAccess: 0,
      configFileAccess: 0,
      encodingAttempts: {
        basic: 0,
        urlEncoded: 0,
        doubleEncoded: 0,
        unicode: 0,
        nullByte: 0
      },
      bypassTechniques: new Set(),
      ipAddresses: new Set(),
      userAgents: new Set(),
      fileTypes: {}
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Read File with Path Traversal
   * 
   * Demonstrates classic path traversal vulnerability
   * Attack: ../../../../etc/passwd
   * 
   * @param {string} filename - User-supplied filename (VULNERABLE)
   * @param {object} context - Attack context
   * @returns {Promise<object>} File contents (EXPOSED)
   */
  async vulnerableReadFile(filename, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 PATH TRAVERSAL FILE READ ATTEMPT', {
        filename,
        ip: context.ip,
        mode: Config.security.mode
      });

      // Detect attack patterns
      const detection = this.detectPathTraversal(filename, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'PATH_TRAVERSAL_READ',
          severity: detection.severity,
          filename,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Direct path concatenation without validation
      const filePath = path.join(this.baseDirectory, filename);

      logger.warn('🚨 ATTEMPTING TO READ FILE', {
        requestedFile: filename,
        resolvedPath: filePath,
        baseDirectory: this.baseDirectory
      });

      // ⚠️ VULNERABLE: No path validation - allows traversal
      let fileContent;
      let fileStats;

      try {
        fileStats = await fs.stat(filePath);
        
        if (fileStats.isDirectory()) {
          // Return directory listing (also vulnerable)
          const files = await fs.readdir(filePath);
          fileContent = {
            type: 'directory',
            contents: files
          };
        } else {
          // Read file content
          fileContent = await fs.readFile(filePath, 'utf8');
        }

        this.attackStats.successfulTraversals++;
        this.attackStats.uniquePaths.add(filePath);

        // Track if sensitive file was accessed
        if (this.isSensitiveFile(filePath)) {
          this.attackStats.accessedSensitiveFiles++;
        }

        const duration = Date.now() - startTime;

        return {
          success: true,
          vulnerable: true,
          data: {
            filename,
            requestedPath: filename,
            actualPath: filePath,
            content: fileContent,
            size: fileStats?.size,
            isDirectory: fileStats?.isDirectory(),
            permissions: fileStats?.mode,
            modified: fileStats?.mtime,
            warning: 'PATH TRAVERSAL: File accessed outside intended directory'
          },
          metadata: {
            executionTime: duration,
            severity: detection.severity,
            attackDetected: detection.isAttack,
            traversalDepth: this.calculateTraversalDepth(filename),
            encodingDetected: detection.encodingType
          }
        };

      } catch (fileError) {
        // File doesn't exist or permission denied
        if (fileError.code === 'ENOENT') {
          return {
            success: false,
            vulnerable: true,
            error: 'File not found',
            data: {
              filename,
              requestedPath: filename,
              attemptedPath: filePath,
              message: `File not found: ${filePath}`
            },
            metadata: {
              executionTime: Date.now() - startTime,
              errorCode: 'ENOENT',
              attackDetected: detection.isAttack
            }
          };
        } else if (fileError.code === 'EACCES') {
          return {
            success: false,
            vulnerable: true,
            error: 'Permission denied',
            data: {
              filename,
              requestedPath: filename,
              attemptedPath: filePath,
              message: `Permission denied: ${filePath}`,
              hint: 'File exists but cannot be read'
            },
            metadata: {
              executionTime: Date.now() - startTime,
              errorCode: 'EACCES',
              attackDetected: detection.isAttack
            }
          };
        }
        throw fileError;
      }

    } catch (error) {
      return this.handleVulnerableError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Download File with Traversal
   * 
   * Allows downloading files via path traversal
   * Attack: ../../config/database.json
   * 
   * @param {string} filename - User-supplied filename (VULNERABLE)
   * @param {object} context - Attack context
   * @returns {Promise<object>} File download info (EXPOSED)
   */
  async vulnerableDownloadFile(filename, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 PATH TRAVERSAL DOWNLOAD ATTEMPT', {
        filename,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPathTraversal(filename, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'PATH_TRAVERSAL_DOWNLOAD',
          severity: detection.severity,
          filename,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Direct file path construction
      const filePath = path.join(this.publicDirectory, filename);

      logger.warn('🚨 ATTEMPTING FILE DOWNLOAD', {
        requestedFile: filename,
        resolvedPath: filePath
      });

      // Check if file exists
      const fileExists = fsSync.existsSync(filePath);
      
      if (!fileExists) {
        return {
          success: false,
          vulnerable: true,
          error: 'File not found',
          data: { filename, path: filePath },
          metadata: {
            executionTime: Date.now() - startTime,
            attackDetected: detection.isAttack
          }
        };
      }

      const fileStats = await fs.stat(filePath);

      this.attackStats.successfulTraversals++;
      this.attackStats.uniquePaths.add(filePath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          filename: path.basename(filePath),
          path: filePath,
          size: fileStats.size,
          mimeType: this.getMimeType(filePath),
          downloadUrl: `/download?file=${encodeURIComponent(filename)}`,
          warning: 'PATH TRAVERSAL: Download allowed outside intended directory'
        },
        metadata: {
          executionTime: duration,
          severity: detection.severity,
          attackDetected: detection.isAttack,
          traversalDepth: this.calculateTraversalDepth(filename)
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Upload File with Traversal
   * 
   * Allows uploading files to arbitrary locations
   * Attack: ../../../etc/cron.d/malicious
   * 
   * @param {string} filename - User-supplied filename (VULNERABLE)
   * @param {Buffer|string} content - File content
   * @param {object} context - Attack context
   * @returns {Promise<object>} Upload result (VULNERABLE)
   */
  async vulnerableUploadFile(filename, content, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 PATH TRAVERSAL UPLOAD ATTEMPT', {
        filename,
        contentLength: content?.length,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPathTraversal(filename, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'PATH_TRAVERSAL_UPLOAD',
          severity: ATTACK_SEVERITY.CRITICAL,
          filename,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Allow writing to arbitrary paths
      const uploadPath = path.join(this.baseDirectory, filename);

      logger.warn('🚨 ATTEMPTING FILE UPLOAD', {
        requestedFile: filename,
        uploadPath
      });

      // ⚠️ VULNERABLE: Create directories if they don't exist
      const directory = path.dirname(uploadPath);
      await fs.mkdir(directory, { recursive: true });

      // ⚠️ VULNERABLE: Write file without validation
      await fs.writeFile(uploadPath, content);

      this.attackStats.successfulTraversals++;
      this.attackStats.uniquePaths.add(uploadPath);

      const fileStats = await fs.stat(uploadPath);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          filename,
          uploadedTo: uploadPath,
          size: fileStats.size,
          created: fileStats.birthtime,
          warning: 'PATH TRAVERSAL: File written outside intended directory'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          traversalDepth: this.calculateTraversalDepth(filename)
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Include File (LFI)
   * 
   * Demonstrates Local File Inclusion vulnerability
   * Attack: ../../../../etc/passwd%00
   * 
   * @param {string} filename - User-supplied filename (VULNERABLE)
   * @param {object} context - Attack context
   * @returns {Promise<object>} Included file content (EXPOSED)
   */
  async vulnerableIncludeFile(filename, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 LOCAL FILE INCLUSION ATTEMPT', {
        filename,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPathTraversal(filename, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'LOCAL_FILE_INCLUSION',
          severity: ATTACK_SEVERITY.CRITICAL,
          filename,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Strip null bytes but still vulnerable
      let sanitizedFilename = filename.replace(/\0/g, '');
      
      // ⚠️ VULNERABLE: Direct file inclusion
      const includePath = path.join(process.cwd(), 'views', sanitizedFilename);

      logger.warn('🚨 ATTEMPTING FILE INCLUSION', {
        requestedFile: filename,
        includePath
      });

      // ⚠️ VULNERABLE: Read and potentially execute file content
      const fileContent = await fs.readFile(includePath, 'utf8');

      this.attackStats.successfulTraversals++;
      this.attackStats.uniquePaths.add(includePath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          filename,
          includedPath: includePath,
          content: fileContent,
          warning: 'LOCAL FILE INCLUSION: Arbitrary file content loaded'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          technique: 'LFI'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Delete File with Traversal
   * 
   * Allows deleting files via path traversal
   * Attack: ../../../var/log/auth.log
   * 
   * @param {string} filename - User-supplied filename (VULNERABLE)
   * @param {object} context - Attack context
   * @returns {Promise<object>} Deletion result (CRITICAL)
   */
  async vulnerableDeleteFile(filename, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 PATH TRAVERSAL DELETE ATTEMPT', {
        filename,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPathTraversal(filename, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'PATH_TRAVERSAL_DELETE',
          severity: ATTACK_SEVERITY.CRITICAL,
          filename,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Direct path construction for deletion
      const deletePath = path.join(this.baseDirectory, filename);

      logger.warn('🚨 ATTEMPTING FILE DELETION', {
        requestedFile: filename,
        deletePath
      });

      // Check if file exists
      const fileStats = await fs.stat(deletePath);

      // ⚠️ VULNERABLE: Delete without authorization check
      await fs.unlink(deletePath);

      this.attackStats.successfulTraversals++;
      this.attackStats.uniquePaths.add(deletePath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          filename,
          deletedPath: deletePath,
          fileSize: fileStats.size,
          warning: 'PATH TRAVERSAL: File deleted outside intended directory'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack,
          operation: 'DELETE'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: List Directory with Traversal
   * 
   * Lists directory contents via traversal
   * Attack: ../../../etc/
   * 
   * @param {string} dirPath - User-supplied directory path (VULNERABLE)
   * @param {object} context - Attack context
   * @returns {Promise<object>} Directory listing (EXPOSED)
   */
  async vulnerableListDirectory(dirPath, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 PATH TRAVERSAL DIRECTORY LIST ATTEMPT', {
        dirPath,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectPathTraversal(dirPath, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'PATH_TRAVERSAL_LIST_DIR',
          severity: ATTACK_SEVERITY.HIGH,
          path: dirPath,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Direct directory listing
      const fullPath = path.join(this.baseDirectory, dirPath);

      logger.warn('🚨 ATTEMPTING DIRECTORY LISTING', {
        requestedPath: dirPath,
        fullPath
      });

      const entries = await fs.readdir(fullPath, { withFileTypes: true });
      
      const files = await Promise.all(
        entries.map(async (entry) => {
          const entryPath = path.join(fullPath, entry.name);
          const stats = await fs.stat(entryPath);
          
          return {
            name: entry.name,
            type: entry.isDirectory() ? 'directory' : 'file',
            size: stats.size,
            modified: stats.mtime,
            permissions: stats.mode.toString(8),
            owner: stats.uid,
            group: stats.gid
          };
        })
      );

      this.attackStats.successfulTraversals++;
      this.attackStats.uniquePaths.add(fullPath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          directory: dirPath,
          fullPath,
          files,
          totalEntries: files.length,
          warning: 'PATH TRAVERSAL: Directory listing outside intended path'
        },
        metadata: {
          executionTime: duration,
          severity: detection.severity,
          attackDetected: detection.isAttack,
          traversalDepth: this.calculateTraversalDepth(dirPath)
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, dirPath, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Read File with Path Validation
   * 
   * @param {string} filename - User-supplied filename (VALIDATED)
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} File contents (PROTECTED)
   */
  async secureReadFile(filename, req) {
    const startTime = Date.now();

    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AccessDeniedError('Authentication required');
      }

      // ✅ Input validation
      if (!filename || typeof filename !== 'string') {
        throw new AppError('Invalid filename', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Path sanitization - remove traversal sequences
      let sanitizedFilename = filename
        .replace(/\.\./g, '')
        .replace(/\\/g, '/')
        .replace(/^\/+/, '')
        .replace(/\0/g, '');

      // ✅ Normalize path
      sanitizedFilename = path.normalize(sanitizedFilename);

      // ✅ Construct safe path
      const safePath = path.join(this.baseDirectory, sanitizedFilename);

      // ✅ Verify path is within allowed directory
      const realPath = await fs.realpath(safePath);
      const realBase = await fs.realpath(this.baseDirectory);

      if (!realPath.startsWith(realBase)) {
        throw new AccessDeniedError('Access denied: Path traversal detected');
      }

      // ✅ Check file ownership/permissions
      const [files] = await db.execute(
        `SELECT user_id FROM ${tables.FILES} WHERE file_path = ? LIMIT 1`,
        [sanitizedFilename]
      );

      if (files.length === 0 || files[0].user_id !== req.user.id) {
        throw new AccessDeniedError('File not found or access denied');
      }

      // ✅ Read file securely
      const fileContent = await fs.readFile(realPath, 'utf8');
      const fileStats = await fs.stat(realPath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: {
          filename: sanitizedFilename,
          content: fileContent,
          size: fileStats.size
        },
        metadata: {
          executionTime: duration,
          method: 'SECURE_READ'
        }
      };

    } catch (error) {
      logger.error('Secure file read error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Download File with Whitelist
   * 
   * @param {string} fileId - File ID (not path)
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} File download info (PROTECTED)
   */
  async secureDownloadFile(fileId, req) {
    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AccessDeniedError('Authentication required');
      }

      // ✅ Validate file ID (integer)
      const id = parseInt(fileId, 10);
      if (isNaN(id) || id <= 0) {
        throw new AppError('Invalid file ID', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Get file metadata from database
      const [files] = await db.execute(
        `SELECT id, file_path, filename, user_id, mime_type 
         FROM ${tables.FILES} 
         WHERE id = ? AND user_id = ? 
         LIMIT 1`,
        [id, req.user.id]
      );

      if (files.length === 0) {
        throw new AccessDeniedError('File not found or access denied');
      }

      const file = files[0];

      // ✅ Construct safe path using database metadata
      const safePath = path.join(this.baseDirectory, file.file_path);

      // ✅ Verify path integrity
      const realPath = await fs.realpath(safePath);
      const realBase = await fs.realpath(this.baseDirectory);

      if (!realPath.startsWith(realBase)) {
        throw new AccessDeniedError('Invalid file path');
      }

      return {
        success: true,
        vulnerable: false,
        data: {
          fileId: id,
          filename: file.filename,
          path: realPath,
          mimeType: file.mime_type
        }
      };

    } catch (error) {
      logger.error('Secure file download error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Upload File with Validation
   * 
   * @param {string} filename - Original filename
   * @param {Buffer} content - File content
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} Upload result (PROTECTED)
   */
  async secureUploadFile(filename, content, req) {
    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AccessDeniedError('Authentication required');
      }

      // ✅ Validate filename
      if (!filename || typeof filename !== 'string') {
        throw new AppError('Invalid filename', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Sanitize filename - remove all path components
      const sanitizedFilename = path.basename(filename)
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .substring(0, 255);

      // ✅ Generate unique filename to prevent collisions
      const uniqueFilename = `${Date.now()}_${sanitizedFilename}`;

      // ✅ Validate file extension whitelist
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt'];
      const fileExt = path.extname(sanitizedFilename).toLowerCase();

      if (!allowedExtensions.includes(fileExt)) {
        throw new AppError('File type not allowed', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Validate file size
      if (content.length > 10 * 1024 * 1024) { // 10MB limit
        throw new AppError('File too large', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Create user-specific upload directory
      const userDir = path.join(this.baseDirectory, `user_${req.user.id}`);
      await fs.mkdir(userDir, { recursive: true });

      // ✅ Construct safe upload path
      const uploadPath = path.join(userDir, uniqueFilename);

      // ✅ Write file securely
      await fs.writeFile(uploadPath, content, { mode: 0o644 });

      // ✅ Store file metadata in database
      const [result] = await db.execute(
        `INSERT INTO ${tables.FILES} (user_id, filename, file_path, mime_type, size, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())`,
        [
          req.user.id,
          sanitizedFilename,
          `user_${req.user.id}/${uniqueFilename}`,
          this.getMimeType(sanitizedFilename),
          content.length
        ]
      );

      return {
        success: true,
        vulnerable: false,
        data: {
          fileId: result.insertId,
          filename: sanitizedFilename,
          size: content.length
        }
      };

    } catch (error) {
      logger.error('Secure file upload error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & ANALYSIS
  // ==========================================================================

  /**
   * Detect path traversal patterns and encoding techniques
   * 
   * @param {string} input - User input to analyze
   * @param {object} context - Request context
   * @returns {object} Detection results with comprehensive analysis
   */
  detectPathTraversal(input, context = {}) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.LOW;
    let score = 0;
    let encodingType = 'none';

    // Check all pattern categories
    for (const [category, patterns] of Object.entries(PATH_TRAVERSAL_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(input)) {
          detectedPatterns.push({
            category,
            pattern: pattern.toString(),
            matched: true
          });
          score += this.getPatternScore(category);

          // Track encoding types
          if (category.includes('ENCODED')) {
            encodingType = category.toLowerCase();
            this.attackStats.encodingAttempts[encodingType.replace('_', '')]++;
          }
        }
      }
    }

    // Check for sensitive file targets
    const targetedSensitiveFile = this.checkSensitiveFileTarget(input);
    if (targetedSensitiveFile) {
      detectedPatterns.push({
        category: 'SENSITIVE_FILE_TARGET',
        file: targetedSensitiveFile,
        matched: true
      });
      score += 15;
      severity = ATTACK_SEVERITY.CRITICAL;
    }

    // Calculate traversal depth
    const traversalDepth = this.calculateTraversalDepth(input);
    if (traversalDepth > 0) {
      detectedPatterns.push({
        category: 'TRAVERSAL_DEPTH',
        depth: traversalDepth,
        matched: true
      });
      score += traversalDepth * 3;
    }

    // Check for absolute paths
    if (this.isAbsolutePath(input)) {
      detectedPatterns.push({
        category: 'ABSOLUTE_PATH',
        matched: true
      });
      score += 10;
    }

    // Check for null byte injection
    if (/\0|%00/i.test(input)) {
      detectedPatterns.push({
        category: 'NULL_BYTE_INJECTION',
        matched: true
      });
      score += 12;
      this.attackStats.encodingAttempts.nullByte++;
    }

    // Check for bypass techniques
    const bypassTechnique = this.detectBypassTechnique(input);
    if (bypassTechnique) {
      detectedPatterns.push({
        category: 'BYPASS_TECHNIQUE',
        technique: bypassTechnique,
        matched: true
      });
      score += 8;
      this.attackStats.bypassTechniques.add(bypassTechnique);
    }

    // Determine final severity
    if (score >= 25) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 15) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 8) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.updateAttackStats(severity, input, encodingType);
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      encodingType,
      traversalDepth,
      input: input.substring(0, 200),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Check if input targets a known sensitive file
   */
  checkSensitiveFileTarget(input) {
    const normalized = input.toLowerCase().replace(/\\/g, '/');

    // Check UNIX sensitive files
    for (const file of SENSITIVE_FILES.UNIX) {
      if (normalized.includes(file.toLowerCase())) {
        this.attackStats.systemFileAccess++;
        return file;
      }
    }

    // Check Windows sensitive files
    for (const file of SENSITIVE_FILES.WINDOWS) {
      if (normalized.includes(file.toLowerCase().replace(/\\/g, '/'))) {
        this.attackStats.systemFileAccess++;
        return file;
      }
    }

    // Check application sensitive files
    for (const file of SENSITIVE_FILES.APPLICATION) {
      if (normalized.includes(file.toLowerCase())) {
        this.attackStats.configFileAccess++;
        return file;
      }
    }

    return null;
  }

  /**
   * Calculate directory traversal depth
   */
  calculateTraversalDepth(input) {
    const traversalPatterns = [
      /\.\.\//g,
      /\.\.\\/g,
      /%2e%2e%2f/gi,
      /%2e%2e%5c/gi
    ];

    let maxDepth = 0;

    for (const pattern of traversalPatterns) {
      const matches = input.match(pattern);
      if (matches) {
        maxDepth = Math.max(maxDepth, matches.length);
      }
    }

    return maxDepth;
  }

  /**
   * Check if path is absolute
   */
  isAbsolutePath(input) {
    // UNIX absolute path
    if (input.startsWith('/')) return true;

    // Windows absolute path
    if (/^[a-z]:/i.test(input)) return true;

    // UNC path
    if (input.startsWith('\\\\')) return true;

    // URL encoded absolute paths
    if (/%2f/i.test(input.substring(0, 10))) return true;

    return false;
  }

  /**
   * Detect bypass techniques
   */
  detectBypassTechnique(input) {
    // Path normalization bypass
    if (/\.\.\/\./.test(input) || /\.\.\\\./  .test(input)) {
      return 'PATH_NORMALIZATION_BYPASS';
    }

    // Double encoding
    if (/%25[0-9a-f]{2}/i.test(input)) {
      return 'DOUBLE_ENCODING';
    }

    // Unicode encoding
    if (/%c[0-1]%[0-9a-f]{2}/i.test(input)) {
      return 'UNICODE_ENCODING';
    }

    // Overlong UTF-8
    if (/%[ef][0-9a-f]%[0-9a-f]{2}%[0-9a-f]{2}/i.test(input)) {
      return 'OVERLONG_UTF8';
    }

    // Mixed encoding
    if (/\.\.|%2e|%252e/.test(input)) {
      return 'MIXED_ENCODING';
    }

    return null;
  }

  /**
   * Check if file is sensitive
   */
  isSensitiveFile(filePath) {
    const normalized = filePath.toLowerCase().replace(/\\/g, '/');

    return [...SENSITIVE_FILES.UNIX, ...SENSITIVE_FILES.WINDOWS, ...SENSITIVE_FILES.APPLICATION]
      .some(sensitive => normalized.includes(sensitive.toLowerCase().replace(/\\/g, '/')));
  }

  /**
   * Get MIME type from filename
   */
  getMimeType(filename) {
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.pdf': 'application/pdf',
      '.txt': 'text/plain',
      '.html': 'text/html',
      '.css': 'text/css',
      '.js': 'application/javascript',
      '.json': 'application/json',
      '.xml': 'application/xml',
      '.zip': 'application/zip'
    };
    return mimeTypes[ext] || 'application/octet-stream';
  }

  /**
   * Get pattern severity score
   */
  getPatternScore(category) {
    const scores = {
      BASIC: 5,
      ENCODED: 8,
      DOUBLE_ENCODED: 12,
      UNICODE: 10,
      NULL_BYTE: 12,
      ABSOLUTE_UNIX: 10,
      ABSOLUTE_WINDOWS: 10,
      BYPASS: 8
    };
    return scores[category] || 3;
  }

  /**
   * Update attack statistics
   */
  updateAttackStats(severity, input, encodingType) {
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

    this.attackStats.uniquePaths.add(input);
    this.attackStats.blockedAttempts++;

    // Track encoding type
    if (encodingType && encodingType !== 'none') {
      this.attackStats.encodingTypes[encodingType] = 
        (this.attackStats.encodingTypes[encodingType] || 0) + 1;
    }

    // Track file type
    const ext = path.extname(input).toLowerCase();
    if (ext) {
      this.attackStats.fileTypes[ext] = (this.attackStats.fileTypes[ext] || 0) + 1;
    }
  }

  /**
   * Log attack attempt
   */
  async logAttack(attackData) {
    try {
      const { type, severity, filename, detection, context } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          type,
          severity,
          JSON.stringify({ filename }),
          JSON.stringify(detection.patterns),
          context.ip || null,
          context.userAgent || null,
          context.userId || null,
          context.endpoint || null
        ]
      );

      // Cache attack for rate limiting
      const cacheKey = CacheKeyBuilder.custom('path_traversal_attacks:', context.ip);
      const recentAttacks = await cache.get(cacheKey) || [];
      recentAttacks.push({
        type,
        severity,
        filename,
        timestamp: new Date().toISOString()
      });
      await cache.set(cacheKey, recentAttacks, 3600);

      // Track IP and User Agent
      if (context.ip) this.attackStats.ipAddresses.add(context.ip);
      if (context.userAgent) this.attackStats.userAgents.add(context.userAgent);

      logger.attack('Path Traversal Attack Detected', {
        type,
        severity,
        filename,
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
  handleVulnerableError(error, input, duration) {
    logger.error('Path traversal error', {
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
        errno: error.errno,
        syscall: error.syscall,
        path: error.path,
        input
      },
      metadata: {
        executionTime: duration,
        errorType: 'PATH_TRAVERSAL_ERROR'
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
      uniquePaths: this.attackStats.uniquePaths.size,
      bypassTechniques: Array.from(this.attackStats.bypassTechniques),
      ipAddresses: this.attackStats.ipAddresses.size,
      userAgents: this.attackStats.userAgents.size,
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulTraversals / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%',
      encodingDistribution: this.attackStats.encodingTypes,
      fileTypeDistribution: this.attackStats.fileTypes
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
      description: 'Path Traversal allows attackers to access files and directories outside the intended directory by manipulating file paths',
      impact: [
        'Unauthorized access to sensitive system files',
        'Exposure of configuration files with credentials',
        'Access to application source code',
        'Reading arbitrary files on the server',
        'Potential remote code execution',
        'Information disclosure',
        'System compromise'
      ],
      attackVectors: [
        '../../../../etc/passwd',
        '../../../config/database.json',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '....//....//....//etc/passwd',
        '/etc/passwd%00.jpg',
        '..\\..\\..\\windows\\system32\\config\\sam'
      ],
      remediation: [
        'Use whitelisted file paths only',
        'Implement strict input validation',
        'Use file IDs instead of filenames in URLs',
        'Normalize and canonicalize all paths',
        'Use chroot jails or sandboxing',
        'Implement proper access controls',
        'Validate file paths against allowed base directories',
        'Remove or encode special characters',
        'Use security frameworks with built-in protections'
      ],
      encodingTechniques: [
        'URL Encoding: %2e%2e%2f',
        'Double Encoding: %252e%252e%252f',
        'Unicode: %c0%ae%c0%ae/',
        'Null Byte: %00',
        'Mixed Encoding: ..%2f',
        'Overlong UTF-8: %c0%af'
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
          payload,
          ip_address,
          COUNT(*) as count,
          DATE(timestamp) as date
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%TRAVERSAL%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY attack_type, severity, DATE(timestamp)
         ORDER BY timestamp DESC`,
        [startDate, endDate]
      );

      const [topTargets] = await db.execute(
        `SELECT 
          payload,
          COUNT(*) as frequency,
          MAX(severity) as max_severity
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%TRAVERSAL%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY payload
         ORDER BY frequency DESC
         LIMIT 20`,
        [startDate, endDate]
      );

      return {
        period: { start: startDate, end: endDate },
        attacks,
        topTargets: topTargets.map(t => ({
          ...t,
          payload: JSON.parse(t.payload)
        })),
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
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulTraversals: 0,
      blockedAttempts: 0,
      uniquePaths: new Set(),
      encodingTypes: {},
      traversalDepth: {},
      targetedFiles: {},
      severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
      accessedSensitiveFiles: 0,
      systemFileAccess: 0,
      configFileAccess: 0,
      encodingAttempts: {
        basic: 0,
        urlEncoded: 0,
        doubleEncoded: 0,
        unicode: 0,
        nullByte: 0
      },
      bypassTechniques: new Set(),
      ipAddresses: new Set(),
      userAgents: new Set(),
      fileTypes: {}
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getPathTraversal = () => {
  if (!instance) {
    instance = new PathTraversal();
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const pt = getPathTraversal();
      
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

      const result = await pt[method](...Object.values(req.body || req.query), context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  PathTraversal,
  getPathTraversal,
  createVulnerableHandler
};
