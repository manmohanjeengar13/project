/**
 * ============================================================================
 * DOM-BASED XSS VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade DOM XSS Demonstration Platform
 * Implements client-side Cross-Site Scripting vulnerabilities
 * 
 * @module vulnerabilities/xss/dom
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * DOM-based XSS occurs entirely client-side through unsafe JavaScript
 * 
 * ⚠️  FOR EDUCATIONAL PURPOSES ONLY
 * 
 * ATTACK TYPES:
 * 1. document.write() with user input
 * 2. innerHTML manipulation
 * 3. eval() with user data
 * 4. location.hash exploitation
 * 5. postMessage vulnerabilities
 * 
 * @requires Database
 * @requires Logger
 */

import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { HTTP_STATUS, ATTACK_SEVERITY, ERROR_CODES } from '../../config/constants.js';

const db = Database.getInstance();
const logger = Logger.getInstance();

export class DOMBasedXSS {
  constructor() {
    this.name = 'DOM-Based XSS';
    this.category = 'Cross-Site Scripting';
    this.cvssScore = 7.3;
    this.severity = ATTACK_SEVERITY.MEDIUM;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-79';
    
    this.attackStats = {
      totalAttempts: 0,
      domManipulations: 0,
      evalUsage: 0,
      innerHTMLUsage: 0,
      successfulAttacks: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE CODE EXAMPLES (Client-Side)
  // ==========================================================================

  /**
   * Generate vulnerable client-side code examples
   */
  getVulnerableExamples() {
    return {
      innerHTML: {
        vulnerable: `
// ⚠️ VULNERABLE
const search = location.hash.substring(1);
document.getElementById('results').innerHTML = 'Search for: ' + search;

// Attack: #<img src=x onerror=alert(1)>
        `,
        secure: `
// ✅ SECURE
const search = location.hash.substring(1);
document.getElementById('results').textContent = 'Search for: ' + search;
        `,
      },
      
      documentWrite: {
        vulnerable: `
// ⚠️ VULNERABLE
const name = new URLSearchParams(location.search).get('name');
document.write('<h1>Welcome ' + name + '</h1>');

// Attack: ?name=<script>alert(1)</script>
        `,
        secure: `
// ✅ SECURE
const name = new URLSearchParams(location.search).get('name');
const h1 = document.createElement('h1');
h1.textContent = 'Welcome ' + name;
document.body.appendChild(h1);
        `,
      },
      
      eval: {
        vulnerable: `
// ⚠️ VULNERABLE
const code = location.hash.substring(1);
eval(code);

// Attack: #alert(document.cookie)
        `,
        secure: `
// ✅ SECURE
// Never use eval() with user input
// Use JSON.parse() for data, not eval()
        `,
      },
      
      locationHash: {
        vulnerable: `
// ⚠️ VULNERABLE
const url = location.hash.substring(1);
window.location = url;

// Attack: #javascript:alert(1)
        `,
        secure: `
// ✅ SECURE
const url = location.hash.substring(1);
if (url.startsWith('http://') || url.startsWith('https://')) {
  window.location = url;
}
        `,
      },
    };
  }

  /**
   * ⚠️ VULNERABLE: API Endpoint Serving Vulnerable JS
   */
  async vulnerableDOMScriptEndpoint(context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.domManipulations++;

      logger.warn('🚨 SERVING VULNERABLE DOM XSS SCRIPT', { ip: context.ip });

      // ⚠️ VULNERABLE: Serve JavaScript with DOM XSS vulnerabilities
      const vulnerableScript = `
(function() {
  // ⚠️ VULNERABLE: innerHTML with location.hash
  const displayMessage = function() {
    const msg = location.hash.substring(1);
    document.getElementById('message').innerHTML = decodeURIComponent(msg);
  };
  
  // ⚠️ VULNERABLE: eval with URL parameter
  const executeCode = function() {
    const code = new URLSearchParams(location.search).get('code');
    if (code) {
      eval(code);
    }
  };
  
  // ⚠️ VULNERABLE: document.write with user input
  const welcomeUser = function() {
    const name = new URLSearchParams(location.search).get('name');
    if (name) {
      document.write('<h2>Welcome ' + name + '</h2>');
    }
  };
  
  window.addEventListener('load', displayMessage);
  window.addEventListener('load', executeCode);
  window.addEventListener('load', welcomeUser);
})();
      `;

      await this.logDOMAttack({
        type: 'DOM_XSS_SCRIPT_SERVED',
        severity: ATTACK_SEVERITY.HIGH,
        payload: { scriptType: 'vulnerable_dom_operations' },
        patterns: [],
        context,
      });

      return {
        success: true,
        vulnerable: true,
        script: vulnerableScript,
        warning: '⚠️ Script contains multiple DOM XSS vulnerabilities',
        vulnerabilities: [
          'innerHTML with location.hash',
          'eval() with URL parameter',
          'document.write() with user input',
        ],
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleDOMError(error, 'script', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: HTML Page with DOM XSS
   */
  async vulnerableDOMPage(context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const vulnerableHTML = `
<!DOCTYPE html>
<html>
<head>
  <title>DOM XSS Demo</title>
</head>
<body>
  <h1>Search Results</h1>
  <div id="message"></div>
  <div id="results"></div>
  
  <script>
    // ⚠️ VULNERABLE: Multiple DOM XSS issues
    (function() {
      // Get URL parameters
      const params = new URLSearchParams(window.location.search);
      const search = params.get('q');
      const message = location.hash.substring(1);
      
      // ⚠️ VULNERABLE: innerHTML
      if (message) {
        document.getElementById('message').innerHTML = message;
      }
      
      // ⚠️ VULNERABLE: document.write
      if (search) {
        document.write('<p>You searched for: ' + search + '</p>');
      }
      
      // ⚠️ VULNERABLE: eval
      const code = params.get('exec');
      if (code) {
        eval(code);
      }
    })();
  </script>
</body>
</html>
      `;

      logger.warn('🚨 SERVING VULNERABLE DOM XSS PAGE', { ip: context.ip });

      await this.logDOMAttack({
        type: 'DOM_XSS_PAGE_SERVED',
        severity: ATTACK_SEVERITY.HIGH,
        payload: { pageType: 'vulnerable_dom_page' },
        patterns: [],
        context,
      });

      return {
        success: true,
        vulnerable: true,
        html: vulnerableHTML,
        warning: '⚠️ Page contains multiple DOM XSS vulnerabilities',
        attackVectors: [
          '?q=<img src=x onerror=alert(1)>',
          '#<script>alert(1)</script>',
          '?exec=alert(document.cookie)',
        ],
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleDOMError(error, 'page', Date.now() - startTime);
    }
  }

  /**
   * Log detected DOM XSS patterns
   */
  async logDOMPatternDetection(pattern, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const dangerousPatterns = {
        innerHTML: /\.innerHTML\s*=/,
        eval: /eval\s*\(/,
        documentWrite: /document\.write\s*\(/,
        locationHash: /location\.hash/,
        unsafeAssignment: /\.src\s*=|\.href\s*=/,
      };

      const detectedIssues = [];
      
      for (const [name, regex] of Object.entries(dangerousPatterns)) {
        if (regex.test(pattern)) {
          detectedIssues.push(name);
        }
      }

      if (detectedIssues.length > 0) {
        await this.logDOMAttack({
          type: 'DOM_XSS_PATTERN_DETECTED',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { detectedIssues, pattern: pattern.substring(0, 200) },
          patterns: [],
          context,
        });

        this.attackStats.successfulAttacks++;
      }

      return {
        success: true,
        vulnerable: detectedIssues.length > 0,
        detectedIssues,
        pattern: pattern.substring(0, 200),
        warning: detectedIssues.length > 0 ? '⚠️ Dangerous DOM operations detected' : null,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleDOMError(error, 'pattern', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // LOGGING & UTILITIES
  // ==========================================================================

  async logDOMAttack(attackData) {
    try {
      const { type, severity, payload, patterns, context, timestamp = new Date() } = attackData;

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

      logger.attack('DOM XSS Attack Detected', { type, severity, payload, context });

    } catch (error) {
      logger.error('Failed to log DOM attack', { error: error.message });
    }
  }

  handleDOMError(error, identifier, duration) {
    logger.error('DOM XSS Error', { message: error.message, identifier, duration });
    return {
      success: false,
      vulnerable: true,
      error: { message: error.message, code: error.code },
      metadata: { executionTime: duration, errorType: 'DOM_XSS_ERROR' },
    };
  }

  getStatistics() {
    return {
      ...this.attackStats,
      attackRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulAttacks / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
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
      description: 'DOM-based XSS occurs when JavaScript reads user-controllable data and writes it to dangerous sinks',
      impact: [
        'Session hijacking',
        'Credential theft',
        'Malware distribution',
        'Phishing',
      ],
      dangerousSinks: [
        'innerHTML',
        'outerHTML',
        'document.write()',
        'document.writeln()',
        'eval()',
        'setTimeout() with string',
        'setInterval() with string',
        'Function() constructor',
        'location',
        'location.href',
      ],
      remediation: [
        'Use textContent instead of innerHTML',
        'Never use eval()',
        'Validate and sanitize URL parameters',
        'Use Content Security Policy',
        'Avoid document.write()',
        'Use safe DOM manipulation methods',
      ],
      references: [
        'https://owasp.org/www-community/attacks/DOM_Based_XSS',
        'CWE-79',
      ],
    };
  }

  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      domManipulations: 0,
      evalUsage: 0,
      innerHTMLUsage: 0,
      successfulAttacks: 0,
    };
  }
}

let instance = null;

export const getDOMBasedXSS = () => {
  if (!instance) {
    instance = new DOMBasedXSS();
  }
  return instance;
};

export const createDOMXSSHandler = (method) => {
  return async (req, res, next) => {
    try {
      const xss = getDOMBasedXSS();
      
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
      const result = await xss[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  DOMBasedXSS,
  getDOMBasedXSS,
  createDOMXSSHandler,
};
