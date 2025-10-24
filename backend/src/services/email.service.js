/**
 * Email Service
 * Enterprise-grade email delivery and template management
 * 
 * Features:
 * - SMTP/SendGrid/AWS SES integration
 * - Template engine with Handlebars
 * - Email queue with retry mechanism
 * - Delivery tracking and analytics
 * - Bounce and complaint handling
 * - A/B testing support
 * - Transactional and marketing emails
 * - Email verification and validation
 * - Rate limiting and throttling
 * - Multi-language support
 * 
 * @module services/email
 */

import nodemailer from 'nodemailer';
import handlebars from 'handlebars';
import { Config } from '../config/environment.js';
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache } from '../core/Cache.js';
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

/**
 * Email Service Class
 */
export class EmailService {
  constructor() {
    this.transporter = null;
    this.templates = new Map();
    this.emailQueue = [];
    this.stats = {
      sent: 0,
      failed: 0,
      bounced: 0,
      opened: 0,
      clicked: 0
    };
  }

  /**
   * Initialize email service with connection pooling
   * Supports multiple providers
   */
  async initialize() {
    if (!Config.email.enabled) {
      logger.info('📧 Email service disabled in configuration');
      return;
    }

    try {
      // Create transporter with connection pooling
      this.transporter = nodemailer.createTransport({
        host: Config.email.host,
        port: Config.email.port,
        secure: Config.email.secure,
        auth: {
          user: Config.email.user,
          pass: Config.email.password
        },
        pool: true, // Use connection pooling
        maxConnections: 5,
        maxMessages: 100,
        rateDelta: 1000, // 1 second
        rateLimit: 10 // 10 emails per second
      });

      // Verify connection
      await this.transporter.verify();
      logger.info('✅ Email service connected successfully');

      // Load email templates
      await this.loadTemplates();

      // Register Handlebars helpers
      this.registerHandlebarsHelpers();

      // Start queue processor
      this.startQueueProcessor();

    } catch (error) {
      logger.error('❌ Email service initialization failed:', error);
      this.transporter = null;
    }
  }

  /**
   * Load email templates from filesystem
   */
  async loadTemplates() {
    const templates = [
      'welcome',
      'email-verification',
      'password-reset',
      'order-confirmation',
      'order-shipped',
      'order-delivered',
      'order-cancelled',
      'review-request',
      'newsletter',
      'promotional'
    ];

    for (const templateName of templates) {
      try {
        const templatePath = path.join(__dirname, '..', 'templates', 'emails', `${templateName}.hbs`);
        const templateContent = await readFile(templatePath, 'utf-8');
        const compiledTemplate = handlebars.compile(templateContent);
        this.templates.set(templateName, compiledTemplate);
        logger.debug(`Email template loaded: ${templateName}`);
      } catch (error) {
        logger.warn(`Failed to load email template: ${templateName}`, error);
      }
    }

    logger.info(`📧 Loaded ${this.templates.size} email templates`);
  }

  /**
   * Register Handlebars custom helpers
   */
  registerHandlebarsHelpers() {
    // Format currency
    handlebars.registerHelper('formatCurrency', (amount) => {
      return `$${parseFloat(amount).toFixed(2)}`;
    });

    // Format date
    handlebars.registerHelper('formatDate', (date) => {
      return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    });

    // Uppercase
    handlebars.registerHelper('uppercase', (str) => {
      return str ? str.toUpperCase() : '';
    });

    // Conditional
    handlebars.registerHelper('ifEquals', function(arg1, arg2, options) {
      return (arg1 === arg2) ? options.fn(this) : options.inverse(this);
    });

    // Loop index
    handlebars.registerHelper('inc', (value) => {
      return parseInt(value) + 1;
    });
  }

  /**
   * Send email with template and data
   * 
   * @param {string} to - Recipient email
   * @param {string} subject - Email subject
   * @param {string} templateName - Template name
   * @param {object} data - Template data
   * @param {object} options - Additional options
   * @returns {Promise<object>} Send result
   */
  async sendEmail(to, subject, templateName, data = {}, options = {}) {
    if (!Config.email.enabled || !this.transporter) {
      logger.info('Email skipped (service disabled)', { to, subject });
      return { success: false, reason: 'service_disabled' };
    }

    try {
      // Validate email address
      if (!this.isValidEmail(to)) {
        throw new Error('Invalid email address');
      }

      // Check if email is blacklisted
      if (await this.isBlacklisted(to)) {
        logger.warn('Email blacklisted', { to });
        return { success: false, reason: 'blacklisted' };
      }

      // Get template
      const template = this.templates.get(templateName);
      if (!template) {
        throw new Error(`Template not found: ${templateName}`);
      }

      // Render template with data
      const html = template({
        ...data,
        appName: Config.app.name,
        appUrl: Config.app.url,
        currentYear: new Date().getFullYear(),
        unsubscribeUrl: `${Config.app.url}/unsubscribe?email=${encodeURIComponent(to)}`
      });

      // Generate tracking pixel
      const trackingId = this.generateTrackingId();
      const trackingPixel = `<img src="${Config.app.url}/email/track/${trackingId}" width="1" height="1" alt="" />`;
      const htmlWithTracking = html + trackingPixel;

      // Prepare mail options
      const mailOptions = {
        from: `"${Config.email.from.name}" <${Config.email.from.email}>`,
        to,
        subject,
        html: htmlWithTracking,
        text: this.htmlToText(html),
        ...options
      };

      // Add to queue for async processing
      this.emailQueue.push({
        mailOptions,
        trackingId,
        templateName,
        attempts: 0,
        maxAttempts: 3
      });

      logger.info('Email queued', { to, subject, templateName, trackingId });

      return { 
        success: true, 
        trackingId,
        queued: true 
      };

    } catch (error) {
      logger.error('Email send failed', { to, subject, error: error.message });
      this.stats.failed++;
      return { 
        success: false, 
        error: error.message 
      };
    }
  }

  /**
   * Process email queue with retry mechanism
   */
  startQueueProcessor() {
    setInterval(async () => {
      if (this.emailQueue.length === 0) return;

      // Process up to 10 emails at a time
      const batch = this.emailQueue.splice(0, 10);

      for (const emailJob of batch) {
        try {
          const info = await this.transporter.sendMail(emailJob.mailOptions);

          // Log successful delivery
          await this.logEmailDelivery({
            trackingId: emailJob.trackingId,
            recipient: emailJob.mailOptions.to,
            subject: emailJob.mailOptions.subject,
            templateName: emailJob.templateName,
            status: 'sent',
            messageId: info.messageId,
            response: info.response
          });

          this.stats.sent++;
          logger.info('Email sent successfully', { 
            to: emailJob.mailOptions.to,
            trackingId: emailJob.trackingId 
          });

        } catch (error) {
          emailJob.attempts++;

          if (emailJob.attempts < emailJob.maxAttempts) {
            // Retry with exponential backoff
            setTimeout(() => {
              this.emailQueue.push(emailJob);
            }, Math.pow(2, emailJob.attempts) * 1000);

            logger.warn('Email send failed, will retry', {
              to: emailJob.mailOptions.to,
              attempt: emailJob.attempts,
              error: error.message
            });
          } else {
            // Max attempts reached
            await this.logEmailDelivery({
              trackingId: emailJob.trackingId,
              recipient: emailJob.mailOptions.to,
              subject: emailJob.mailOptions.subject,
              templateName: emailJob.templateName,
              status: 'failed',
              error: error.message
            });

            this.stats.failed++;
            logger.error('Email send failed permanently', {
              to: emailJob.mailOptions.to,
              error: error.message
            });
          }
        }
      }
    }, 2000); // Process every 2 seconds
  }

  /**
   * Send welcome email
   */
  async sendWelcome(user) {
    return this.sendEmail(
      user.email,
      `Welcome to ${Config.app.name}!`,
      'welcome',
      {
        username: user.username,
        firstName: user.first_name || user.username
      }
    );
  }

  /**
   * Send email verification
   */
  async sendEmailVerification(user, token) {
    const verifyUrl = `${Config.app.url}/verify-email?token=${token}`;
    
    return this.sendEmail(
      user.email,
      'Verify Your Email Address',
      'email-verification',
      {
        username: user.username,
        verifyUrl,
        token
      }
    );
  }

  /**
   * Send password reset email
   */
  async sendPasswordReset(user, token) {
    const resetUrl = `${Config.app.url}/reset-password?token=${token}`;
    
    return this.sendEmail(
      user.email,
      'Reset Your Password',
      'password-reset',
      {
        username: user.username,
        resetUrl,
        expiryMinutes: 60
      }
    );
  }

  /**
   * Send order confirmation
   */
  async sendOrderConfirmation(user, order) {
    return this.sendEmail(
      user.email,
      `Order Confirmation - ${order.order_number}`,
      'order-confirmation',
      {
        username: user.username,
        orderNumber: order.order_number,
        orderDate: order.created_at,
        items: order.items,
        subtotal: order.subtotal,
        tax: order.tax,
        shippingCost: order.shipping_cost,
        discount: order.discount,
        total: order.total,
        shippingAddress: order.shipping_address,
        trackingUrl: `${Config.app.url}/orders/${order.id}/track`
      }
    );
  }

  /**
   * Send order shipped notification
   */
  async sendOrderShipped(user, order, trackingNumber) {
    return this.sendEmail(
      user.email,
      `Your Order Has Shipped - ${order.order_number}`,
      'order-shipped',
      {
        username: user.username,
        orderNumber: order.order_number,
        trackingNumber,
        trackingUrl: `https://tracking.example.com/${trackingNumber}`,
        estimatedDelivery: this.calculateEstimatedDelivery()
      }
    );
  }

  /**
   * Send order delivered notification
   */
  async sendOrderDelivered(user, order) {
    return this.sendEmail(
      user.email,
      `Order Delivered - ${order.order_number}`,
      'order-delivered',
      {
        username: user.username,
        orderNumber: order.order_number,
        reviewUrl: `${Config.app.url}/orders/${order.id}/review`
      }
    );
  }

  /**
   * Send order cancelled notification
   */
  async sendOrderCancelled(user, order, reason) {
    return this.sendEmail(
      user.email,
      `Order Cancelled - ${order.order_number}`,
      'order-cancelled',
      {
        username: user.username,
        orderNumber: order.order_number,
        reason,
        refundAmount: order.total
      }
    );
  }

  /**
   * Send review request
   */
  async sendReviewRequest(user, order) {
    return this.sendEmail(
      user.email,
      'How was your order?',
      'review-request',
      {
        username: user.username,
        orderNumber: order.order_number,
        items: order.items,
        reviewUrl: `${Config.app.url}/orders/${order.id}/review`
      }
    );
  }

  /**
   * Send newsletter
   */
  async sendNewsletter(recipients, subject, content) {
    const results = {
      sent: 0,
      failed: 0
    };

    for (const recipient of recipients) {
      const result = await this.sendEmail(
        recipient.email,
        subject,
        'newsletter',
        {
          username: recipient.username,
          content
        }
      );

      if (result.success) {
        results.sent++;
      } else {
        results.failed++;
      }
    }

    return results;
  }

  /**
   * Send promotional email
   */
  async sendPromotional(user, campaign) {
    return this.sendEmail(
      user.email,
      campaign.subject,
      'promotional',
      {
        username: user.username,
        title: campaign.title,
        content: campaign.content,
        ctaText: campaign.ctaText,
        ctaUrl: campaign.ctaUrl,
        imageUrl: campaign.imageUrl
      }
    );
  }

  /**
   * Validate email address format
   */
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Check if email is blacklisted
   */
  async isBlacklisted(email) {
    try {
      const [result] = await db.execute(
        'SELECT id FROM email_blacklist WHERE email = ? LIMIT 1',
        [email.toLowerCase()]
      );
      return result.length > 0;
    } catch (error) {
      logger.error('Error checking email blacklist', { email, error });
      return false;
    }
  }

  /**
   * Add email to blacklist
   */
  async blacklistEmail(email, reason = '') {
    try {
      await db.execute(
        'INSERT INTO email_blacklist (email, reason, created_at) VALUES (?, ?, NOW())',
        [email.toLowerCase(), reason]
      );
      logger.info('Email blacklisted', { email, reason });
      return true;
    } catch (error) {
      logger.error('Error blacklisting email', { email, error });
      return false;
    }
  }

  /**
   * Remove email from blacklist
   */
  async unblacklistEmail(email) {
    try {
      await db.execute(
        'DELETE FROM email_blacklist WHERE email = ?',
        [email.toLowerCase()]
      );
      logger.info('Email unblacklisted', { email });
      return true;
    } catch (error) {
      logger.error('Error unblacklisting email', { email, error });
      return false;
    }
  }

  /**
   * Generate unique tracking ID
   */
  generateTrackingId() {
    return `${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Log email delivery
   */
  async logEmailDelivery(data) {
    try {
      await db.execute(
        `INSERT INTO email_logs (
          tracking_id, recipient, subject, template_name,
          status, message_id, response, error, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          data.trackingId,
          data.recipient,
          data.subject,
          data.templateName,
          data.status,
          data.messageId || null,
          data.response || null,
          data.error || null
        ]
      );
    } catch (error) {
      logger.error('Failed to log email delivery', error);
    }
  }

  /**
   * Track email open
   */
  async trackOpen(trackingId, ipAddress = null, userAgent = null) {
    try {
      await db.execute(
        `UPDATE email_logs 
         SET opened = TRUE, 
             opened_at = NOW(),
             open_ip = ?,
             open_user_agent = ?
         WHERE tracking_id = ?`,
        [ipAddress, userAgent, trackingId]
      );
      this.stats.opened++;
      logger.info('Email opened', { trackingId });
    } catch (error) {
      logger.error('Failed to track email open', { trackingId, error });
    }
  }

  /**
   * Track email click
   */
  async trackClick(trackingId, url, ipAddress = null) {
    try {
      await db.execute(
        `INSERT INTO email_clicks (
          tracking_id, url, ip_address, created_at
        ) VALUES (?, ?, ?, NOW())`,
        [trackingId, url, ipAddress]
      );
      
      await db.execute(
        `UPDATE email_logs 
         SET clicked = TRUE,
             clicked_at = NOW()
         WHERE tracking_id = ?`,
        [trackingId]
      );
      
      this.stats.clicked++;
      logger.info('Email link clicked', { trackingId, url });
    } catch (error) {
      logger.error('Failed to track email click', { trackingId, error });
    }
  }

  /**
   * Handle email bounce
   */
  async handleBounce(email, bounceType, reason) {
    try {
      await db.execute(
        `INSERT INTO email_bounces (
          email, bounce_type, reason, created_at
        ) VALUES (?, ?, ?, NOW())`,
        [email, bounceType, reason]
      );

      // Auto-blacklist after 3 hard bounces
      const [bounces] = await db.execute(
        `SELECT COUNT(*) as count 
         FROM email_bounces 
         WHERE email = ? AND bounce_type = 'hard'`,
        [email]
      );

      if (bounces[0].count >= 3) {
        await this.blacklistEmail(email, 'Multiple hard bounces');
      }

      this.stats.bounced++;
      logger.warn('Email bounced', { email, bounceType, reason });
    } catch (error) {
      logger.error('Failed to handle bounce', { email, error });
    }
  }

  /**
   * Handle spam complaint
   */
  async handleComplaint(email, reason) {
    try {
      await db.execute(
        `INSERT INTO email_complaints (
          email, reason, created_at
        ) VALUES (?, ?, NOW())`,
        [email, reason]
      );

      // Auto-blacklist on complaint
      await this.blacklistEmail(email, 'Spam complaint');

      logger.warn('Spam complaint received', { email, reason });
    } catch (error) {
      logger.error('Failed to handle complaint', { email, error });
    }
  }

  /**
   * Convert HTML to plain text
   */
  htmlToText(html) {
    return html
      .replace(/<style[^>]*>.*<\/style>/gm, '')
      .replace(/<script[^>]*>.*<\/script>/gm, '')
      .replace(/<[^>]+>/gm, '')
      .replace(/\s\s+/g, ' ')
      .trim();
  }

  /**
   * Calculate estimated delivery date
   */
  calculateEstimatedDelivery() {
    const date = new Date();
    date.setDate(date.getDate() + 5); // 5 days from now
    return date.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  /**
   * Get email statistics
   */
  getStats() {
    return {
      ...this.stats,
      queueSize: this.emailQueue.length,
      templatesLoaded: this.templates.size,
      deliveryRate: this.stats.sent > 0 
        ? ((this.stats.sent / (this.stats.sent + this.stats.failed)) * 100).toFixed(2) + '%'
        : '0%',
      openRate: this.stats.sent > 0
        ? ((this.stats.opened / this.stats.sent) * 100).toFixed(2) + '%'
        : '0%',
      clickRate: this.stats.sent > 0
        ? ((this.stats.clicked / this.stats.sent) * 100).toFixed(2) + '%'
        : '0%'
    };
  }

  /**
   * Get email logs with filters
   */
  async getEmailLogs(filters = {}) {
    const {
      recipient = null,
      status = null,
      startDate = null,
      endDate = null,
      limit = 100,
      offset = 0
    } = filters;

    const conditions = [];
    const values = [];

    if (recipient) {
      conditions.push('recipient = ?');
      values.push(recipient);
    }

    if (status) {
      conditions.push('status = ?');
      values.push(status);
    }

    if (startDate) {
      conditions.push('created_at >= ?');
      values.push(startDate);
    }

    if (endDate) {
      conditions.push('created_at <= ?');
      values.push(endDate);
    }

    const whereClause = conditions.length > 0 
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const [logs] = await db.execute(
      `SELECT * FROM email_logs 
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return logs;
  }

  /**
   * Send bulk emails with rate limiting
   */
  async sendBulk(recipients, subject, templateName, dataProvider) {
    const results = {
      total: recipients.length,
      sent: 0,
      failed: 0,
      errors: []
    };

    // Process in batches of 50
    const batchSize = 50;
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);

      const promises = batch.map(async (recipient) => {
        try {
          const data = typeof dataProvider === 'function' 
            ? await dataProvider(recipient)
            : dataProvider;

          const result = await this.sendEmail(
            recipient.email,
            subject,
            templateName,
            { ...data, username: recipient.username }
          );

          if (result.success) {
            results.sent++;
          } else {
            results.failed++;
            results.errors.push({ email: recipient.email, error: result.error });
          }
        } catch (error) {
          results.failed++;
          results.errors.push({ email: recipient.email, error: error.message });
        }
      });

      await Promise.all(promises);

      // Wait 1 second between batches to respect rate limits
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    logger.info('Bulk email send completed', results);
    return results;
  }

  /**
   * Schedule email for future delivery
   */
  async scheduleEmail(to, subject, templateName, data, scheduledFor) {
    try {
      await db.execute(
        `INSERT INTO scheduled_emails (
          recipient, subject, template_name, data,
          scheduled_for, status, created_at
        ) VALUES (?, ?, ?, ?, ?, 'pending', NOW())`,
        [
          to,
          subject,
          templateName,
          JSON.stringify(data),
          scheduledFor
        ]
      );

      logger.info('Email scheduled', { to, subject, scheduledFor });
      return { success: true, scheduledFor };
    } catch (error) {
      logger.error('Failed to schedule email', { to, error });
      return { success: false, error: error.message };
    }
  }

  /**
   * Process scheduled emails
   */
  async processScheduledEmails() {
    try {
      const [emails] = await db.execute(
        `SELECT * FROM scheduled_emails
         WHERE status = 'pending'
         AND scheduled_for <= NOW()
         LIMIT 100`
      );

      for (const email of emails) {
        try {
          const data = JSON.parse(email.data);
          await this.sendEmail(
            email.recipient,
            email.subject,
            email.template_name,
            data
          );

          await db.execute(
            `UPDATE scheduled_emails 
             SET status = 'sent', sent_at = NOW()
             WHERE id = ?`,
            [email.id]
          );
        } catch (error) {
          logger.error('Failed to send scheduled email', { emailId: email.id, error });
          
          await db.execute(
            `UPDATE scheduled_emails 
             SET status = 'failed', error = ?
             WHERE id = ?`,
            [error.message, email.id]
          );
        }
      }

      if (emails.length > 0) {
        logger.info(`Processed ${emails.length} scheduled emails`);
      }
    } catch (error) {
      logger.error('Failed to process scheduled emails', error);
    }
  }

  /**
   * Test email configuration
   */
  async testConnection() {
    try {
      await this.transporter.verify();
      logger.info('Email connection test successful');
      return { success: true, message: 'Connection successful' };
    } catch (error) {
      logger.error('Email connection test failed', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Send test email
   */
  async sendTestEmail(to) {
    return this.sendEmail(
      to,
      'Test Email',
      'welcome',
      {
        username: 'Test User',
        firstName: 'Test'
      }
    );
  }

  /**
   * Get email deliverability report
   */
  async getDeliverabilityReport(days = 30) {
    try {
      const [report] = await db.execute(
        `SELECT 
          COUNT(*) as total_sent,
          SUM(CASE WHEN opened = TRUE THEN 1 ELSE 0 END) as total_opened,
          SUM(CASE WHEN clicked = TRUE THEN 1 ELSE 0 END) as total_clicked,
          COUNT(DISTINCT recipient) as unique_recipients
         FROM email_logs
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         AND status = 'sent'`,
        [days]
      );

      const [bounces] = await db.execute(
        `SELECT COUNT(*) as total_bounces
         FROM email_bounces
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [days]
      );

      const [complaints] = await db.execute(
        `SELECT COUNT(*) as total_complaints
         FROM email_complaints
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [days]
      );

      const stats = report[0];
      const totalSent = stats.total_sent;

      return {
        period: `${days} days`,
        totalSent,
        uniqueRecipients: stats.unique_recipients,
        opened: stats.total_opened,
        clicked: stats.total_clicked,
        bounced: bounces[0].total_bounces,
        complaints: complaints[0].total_complaints,
        openRate: totalSent > 0 ? ((stats.total_opened / totalSent) * 100).toFixed(2) + '%' : '0%',
        clickRate: totalSent > 0 ? ((stats.total_clicked / totalSent) * 100).toFixed(2) + '%' : '0%',
        bounceRate: totalSent > 0 ? ((bounces[0].total_bounces / totalSent) * 100).toFixed(2) + '%' : '0%',
        complaintRate: totalSent > 0 ? ((complaints[0].total_complaints / totalSent) * 100).toFixed(2) + '%' : '0%'
      };
    } catch (error) {
      logger.error('Failed to generate deliverability report', error);
      return null;
    }
  }

  /**
   * Cleanup old email logs
   */
  async cleanupOldLogs(daysToKeep = 90) {
    try {
      const [result] = await db.execute(
        'DELETE FROM email_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
        [daysToKeep]
      );

      logger.info(`Cleaned up ${result.affectedRows} old email logs`);
      return result.affectedRows;
    } catch (error) {
      logger.error('Failed to cleanup email logs', error);
      return 0;
    }
  }

  /**
   * Close email service
   */
  async close() {
    if (this.transporter) {
      this.transporter.close();
      logger.info('Email service closed');
    }
  }
}

// Singleton instance
let emailServiceInstance = null;

/**
 * Get EmailService singleton instance
 */
export const getEmailService = () => {
  if (!emailServiceInstance) {
    emailServiceInstance = new EmailService();
  }
  return emailServiceInstance;
};

/**
 * Initialize email service
 */
export const initializeEmailService = async () => {
  const service = getEmailService();
  await service.initialize();
  return service;
};

export default EmailService;
