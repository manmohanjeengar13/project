/**
 * Email Core Module
 * Handles email sending with template support
 */

import nodemailer from 'nodemailer';
import handlebars from 'handlebars';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Config } from '../config/environment.js';
import { Logger } from './Logger.js';
import { EMAIL_TEMPLATES } from '../config/constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const logger = Logger.getInstance();

export class Email {
  static instance = null;
  transporter = null;
  templates = new Map();

  constructor() {
    if (Email.instance) {
      return Email.instance;
    }
    Email.instance = this;
  }

  /**
   * Get Email singleton instance
   */
  static getInstance() {
    if (!Email.instance) {
      Email.instance = new Email();
    }
    return Email.instance;
  }

  /**
   * Initialize email transporter
   */
  async initialize() {
    if (!Config.email.enabled) {
      logger.warn('⚠️  Email service disabled');
      return;
    }

    try {
      this.transporter = nodemailer.createTransporter({
        host: Config.email.host,
        port: Config.email.port,
        secure: Config.email.secure,
        auth: {
          user: Config.email.user,
          pass: Config.email.password
        }
      });

      // Verify connection
      await this.transporter.verify();
      logger.info('✅ Email service initialized');
      
      // Load templates
      await this.loadTemplates();
    } catch (error) {
      logger.error('❌ Email initialization failed:', error);
      throw error;
    }
  }

  /**
   * Load email templates
   */
  async loadTemplates() {
    const templatePath = join(__dirname, '../templates/email');
    
    Object.values(EMAIL_TEMPLATES).forEach(template => {
      try {
        const htmlPath = join(templatePath, `${template}.html`);
        const html = readFileSync(htmlPath, 'utf-8');
        this.templates.set(template, handlebars.compile(html));
        logger.debug(`✓ Template loaded: ${template}`);
      } catch (error) {
        logger.warn(`⚠️  Template not found: ${template}`);
      }
    });
  }

  /**
   * Send email
   */
  async send(options) {
    if (!Config.email.enabled) {
      logger.debug('Email not sent (service disabled)');
      return { success: false, reason: 'service_disabled' };
    }

    try {
      const {
        to,
        subject,
        text,
        html,
        template,
        data = {},
        attachments = []
      } = options;

      let finalHtml = html;

      // Use template if provided
      if (template && this.templates.has(template)) {
        const templateFunc = this.templates.get(template);
        finalHtml = templateFunc(data);
      }

      const mailOptions = {
        from: `${Config.email.from.name} <${Config.email.from.email}>`,
        to,
        subject,
        text,
        html: finalHtml,
        attachments
      };

      const info = await this.transporter.sendMail(mailOptions);
      
      logger.info(`📧 Email sent: ${subject} → ${to}`);
      
      return {
        success: true,
        messageId: info.messageId,
        response: info.response
      };
    } catch (error) {
      logger.error('Email send error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send welcome email
   */
  async sendWelcome(user) {
    return this.send({
      to: user.email,
      subject: `Welcome to ${Config.app.name}!`,
      template: EMAIL_TEMPLATES.WELCOME,
      data: {
        username: user.username,
        appName: Config.app.name,
        appUrl: Config.app.url
      }
    });
  }

  /**
   * Send email verification
   */
  async sendEmailVerification(user, token) {
    const verificationUrl = `${Config.app.url}/verify-email?token=${token}`;
    
    return this.send({
      to: user.email,
      subject: 'Verify Your Email Address',
      template: EMAIL_TEMPLATES.EMAIL_VERIFICATION,
      data: {
        username: user.username,
        verificationUrl,
        appName: Config.app.name
      }
    });
  }

  /**
   * Send password reset email
   */
  async sendPasswordReset(user, token) {
    const resetUrl = `${Config.app.url}/reset-password?token=${token}`;
    
    return this.send({
      to: user.email,
      subject: 'Password Reset Request',
      template: EMAIL_TEMPLATES.PASSWORD_RESET,
      data: {
        username: user.username,
        resetUrl,
        appName: Config.app.name,
        expiresIn: '1 hour'
      }
    });
  }

  /**
   * Send order confirmation email
   */
  async sendOrderConfirmation(user, order) {
    return this.send({
      to: user.email,
      subject: `Order Confirmation #${order.order_number}`,
      template: EMAIL_TEMPLATES.ORDER_CONFIRMATION,
      data: {
        username: user.username,
        orderNumber: order.order_number,
        orderTotal: order.total,
        orderDate: order.created_at,
        orderUrl: `${Config.app.url}/orders/${order.id}`,
        appName: Config.app.name
      }
    });
  }

  /**
   * Send order shipped notification
   */
  async sendOrderShipped(user, order, trackingNumber) {
    return this.send({
      to: user.email,
      subject: `Order #${order.order_number} Shipped`,
      template: EMAIL_TEMPLATES.ORDER_SHIPPED,
      data: {
        username: user.username,
        orderNumber: order.order_number,
        trackingNumber,
        trackingUrl: `https://tracking.example.com/${trackingNumber}`,
        appName: Config.app.name
      }
    });
  }

  /**
   * Send security alert
   */
  async sendSecurityAlert(user, alertType, details) {
    return this.send({
      to: user.email,
      subject: `Security Alert: ${alertType}`,
      template: EMAIL_TEMPLATES.SECURITY_ALERT,
      data: {
        username: user.username,
        alertType,
        details,
        ipAddress: details.ip,
        location: details.location,
        timestamp: new Date().toISOString(),
        appName: Config.app.name
      }
    });
  }

  /**
   * Send account locked notification
   */
  async sendAccountLocked(user, reason) {
    return this.send({
      to: user.email,
      subject: 'Account Locked',
      template: EMAIL_TEMPLATES.ACCOUNT_LOCKED,
      data: {
        username: user.username,
        reason,
        unlockUrl: `${Config.app.url}/unlock-account`,
        appName: Config.app.name
      }
    });
  }

  /**
   * Send bulk emails
   */
  async sendBulk(emails) {
    const results = [];
    
    for (const emailOptions of emails) {
      const result = await this.send(emailOptions);
      results.push(result);
      
      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    return results;
  }

  /**
   * Queue email for later sending
   */
  async queue(options) {
    // This would integrate with Queue.js for async email sending
    logger.info('Email queued:', options.subject);
    return { queued: true, options };
  }

  /**
   * Test email configuration
   */
  async test(recipientEmail) {
    return this.send({
      to: recipientEmail,
      subject: 'Test Email',
      text: 'This is a test email from SQLi Demo Platform',
      html: '<p>This is a <strong>test email</strong> from SQLi Demo Platform</p>'
    });
  }

  /**
   * Get email statistics
   */
  getStats() {
    return {
      enabled: Config.email.enabled,
      host: Config.email.host,
      templatesLoaded: this.templates.size,
      from: Config.email.from.email
    };
  }
}

export default Email;
