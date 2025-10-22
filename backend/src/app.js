#!/usr/bin/env node

/**
 * SQLi Demo Platform - Main Application
 * Version: 3.0.0
 * 
 * Enterprise-grade SQL Injection demonstration platform
 * for security education and training.
 * 
 * @author Your Name
 * @license MIT
 */

import 'dotenv/config';
import express from 'express';
import { Server } from './core/Server.js';
import { Database } from './core/Database.js';
import { Logger } from './core/Logger.js';
import { Config } from './config/environment.js';

const logger = Logger.getInstance();
const app = express();

/**
 * Bootstrap Application
 */
async function bootstrap() {
  try {
    logger.info('🚀 Starting SQLi Demo Platform...');
    logger.info(`📝 Environment: ${Config.app.env}`);
    logger.info(`🔧 Mode: ${Config.security.mode.toUpperCase()}`);
    
    // Initialize Database
    logger.info('💾 Connecting to database...');
    const database = Database.getInstance();
    await database.connect();
    await database.testConnection();
    logger.info('✅ Database connected successfully');
    
    // Initialize Server
    logger.info('🌐 Initializing HTTP server...');
    const server = new Server(app);
    await server.initialize();
    
    // Start Server
    const port = Config.app.port;
    const host = Config.app.host;
    
    app.listen(port, host, () => {
      logger.info('\n' + '='.repeat(70));
      logger.info(`  🎉 SQLi Demo Platform v${Config.app.version} Started Successfully!`);
      logger.info('='.repeat(70));
      logger.info(`  📡 Server URL:      ${Config.app.url}`);
      logger.info(`  🔐 Security Mode:   ${Config.security.mode === 'vulnerable' ? '⚠️  VULNERABLE' : '✅ SECURE'}`);
      logger.info(`  📚 API Docs:        ${Config.app.url}/api/docs`);
      logger.info(`  🏥 Health Check:    ${Config.app.url}/health`);
      logger.info(`  📊 Metrics:         ${Config.app.url}/metrics`);
      logger.info('='.repeat(70));
      
      if (Config.security.mode === 'vulnerable') {
        logger.warn('');
        logger.warn('⚠️  WARNING: Running in VULNERABLE mode!');
        logger.warn('⚠️  This application is intentionally insecure.');
        logger.warn('⚠️  For EDUCATIONAL purposes ONLY!');
        logger.warn('⚠️  DO NOT expose to the internet!');
        logger.warn('');
      }
      
      logger.info(`\n🎓 Available Vulnerabilities:`);
      logger.info(`  • SQL Injection (Classic, Union, Blind, Time-based)`);
      logger.info(`  • Cross-Site Scripting (Stored, Reflected, DOM)`);
      logger.info(`  • Command Injection`);
      logger.info(`  • SSRF (Server-Side Request Forgery)`);
      logger.info(`  • XXE (XML External Entity)`);
      logger.info(`  • IDOR (Insecure Direct Object Reference)`);
      logger.info(`  • Path Traversal`);
      logger.info(`  • Mass Assignment`);
      logger.info(`  • Race Conditions`);
      logger.info(`  • Session Fixation`);
      logger.info(`  • JWT Bypass`);
      logger.info(`  • CSRF (Cross-Site Request Forgery)`);
      logger.info(`  • And 20+ more...\n`);
      
      logger.info(`💡 Quick Start:`);
      logger.info(`  1. Visit: ${Config.app.url}`);
      logger.info(`  2. Login: admin / admin123`);
      logger.info(`  3. Toggle mode: POST /api/mode/toggle`);
      logger.info(`  4. View attacks: GET /api/attacks/logs\n`);
    });
    
    // Graceful Shutdown
    setupGracefulShutdown(database);
    
  } catch (error) {
    logger.error('❌ Failed to start application:', error);
    process.exit(1);
  }
}

/**
 * Setup Graceful Shutdown Handlers
 */
function setupGracefulShutdown(database) {
  const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
  
  signals.forEach(signal => {
    process.on(signal, async () => {
      logger.info(`\n📡 ${signal} signal received`);
      logger.info('🛑 Starting graceful shutdown...');
      
      try {
        // Close database connections
        logger.info('💾 Closing database connections...');
        await database.disconnect();
        logger.info('✅ Database connections closed');
        
        // Exit process
        logger.info('✅ Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        logger.error('❌ Error during shutdown:', error);
        process.exit(1);
      }
    });
  });
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    logger.error('💥 Uncaught Exception:', error);
    process.exit(1);
  });
  
  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('💥 Unhandled Promise Rejection at:', promise);
    logger.error('💥 Reason:', reason);
    process.exit(1);
  });
}

/**
 * Display Banner
 */
function displayBanner() {
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗ ██████╗ ██╗     ██╗    ██████╗ ███████╗███╗   ███╗   ║
║   ██╔════╝██╔═══██╗██║     ██║    ██╔══██╗██╔════╝████╗ ████║   ║
║   ███████╗██║   ██║██║     ██║    ██║  ██║█████╗  ██╔████╔██║   ║
║   ╚════██║██║▄▄ ██║██║     ██║    ██║  ██║██╔══╝  ██║╚██╔╝██║   ║
║   ███████║╚██████╔╝███████╗██║    ██████╔╝███████╗██║ ╚═╝ ██║   ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚═════╝ ╚══════╝╚═╝     ╚═╝   ║
║                                                                   ║
║            SQL Injection Demonstration Platform                  ║
║                    Version 3.0.0                                 ║
║                                                                   ║
║              ⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️                ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
  `);
}

// Display banner
displayBanner();

// Start application
bootstrap().catch(error => {
  logger.error('💥 Fatal Error:', error);
  process.exit(1);
});
