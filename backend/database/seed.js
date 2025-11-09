#!/usr/bin/env node

/**
 * ============================================================================
 * Master Database Seed Script
 * ============================================================================
 * Orchestrates all database seeding operations in correct order
 * 
 * @module database/seed
 * @version 1.0.0
 * @license MIT
 * 
 * Usage:
 *   node database/seed.js [options]
 * 
 * Options:
 *   --fresh    Drop and recreate all data
 *   --users    Seed only users
 *   --products Seed only products
 *   --orders   Seed only orders
 *   --all      Seed everything (default)
 *   --clean    Clean all seeded data
 *   --stats    Show database statistics
 * 
 * Examples:
 *   node database/seed.js --fresh
 *   node database/seed.js --users --products
 *   node database/seed.js --stats
 * ============================================================================
 */

import 'dotenv/config';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { Database } from '../src/core/Database.js';
import { Logger } from '../src/core/Logger.js';
import { Config } from '../src/config/environment.js';

// Import seed modules
import { seedUsers, cleanUsers, getUserStats } from './seeds/users.seed.js';
import { seedCategories } from './seeds/categories.seed.js';
import { seedProducts, getProductStats } from './seeds/products.seed.js';

const db = Database.getInstance();
const logger = Logger.getInstance();

// ============================================================================
// CLI CONFIGURATION
// ============================================================================

const program = new Command();

program
  .name('seed')
  .description('Database seeding utility for SQLi Demo Platform')
  .version('1.0.0')
  .option('--fresh', 'Drop existing data and reseed')
  .option('--users', 'Seed users only')
  .option('--categories', 'Seed categories only')
  .option('--products', 'Seed products only')
  .option('--orders', 'Seed orders only')
  .option('--all', 'Seed all data (default)', true)
  .option('--clean', 'Clean all seeded data')
  .option('--stats', 'Show database statistics')
  .option('--force', 'Force operation without confirmation')
  .parse(process.argv);

const options = program.opts();

// ============================================================================
// SEEDING ORCHESTRATION
// ============================================================================

/**
 * Main seed function
 */
async function seed() {
  try {
    console.log(chalk.cyan.bold('\n╔════════════════════════════════════════════════════════════╗'));
    console.log(chalk.cyan.bold('║     SQLi Demo Platform - Database Seeding Utility         ║'));
    console.log(chalk.cyan.bold('╚════════════════════════════════════════════════════════════╝\n'));

    // Connect to database
    const spinner = ora('Connecting to database...').start();
    await db.connect();
    await db.testConnection();
    spinner.succeed(chalk.green('Database connected'));

    console.log(chalk.gray(`Database: ${Config.database.name}`));
    console.log(chalk.gray(`Host: ${Config.database.host}:${Config.database.port}\n`));

    // Handle different operations
    if (options.stats) {
      await showStatistics();
      return;
    }

    if (options.clean) {
      await cleanDatabase();
      return;
    }

    // Determine what to seed
    const seedOperations = {
      users: options.users || options.all,
      categories: options.categories || options.all,
      products: options.products || options.all,
      orders: options.orders || options.all
    };

    // Confirmation for fresh seed
    if (options.fresh && !options.force) {
      console.log(chalk.yellow.bold('⚠️  WARNING: This will delete all existing data!'));
      console.log(chalk.yellow('This operation cannot be undone.\n'));
      
      const confirmFresh = await confirm('Are you sure you want to proceed?');
      if (!confirmFresh) {
        console.log(chalk.gray('Operation cancelled.\n'));
        return;
      }

      await cleanDatabase();
      console.log('');
    }

    // Start seeding process
    console.log(chalk.cyan.bold('🌱 Starting database seeding...\n'));

    const results = {
      users: null,
      categories: null,
      products: null,
      orders: null
    };

    const startTime = Date.now();

    // Seed in correct order (respecting dependencies)
    
    // 1. Users (no dependencies)
    if (seedOperations.users) {
      console.log(chalk.blue.bold('📋 Step 1/4: Seeding Users'));
      console.log(chalk.gray('─'.repeat(60)));
      results.users = await seedUsers();
      console.log('');
    }

    // 2. Categories (no dependencies)
    if (seedOperations.categories) {
      console.log(chalk.blue.bold('📋 Step 2/4: Seeding Categories'));
      console.log(chalk.gray('─'.repeat(60)));
      results.categories = await seedCategories();
      console.log('');
    }

    // 3. Products (depends on categories)
    if (seedOperations.products) {
      console.log(chalk.blue.bold('📋 Step 3/4: Seeding Products'));
      console.log(chalk.gray('─'.repeat(60)));
      results.products = await seedProducts();
      console.log('');
    }

    // 4. Orders (depends on users and products)
    if (seedOperations.orders) {
      console.log(chalk.blue.bold('📋 Step 4/4: Seeding Orders'));
      console.log(chalk.gray('─'.repeat(60)));
      // results.orders = await seedOrders();
      console.log(chalk.yellow('   ⚠️  Order seeding not yet implemented'));
      console.log('');
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    // Summary
    console.log(chalk.green.bold('✅ Database seeding completed!\n'));
    console.log(chalk.cyan.bold('📊 Seeding Summary:'));
    console.log(chalk.gray('─'.repeat(60)));

    const table = new Table({
      head: [chalk.cyan('Resource'), chalk.cyan('Status'), chalk.cyan('Count'), chalk.cyan('Details')],
      colWidths: [15, 12, 10, 25]
    });

    if (results.users) {
      table.push([
        'Users',
        results.users.skipped ? chalk.yellow('Skipped') : chalk.green('Created'),
        results.users.created || results.users.count,
        results.users.failed ? `${results.users.failed} failed` : '—'
      ]);
    }

    if (results.categories) {
      table.push([
        'Categories',
        results.categories.skipped ? chalk.yellow('Skipped') : chalk.green('Created'),
        results.categories.created || results.categories.count,
        '—'
      ]);
    }

    if (results.products) {
      table.push([
        'Products',
        results.products.skipped ? chalk.yellow('Skipped') : chalk.green('Created'),
        results.products.created || results.products.count,
        results.products.failed ? `${results.products.failed} failed` : '—'
      ]);
    }

    console.log(table.toString());
    console.log('');
    console.log(chalk.gray(`⏱️  Completed in ${duration}s\n`));

    // Show demo credentials
    if (results.users && results.users.users) {
      console.log(chalk.cyan.bold('🔑 Demo Credentials:'));
      console.log(chalk.gray('─'.repeat(60)));
      
      const credTable = new Table({
        head: [chalk.cyan('Username'), chalk.cyan('Password'), chalk.cyan('Role')],
        colWidths: [18, 20, 15]
      });

      results.users.users.slice(0, 5).forEach(user => {
        credTable.push([
          user.username,
          user.password,
          user.role
        ]);
      });

      console.log(credTable.toString());
      console.log('');
    }

    // Next steps
    console.log(chalk.cyan.bold('🚀 Next Steps:'));
    console.log(chalk.gray('─'.repeat(60)));
    console.log(chalk.white('  1. Start the application:'));
    console.log(chalk.gray('     npm start'));
    console.log(chalk.white('  2. Access the application:'));
    console.log(chalk.gray(`     ${Config.app.url}`));
    console.log(chalk.white('  3. View database stats:'));
    console.log(chalk.gray('     node database/seed.js --stats'));
    console.log('');

  } catch (error) {
    console.log('');
    console.log(chalk.red.bold('❌ Seeding failed!'));
    console.log(chalk.red(error.message));
    console.log('');
    
    if (Config.app.env === 'development') {
      console.log(chalk.gray('Stack trace:'));
      console.log(chalk.gray(error.stack));
    }
    
    throw error;
  }
}

/**
 * Clean database (delete all seeded data)
 */
async function cleanDatabase() {
  try {
    console.log(chalk.yellow.bold('🧹 Cleaning database...\n'));

    const spinner = ora('Disabling foreign key checks...').start();
    await db.execute('SET FOREIGN_KEY_CHECKS = 0');
    spinner.succeed();

    // Clean in reverse order of dependencies
    const tables = [
      'order_items',
      'orders',
      'coupon_usage',
      'coupons',
      'reviews',
      'wishlists',
      'cart_items',
      'products',
      'categories',
      'admin_notes',
      'notifications',
      'webhook_logs',
      'webhooks',
      'api_tokens',
      'files',
      'search_queries',
      'page_views',
      'event_tracking',
      'rate_limits',
      'ip_blacklist',
      'audit_logs',
      'security_events',
      'login_history',
      'attack_logs',
      'user_sessions',
      'users'
    ];

    for (const table of tables) {
      const cleanSpinner = ora(`Cleaning ${table}...`).start();
      try {
        const [result] = await db.execute(`DELETE FROM ${table} WHERE id > 0`);
        cleanSpinner.succeed(chalk.green(`Cleaned ${table} (${result.affectedRows} rows)`));
      } catch (error) {
        cleanSpinner.warn(chalk.yellow(`Skipped ${table} (${error.message})`));
      }
    }

    const reEnableSpinner = ora('Re-enabling foreign key checks...').start();
    await db.execute('SET FOREIGN_KEY_CHECKS = 1');
    reEnableSpinner.succeed();

    console.log('');
    console.log(chalk.green.bold('✅ Database cleaned successfully\n'));

  } catch (error) {
    console.log('');
    console.log(chalk.red.bold('❌ Database cleaning failed!'));
    console.log(chalk.red(error.message));
    throw error;
  }
}

/**
 * Show database statistics
 */
async function showStatistics() {
  try {
    console.log(chalk.cyan.bold('📊 Database Statistics\n'));

    const spinner = ora('Fetching statistics...').start();

    // Get stats from each module
    const [userStats, productStats] = await Promise.all([
      getUserStats(),
      getProductStats()
    ]);

    // Get additional counts
    const [orderCount] = await db.execute('SELECT COUNT(*) as count FROM orders');
    const [reviewCount] = await db.execute('SELECT COUNT(*) as count FROM reviews');
    const [categoryCount] = await db.execute('SELECT COUNT(*) as count FROM categories');

    spinner.succeed(chalk.green('Statistics fetched\n'));

    // User Statistics
    const userTable = new Table({
      head: [chalk.cyan.bold('Users'), chalk.cyan.bold('Count')],
      colWidths: [25, 15]
    });

    userTable.push(
      ['Total Users', userStats.total_users],
      ['Active Users', userStats.active_users],
      ['Verified Users', userStats.verified_users],
      ['Super Admins', userStats.super_admins],
      ['Admins', userStats.admins],
      ['Moderators', userStats.moderators],
      ['Customers', userStats.customers],
      ['Locked Accounts', userStats.locked_users]
    );

    console.log(chalk.cyan.bold('👥 User Statistics:'));
    console.log(userTable.toString());
    console.log('');

    // Product Statistics
    const productTable = new Table({
      head: [chalk.cyan.bold('Products'), chalk.cyan.bold('Count/Value')],
      colWidths: [25, 15]
    });

    productTable.push(
      ['Total Products', productStats.total_products],
      ['Active Products', productStats.active_products],
      ['Featured Products', productStats.featured_products],
      ['Bestsellers', productStats.bestsellers],
      ['New Arrivals', productStats.new_arrivals],
      ['Total Stock', productStats.total_stock],
      ['Out of Stock', productStats.out_of_stock],
      ['Average Price', `$${parseFloat(productStats.avg_price).toFixed(2)}`]
    );

    console.log(chalk.cyan.bold('📦 Product Statistics:'));
    console.log(productTable.toString());
    console.log('');

    // Other Statistics
    const otherTable = new Table({
      head: [chalk.cyan.bold('Resource'), chalk.cyan.bold('Count')],
      colWidths: [25, 15]
    });

    otherTable.push(
      ['Categories', categoryCount[0].count],
      ['Orders', orderCount[0].count],
      ['Reviews', reviewCount[0].count]
    );

    console.log(chalk.cyan.bold('📊 Other Statistics:'));
    console.log(otherTable.toString());
    console.log('');

    // Database Info
    const [dbSize] = await db.execute(`
      SELECT 
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb
      FROM information_schema.tables
      WHERE table_schema = ?
    `, [Config.database.name]);

    console.log(chalk.cyan.bold('💾 Database Information:'));
    console.log(chalk.gray('─'.repeat(60)));
    console.log(chalk.white(`  Database: ${Config.database.name}`));
    console.log(chalk.white(`  Size: ${dbSize[0].size_mb || 0} MB`));
    console.log(chalk.white(`  Host: ${Config.database.host}:${Config.database.port}`));
    console.log('');

  } catch (error) {
    console.log('');
    console.log(chalk.red.bold('❌ Failed to fetch statistics!'));
    console.log(chalk.red(error.message));
    throw error;
  }
}

/**
 * Confirmation prompt
 */
async function confirm(message) {
  const inquirer = (await import('inquirer')).default;
  const answers = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirmed',
      message,
      default: false
    }
  ]);
  return answers.confirmed;
}

/**
 * Main execution
 */
async function main() {
  try {
    await seed();
    await db.disconnect();
    process.exit(0);
  } catch (error) {
    logger.error('Seed process failed:', error);
    await db.disconnect();
    process.exit(1);
  }
}

// ============================================================================
// EXPORTS & EXECUTION
// ============================================================================

export { seed, cleanDatabase, showStatistics };

// Execute if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
