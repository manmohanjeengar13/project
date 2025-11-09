/**
 * ============================================================================
 * Users Seed Data
 * ============================================================================
 * Generates demo user accounts with various roles and permissions
 * 
 * @module seeds/users
 * @version 1.0.0
 * @license MIT
 * 
 * SECURITY WARNING: These are DEMO accounts with hardcoded passwords
 * FOR DEVELOPMENT AND TESTING ONLY - Never use in production!
 * ============================================================================
 */

import bcrypt from 'bcrypt';
import { Database } from '../../src/core/Database.js';
import { Logger } from '../../src/core/Logger.js';
import { Config } from '../../src/config/environment.js';

const db = Database.getInstance();
const logger = Logger.getInstance();

/**
 * Demo user accounts
 * Password format: <Role>@123456
 */
const DEMO_USERS = [
  {
    username: 'admin',
    email: 'admin@sqli-demo.local',
    password: 'Admin@123456',
    firstName: 'System',
    lastName: 'Administrator',
    role: 'super_admin',
    isActive: true,
    isEmailVerified: true,
    preferences: {
      theme: 'dark',
      language: 'en',
      notifications: {
        email: true,
        push: true,
        sms: false
      }
    },
    metadata: {
      department: 'Engineering',
      employeeId: 'EMP-001',
      clearanceLevel: 'top-secret'
    }
  },
  {
    username: 'moderator',
    email: 'moderator@sqli-demo.local',
    password: 'Moderator@123',
    firstName: 'John',
    lastName: 'Moderator',
    role: 'moderator',
    isActive: true,
    isEmailVerified: true,
    preferences: {
      theme: 'light',
      language: 'en'
    }
  },
  {
    username: 'john_doe',
    email: 'john.doe@example.com',
    password: 'User@123456',
    firstName: 'John',
    lastName: 'Doe',
    role: 'customer',
    isActive: true,
    isEmailVerified: true,
    phone: '+1-555-0101',
    dateOfBirth: '1990-05-15',
    gender: 'male',
    addressLine1: '123 Main Street',
    city: 'New York',
    state: 'NY',
    postalCode: '10001',
    country: 'US',
    timezone: 'America/New_York',
    locale: 'en_US',
    loyaltyPoints: 500,
    customerTier: 'gold'
  },
  {
    username: 'jane_smith',
    email: 'jane.smith@example.com',
    password: 'User@123456',
    firstName: 'Jane',
    lastName: 'Smith',
    role: 'customer',
    isActive: true,
    isEmailVerified: true,
    phone: '+1-555-0102',
    dateOfBirth: '1988-08-22',
    gender: 'female',
    addressLine1: '456 Oak Avenue',
    city: 'Los Angeles',
    state: 'CA',
    postalCode: '90001',
    country: 'US',
    timezone: 'America/Los_Angeles',
    locale: 'en_US',
    loyaltyPoints: 1000,
    customerTier: 'platinum'
  },
  {
    username: 'bob_johnson',
    email: 'bob.johnson@example.com',
    password: 'User@123456',
    firstName: 'Bob',
    lastName: 'Johnson',
    role: 'customer',
    isActive: true,
    isEmailVerified: true,
    phone: '+1-555-0103',
    addressLine1: '789 Pine Road',
    city: 'Chicago',
    state: 'IL',
    postalCode: '60601',
    country: 'US',
    loyaltyPoints: 250,
    customerTier: 'silver'
  },
  {
    username: 'alice_wilson',
    email: 'alice.wilson@example.com',
    password: 'User@123456',
    firstName: 'Alice',
    lastName: 'Wilson',
    role: 'customer',
    isActive: true,
    isEmailVerified: true,
    phone: '+1-555-0104',
    addressLine1: '321 Elm Street',
    city: 'Houston',
    state: 'TX',
    postalCode: '77001',
    country: 'US',
    loyaltyPoints: 750,
    customerTier: 'gold'
  },
  {
    username: 'charlie_brown',
    email: 'charlie.brown@example.com',
    password: 'User@123456',
    firstName: 'Charlie',
    lastName: 'Brown',
    role: 'customer',
    isActive: true,
    isEmailVerified: false, // Not verified
    phone: '+1-555-0105',
    addressLine1: '555 Maple Drive',
    city: 'Phoenix',
    state: 'AZ',
    postalCode: '85001',
    country: 'US',
    loyaltyPoints: 100,
    customerTier: 'bronze'
  },
  {
    username: 'testuser',
    email: 'test@sqli-demo.local',
    password: 'test123',
    firstName: 'Test',
    lastName: 'User',
    role: 'customer',
    isActive: true,
    isEmailVerified: true,
    metadata: {
      purpose: 'testing',
      canDelete: true
    }
  },
  {
    username: 'inactive_user',
    email: 'inactive@example.com',
    password: 'Inactive@123',
    firstName: 'Inactive',
    lastName: 'User',
    role: 'customer',
    isActive: false, // Inactive account
    isEmailVerified: false
  },
  {
    username: 'locked_user',
    email: 'locked@example.com',
    password: 'Locked@123',
    firstName: 'Locked',
    lastName: 'User',
    role: 'customer',
    isActive: true,
    isEmailVerified: true,
    failedLoginAttempts: 5,
    accountLockedUntil: new Date(Date.now() + 30 * 60 * 1000) // Locked for 30 mins
  }
];

/**
 * Hash password using bcrypt
 */
async function hashPassword(password) {
  const saltRounds = 10; // Use lower rounds for seeding speed
  return await bcrypt.hash(password, saltRounds);
}

/**
 * Generate referral code
 */
function generateReferralCode(userId) {
  return `REF${String(userId).padStart(6, '0')}`;
}

/**
 * Seed users table
 */
export async function seedUsers() {
  try {
    logger.info('🌱 Seeding users...');

    // Check if users already exist
    const [existingUsers] = await db.execute(
      'SELECT COUNT(*) as count FROM users'
    );

    if (existingUsers[0].count > 0) {
      logger.warn('⚠️  Users already exist. Skipping seed.');
      return {
        success: true,
        skipped: true,
        count: existingUsers[0].count
      };
    }

    const insertedUsers = [];
    let successCount = 0;
    let errorCount = 0;

    for (const user of DEMO_USERS) {
      try {
        // Hash password
        const hashedPassword = await hashPassword(user.password);
        
        // Prepare user data
        const userData = {
          username: user.username,
          email: user.email,
          password: hashedPassword,
          first_name: user.firstName || null,
          last_name: user.lastName || null,
          role: user.role,
          is_active: user.isActive !== undefined ? user.isActive : true,
          is_email_verified: user.isEmailVerified || false,
          phone: user.phone || null,
          date_of_birth: user.dateOfBirth || null,
          gender: user.gender || null,
          address_line1: user.addressLine1 || null,
          address_line2: user.addressLine2 || null,
          city: user.city || null,
          state: user.state || null,
          postal_code: user.postalCode || null,
          country: user.country || 'US',
          timezone: user.timezone || 'UTC',
          locale: user.locale || 'en_US',
          currency: user.currency || 'USD',
          preferences: user.preferences ? JSON.stringify(user.preferences) : null,
          loyalty_points: user.loyaltyPoints || 0,
          customer_tier: user.customerTier || 'bronze',
          failed_login_attempts: user.failedLoginAttempts || 0,
          account_locked_until: user.accountLockedUntil || null,
          metadata: user.metadata ? JSON.stringify(user.metadata) : null,
          member_since: new Date(),
          created_at: new Date()
        };

        // Insert user
        const [result] = await db.execute(
          `INSERT INTO users (
            username, email, password, first_name, last_name, role,
            is_active, is_email_verified, phone, date_of_birth, gender,
            address_line1, address_line2, city, state, postal_code, country,
            timezone, locale, currency, preferences, loyalty_points, customer_tier,
            failed_login_attempts, account_locked_until, metadata,
            member_since, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            userData.username, userData.email, userData.password,
            userData.first_name, userData.last_name, userData.role,
            userData.is_active, userData.is_email_verified,
            userData.phone, userData.date_of_birth, userData.gender,
            userData.address_line1, userData.address_line2,
            userData.city, userData.state, userData.postal_code, userData.country,
            userData.timezone, userData.locale, userData.currency,
            userData.preferences, userData.loyalty_points, userData.customer_tier,
            userData.failed_login_attempts, userData.account_locked_until,
            userData.metadata, userData.member_since, userData.created_at
          ]
        );

        const userId = result.insertId;

        // Generate and update referral code
        const referralCode = generateReferralCode(userId);
        await db.execute(
          'UPDATE users SET referral_code = ? WHERE id = ?',
          [referralCode, userId]
        );

        insertedUsers.push({
          id: userId,
          username: user.username,
          email: user.email,
          role: user.role,
          password: user.password // Store for logging (demo only!)
        });

        successCount++;
        logger.info(`   ✓ Created user: ${user.username} (${user.role})`);

      } catch (error) {
        errorCount++;
        logger.error(`   ✗ Failed to create user: ${user.username}`, {
          error: error.message
        });
      }
    }

    logger.info('');
    logger.info('👥 User Seed Summary:');
    logger.info(`   • Total users: ${DEMO_USERS.length}`);
    logger.info(`   • Created: ${successCount}`);
    logger.info(`   • Failed: ${errorCount}`);
    logger.info('');
    logger.info('🔑 Demo Credentials:');
    
    insertedUsers.forEach(user => {
      logger.info(`   • ${user.username.padEnd(15)} / ${user.password.padEnd(20)} (${user.role})`);
    });

    logger.info('');
    logger.info('✅ Users seeded successfully');

    return {
      success: true,
      total: DEMO_USERS.length,
      created: successCount,
      failed: errorCount,
      users: insertedUsers
    };

  } catch (error) {
    logger.error('❌ User seeding failed:', error);
    throw error;
  }
}

/**
 * Clean users (for testing)
 */
export async function cleanUsers() {
  try {
    logger.info('🧹 Cleaning users...');

    // Delete all users except system admin (id: 1)
    const [result] = await db.execute(
      'DELETE FROM users WHERE id > 1'
    );

    logger.info(`   ✓ Deleted ${result.affectedRows} users`);
    logger.info('✅ Users cleaned successfully');

    return {
      success: true,
      deleted: result.affectedRows
    };

  } catch (error) {
    logger.error('❌ User cleaning failed:', error);
    throw error;
  }
}

/**
 * Get user statistics
 */
export async function getUserStats() {
  try {
    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) as total_users,
        SUM(CASE WHEN role = 'super_admin' THEN 1 ELSE 0 END) as super_admins,
        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admins,
        SUM(CASE WHEN role = 'moderator' THEN 1 ELSE 0 END) as moderators,
        SUM(CASE WHEN role = 'customer' THEN 1 ELSE 0 END) as customers,
        SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
        SUM(CASE WHEN is_email_verified = TRUE THEN 1 ELSE 0 END) as verified_users,
        SUM(CASE WHEN account_locked_until IS NOT NULL AND account_locked_until > NOW() THEN 1 ELSE 0 END) as locked_users
      FROM users
    `);

    return stats[0];

  } catch (error) {
    logger.error('Failed to get user stats:', error);
    throw error;
  }
}

/**
 * Create additional test users
 */
export async function createTestUsers(count = 10) {
  try {
    logger.info(`🌱 Creating ${count} test users...`);

    const testUsers = [];
    const hashedPassword = await hashPassword('Test@123456');

    for (let i = 1; i <= count; i++) {
      const username = `testuser${i}`;
      const email = `test${i}@example.com`;

      try {
        const [result] = await db.execute(
          `INSERT INTO users (
            username, email, password, first_name, last_name, role,
            is_active, is_email_verified, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
          [username, email, hashedPassword, `Test${i}`, 'User', 'customer', true, true]
        );

        testUsers.push({
          id: result.insertId,
          username,
          email
        });

      } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          logger.warn(`   ⚠️  User ${username} already exists`);
        } else {
          throw error;
        }
      }
    }

    logger.info(`   ✓ Created ${testUsers.length} test users`);
    logger.info('✅ Test users created successfully');

    return {
      success: true,
      created: testUsers.length,
      users: testUsers
    };

  } catch (error) {
    logger.error('❌ Test user creation failed:', error);
    throw error;
  }
}

/**
 * Reset user passwords (for development)
 */
export async function resetUserPasswords() {
  try {
    logger.info('🔐 Resetting user passwords...');

    const defaultPassword = 'Reset@123456';
    const hashedPassword = await hashPassword(defaultPassword);

    const [result] = await db.execute(
      'UPDATE users SET password = ?, password_changed_at = NOW() WHERE role != "super_admin"',
      [hashedPassword]
    );

    logger.info(`   ✓ Reset ${result.affectedRows} user passwords`);
    logger.info(`   ℹ️  New password: ${defaultPassword}`);
    logger.info('✅ Passwords reset successfully');

    return {
      success: true,
      updated: result.affectedRows,
      password: defaultPassword
    };

  } catch (error) {
    logger.error('❌ Password reset failed:', error);
    throw error;
  }
}

// Export default seed function
export default seedUsers;

/**
 * CLI execution
 */
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    try {
      await seedUsers();
      process.exit(0);
    } catch (error) {
      console.error('Seed failed:', error);
      process.exit(1);
    }
  })();
}
