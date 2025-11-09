/**
 * ============================================================================
 * Categories Seed Data
 * ============================================================================
 * Generates hierarchical product category structure
 * 
 * @module seeds/categories
 * @version 1.0.0
 * @license MIT
 * ============================================================================
 */

import { Database } from '../../src/core/Database.js';
import { Logger } from '../../src/core/Logger.js';

const db = Database.getInstance();
const logger = Logger.getInstance();

/**
 * Hierarchical category structure
 */
const CATEGORIES = [
  {
    name: 'Electronics',
    slug: 'electronics',
    description: 'Electronic devices, computers, and accessories',
    icon: 'laptop',
    isFeatured: true,
    sortOrder: 1,
    children: [
      {
        name: 'Computers',
        slug: 'computers',
        description: 'Desktop computers, laptops, and accessories',
        sortOrder: 1
      },
      {
        name: 'Smartphones',
        slug: 'smartphones',
        description: 'Mobile phones and smartphone accessories',
        sortOrder: 2
      },
      {
        name: 'Audio',
        slug: 'audio',
        description: 'Headphones, speakers, and audio equipment',
        sortOrder: 3
      },
      {
        name: 'Cameras',
        slug: 'cameras',
        description: 'Digital cameras and photography equipment',
        sortOrder: 4
      },
      {
        name: 'Gaming',
        slug: 'gaming',
        description: 'Gaming consoles, accessories, and peripherals',
        sortOrder: 5
      },
      {
        name: 'Smart Home',
        slug: 'smart-home',
        description: 'Smart home devices and IoT products',
        sortOrder: 6
      }
    ]
  },
  {
    name: 'Clothing',
    slug: 'clothing',
    description: 'Fashion, apparel, and accessories for all',
    icon: 'shirt',
    isFeatured: true,
    sortOrder: 2,
    children: [
      {
        name: "Men's Clothing",
        slug: 'mens-clothing',
        description: 'Fashion and apparel for men',
        sortOrder: 1
      },
      {
        name: "Women's Clothing",
        slug: 'womens-clothing',
        description: 'Fashion and apparel for women',
        sortOrder: 2
      },
      {
        name: "Kids' Clothing",
        slug: 'kids-clothing',
        description: 'Clothing for children and toddlers',
        sortOrder: 3
      },
      {
        name: 'Accessories',
        slug: 'accessories',
        description: 'Fashion accessories, jewelry, and more',
        sortOrder: 4
      },
      {
        name: 'Shoes',
        slug: 'shoes',
        description: 'Footwear for all occasions',
        sortOrder: 5
      }
    ]
  },
  {
    name: 'Home & Garden',
    slug: 'home-garden',
    description: 'Home improvement, furniture, and gardening',
    icon: 'home',
    isFeatured: false,
    sortOrder: 3,
    children: [
      {
        name: 'Furniture',
        slug: 'furniture',
        description: 'Indoor and outdoor furniture',
        sortOrder: 1
      },
      {
        name: 'Kitchen & Dining',
        slug: 'kitchen-dining',
        description: 'Kitchenware and dining essentials',
        sortOrder: 2
      },
      {
        name: 'Bedding & Bath',
        slug: 'bedding-bath',
        description: 'Bedding, towels, and bathroom accessories',
        sortOrder: 3
      },
      {
        name: 'Garden & Outdoor',
        slug: 'garden-outdoor',
        description: 'Gardening tools and outdoor equipment',
        sortOrder: 4
      },
      {
        name: 'Home Decor',
        slug: 'home-decor',
        description: 'Decorative items and home accessories',
        sortOrder: 5
      }
    ]
  },
  {
    name: 'Sports & Outdoors',
    slug: 'sports-outdoors',
    description: 'Sports equipment, fitness gear, and outdoor activities',
    icon: 'dumbbell',
    isFeatured: false,
    sortOrder: 4,
    children: [
      {
        name: 'Fitness Equipment',
        slug: 'fitness-equipment',
        description: 'Gym equipment and fitness accessories',
        sortOrder: 1
      },
      {
        name: 'Outdoor Recreation',
        slug: 'outdoor-recreation',
        description: 'Camping, hiking, and outdoor gear',
        sortOrder: 2
      },
      {
        name: 'Sports',
        slug: 'sports',
        description: 'Equipment for various sports',
        sortOrder: 3
      },
      {
        name: 'Activewear',
        slug: 'activewear',
        description: 'Athletic clothing and footwear',
        sortOrder: 4
      }
    ]
  },
  {
    name: 'Books',
    slug: 'books',
    description: 'Books, magazines, and educational materials',
    icon: 'book',
    isFeatured: false,
    sortOrder: 5,
    children: [
      {
        name: 'Fiction',
        slug: 'fiction',
        description: 'Novels and fiction literature',
        sortOrder: 1
      },
      {
        name: 'Non-Fiction',
        slug: 'non-fiction',
        description: 'Biographies, history, and more',
        sortOrder: 2
      },
      {
        name: 'Children\'s Books',
        slug: 'childrens-books',
        description: 'Books for kids and young readers',
        sortOrder: 3
      },
      {
        name: 'Educational',
        slug: 'educational',
        description: 'Textbooks and educational materials',
        sortOrder: 4
      }
    ]
  },
  {
    name: 'Toys & Games',
    slug: 'toys-games',
    description: 'Toys, games, and hobby items',
    icon: 'gamepad',
    isFeatured: false,
    sortOrder: 6,
    children: [
      {
        name: 'Action Figures',
        slug: 'action-figures',
        description: 'Collectible action figures and toys',
        sortOrder: 1
      },
      {
        name: 'Board Games',
        slug: 'board-games',
        description: 'Family board games and puzzles',
        sortOrder: 2
      },
      {
        name: 'Educational Toys',
        slug: 'educational-toys',
        description: 'Learning and development toys',
        sortOrder: 3
      },
      {
        name: 'Outdoor Toys',
        slug: 'outdoor-toys',
        description: 'Outdoor play equipment',
        sortOrder: 4
      }
    ]
  },
  {
    name: 'Health & Beauty',
    slug: 'health-beauty',
    description: 'Personal care, cosmetics, and health products',
    icon: 'heart',
    isFeatured: false,
    sortOrder: 7,
    children: [
      {
        name: 'Skincare',
        slug: 'skincare',
        description: 'Skincare products and treatments',
        sortOrder: 1
      },
      {
        name: 'Makeup',
        slug: 'makeup',
        description: 'Cosmetics and beauty products',
        sortOrder: 2
      },
      {
        name: 'Hair Care',
        slug: 'hair-care',
        description: 'Hair products and styling tools',
        sortOrder: 3
      },
      {
        name: 'Vitamins & Supplements',
        slug: 'vitamins-supplements',
        description: 'Health supplements and vitamins',
        sortOrder: 4
      }
    ]
  },
  {
    name: 'Automotive',
    slug: 'automotive',
    description: 'Car parts, accessories, and tools',
    icon: 'car',
    isFeatured: false,
    sortOrder: 8,
    children: [
      {
        name: 'Car Electronics',
        slug: 'car-electronics',
        description: 'GPS, dash cams, and audio systems',
        sortOrder: 1
      },
      {
        name: 'Car Care',
        slug: 'car-care',
        description: 'Cleaning and maintenance products',
        sortOrder: 2
      },
      {
        name: 'Parts & Accessories',
        slug: 'parts-accessories',
        description: 'Replacement parts and accessories',
        sortOrder: 3
      }
    ]
  }
];

/**
 * Seed categories recursively
 */
async function insertCategory(category, parentId = null, level = 0) {
  try {
    const path = parentId ? `${parentId}/` : '/';

    const [result] = await db.execute(
      `INSERT INTO categories (
        parent_id, name, slug, description, icon,
        sort_order, level, path, is_active, is_featured, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        parentId,
        category.name,
        category.slug,
        category.description || null,
        category.icon || null,
        category.sortOrder || 0,
        level,
        path,
        true,
        category.isFeatured || false
      ]
    );

    const categoryId = result.insertId;
    
    logger.info(`   ${'  '.repeat(level)}✓ ${category.name} (${category.slug})`);

    // Insert children recursively
    if (category.children && category.children.length > 0) {
      for (const child of category.children) {
        await insertCategory(child, categoryId, level + 1);
      }
    }

    return categoryId;

  } catch (error) {
    logger.error(`   ${'  '.repeat(level)}✗ Failed to create: ${category.name}`, {
      error: error.message
    });
    throw error;
  }
}

/**
 * Seed categories
 */
export async function seedCategories() {
  try {
    logger.info('🌱 Seeding categories...');

    // Check if categories already exist
    const [existing] = await db.execute(
      'SELECT COUNT(*) as count FROM categories'
    );

    if (existing[0].count > 0) {
      logger.warn('⚠️  Categories already exist. Skipping seed.');
      return {
        success: true,
        skipped: true,
        count: existing[0].count
      };
    }

    let totalCategories = 0;
    let successCount = 0;

    // Count total categories
    function countCategories(categories) {
      let count = categories.length;
      categories.forEach(cat => {
        if (cat.children) {
          count += countCategories(cat.children);
        }
      });
      return count;
    }

    totalCategories = countCategories(CATEGORIES);

    // Insert all categories
    for (const category of CATEGORIES) {
      await insertCategory(category);
      successCount += 1 + (category.children?.length || 0);
    }

    logger.info('');
    logger.info('📁 Category Seed Summary:');
    logger.info(`   • Total categories: ${totalCategories}`);
    logger.info(`   • Created: ${successCount}`);
    logger.info('✅ Categories seeded successfully');

    return {
      success: true,
      total: totalCategories,
      created: successCount
    };

  } catch (error) {
    logger.error('❌ Category seeding failed:', error);
    throw error;
  }
}

/**
 * Get category statistics
 */
export async function getCategoryStats() {
  try {
    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) as total_categories,
        SUM(CASE WHEN level = 0 THEN 1 ELSE 0 END) as main_categories,
        SUM(CASE WHEN level > 0 THEN 1 ELSE 0 END) as subcategories,
        SUM(CASE WHEN is_featured = TRUE THEN 1 ELSE 0 END) as featured_categories,
        SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_categories,
        MAX(level) as max_depth
      FROM categories
    `);

    return stats[0];

  } catch (error) {
    logger.error('Failed to get category stats:', error);
    throw error;
  }
}

/**
 * Update category product counts
 */
export async function updateCategoryCounts() {
  try {
    logger.info('🔄 Updating category product counts...');

    await db.execute(`
      UPDATE categories c
      SET product_count = (
        SELECT COUNT(*)
        FROM products p
        WHERE p.category_id = c.id
          AND p.deleted_at IS NULL
          AND p.status = 'active'
      )
    `);

    logger.info('   ✓ Category counts updated');
    logger.info('✅ Update completed successfully');

    return { success: true };

  } catch (error) {
    logger.error('❌ Category count update failed:', error);
    throw error;
  }
}

export default seedCategories;

/**
 * CLI execution
 */
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    try {
      await seedCategories();
      process.exit(0);
    } catch (error) {
      console.error('Seed failed:', error);
      process.exit(1);
    }
  })();
}
