/**
 * ============================================================================
 * Products Seed Data
 * ============================================================================
 * Generates demo product catalog with categories, variants, and inventory
 * 
 * @module seeds/products
 * @version 1.0.0
 * @license MIT
 * ============================================================================
 */

import { Database } from '../../src/core/Database.js';
import { Logger } from '../../src/core/Logger.js';
import { nanoid } from 'nanoid';

const db = Database.getInstance();
const logger = Logger.getInstance();

/**
 * Product catalog organized by category
 */
const PRODUCT_CATALOG = {
  electronics: {
    computers: [
      {
        name: 'Professional Laptop 15"',
        sku: 'LAPTOP-001',
        description: 'High-performance laptop with 16GB RAM, 512GB SSD, and Intel Core i7 processor. Perfect for professional work, content creation, and gaming. Features a stunning 15.6" 4K display with 100% sRGB color accuracy.',
        shortDescription: 'Powerful laptop for professionals and creators',
        basePrice: 1299.99,
        salePrice: 1199.99,
        costPrice: 950.00,
        stock: 50,
        weight: 2.1,
        specifications: {
          processor: 'Intel Core i7-11800H',
          ram: '16GB DDR4',
          storage: '512GB NVMe SSD',
          display: '15.6" 4K UHD',
          graphics: 'NVIDIA GTX 1650',
          battery: '6-cell, 86Wh',
          os: 'Windows 11 Pro'
        },
        tags: ['laptop', 'professional', 'gaming', 'high-performance']
      },
      {
        name: 'Ultrabook Pro 13"',
        sku: 'LAPTOP-002',
        description: 'Ultra-portable business laptop with 8GB RAM, 256GB SSD, and 10th Gen Intel Core i5. Weighs only 2.5 lbs with 12-hour battery life.',
        shortDescription: 'Lightweight laptop for business professionals',
        basePrice: 899.99,
        salePrice: null,
        costPrice: 700.00,
        stock: 75,
        weight: 1.13,
        specifications: {
          processor: 'Intel Core i5-10210U',
          ram: '8GB LPDDR3',
          storage: '256GB SSD',
          display: '13.3" Full HD',
          battery: '4-cell, 56Wh',
          os: 'Windows 11 Home'
        },
        tags: ['laptop', 'ultrabook', 'portable', 'business']
      },
      {
        name: 'Gaming Desktop RTX 3080',
        sku: 'DESKTOP-001',
        description: 'Ultimate gaming desktop with NVIDIA RTX 3080, AMD Ryzen 9, 32GB RAM, and 1TB NVMe SSD. RGB lighting and liquid cooling included.',
        shortDescription: 'High-end gaming powerhouse',
        basePrice: 2499.99,
        salePrice: 2299.99,
        costPrice: 1900.00,
        stock: 25,
        weight: 15.0,
        isFeatured: true,
        specifications: {
          processor: 'AMD Ryzen 9 5900X',
          ram: '32GB DDR4 3600MHz',
          storage: '1TB NVMe SSD + 2TB HDD',
          graphics: 'NVIDIA RTX 3080 10GB',
          cooling: 'Liquid CPU Cooler',
          psu: '850W 80+ Gold',
          case: 'RGB Tempered Glass'
        },
        tags: ['desktop', 'gaming', 'rgb', 'high-end']
      }
    ],
    smartphones: [
      {
        name: 'Smartphone Pro Max',
        sku: 'PHONE-001',
        description: 'Latest flagship smartphone with 6.7" OLED display, 5G connectivity, triple camera system (108MP + 12MP + 12MP), and 256GB storage. Features advanced night mode and 8K video recording.',
        shortDescription: 'Premium smartphone experience',
        basePrice: 999.99,
        salePrice: null,
        costPrice: 750.00,
        stock: 100,
        weight: 0.228,
        isFeatured: true,
        isBestseller: true,
        specifications: {
          display: '6.7" AMOLED 120Hz',
          processor: 'Snapdragon 8 Gen 2',
          ram: '12GB',
          storage: '256GB',
          camera: '108MP + 12MP + 12MP',
          battery: '5000mAh',
          charging: '65W Fast Charging',
          os: 'Android 14'
        },
        tags: ['smartphone', 'flagship', '5g', 'camera']
      },
      {
        name: 'Budget Smartphone Plus',
        sku: 'PHONE-002',
        description: 'Affordable smartphone with essential features, 6.5" HD+ display, 48MP camera, and 5000mAh battery. Perfect for everyday use.',
        shortDescription: 'Great value smartphone',
        basePrice: 299.99,
        salePrice: null,
        costPrice: 200.00,
        stock: 200,
        weight: 0.195,
        specifications: {
          display: '6.5" IPS LCD',
          processor: 'MediaTek Helio G85',
          ram: '4GB',
          storage: '64GB',
          camera: '48MP + 8MP',
          battery: '5000mAh',
          os: 'Android 13'
        },
        tags: ['smartphone', 'budget', 'value']
      }
    ],
    audio: [
      {
        name: 'Wireless Noise-Cancelling Headphones',
        sku: 'HEADPHONE-001',
        description: 'Premium over-ear headphones with active noise cancellation, 30-hour battery life, and Hi-Res Audio support. Includes adaptive EQ and multipoint connectivity.',
        shortDescription: 'Superior audio quality and comfort',
        basePrice: 349.99,
        salePrice: 299.99,
        costPrice: 220.00,
        stock: 75,
        weight: 0.254,
        isFeatured: true,
        specifications: {
          type: 'Over-ear, Wireless',
          driver: '40mm Dynamic',
          frequency: '4Hz - 40kHz',
          battery: '30 hours (ANC on)',
          bluetooth: '5.2',
          anc: 'Adaptive ANC',
          codecs: 'LDAC, AAC, SBC'
        },
        tags: ['headphones', 'wireless', 'anc', 'premium']
      },
      {
        name: 'Portable Bluetooth Speaker',
        sku: 'SPEAKER-001',
        description: 'Waterproof wireless speaker with 360-degree sound, 12-hour battery, and built-in power bank. Perfect for outdoor adventures.',
        shortDescription: 'Music on the go',
        basePrice: 79.99,
        salePrice: 69.99,
        costPrice: 45.00,
        stock: 150,
        weight: 0.540,
        specifications: {
          output: '20W Stereo',
          battery: '12 hours',
          bluetooth: '5.0',
          waterproof: 'IPX7',
          range: '30 meters',
          features: 'Power Bank, TWS Pairing'
        },
        tags: ['speaker', 'bluetooth', 'waterproof', 'portable']
      },
      {
        name: 'True Wireless Earbuds Pro',
        sku: 'EARBUDS-001',
        description: 'Premium TWS earbuds with ANC, transparency mode, and spatial audio. Up to 6 hours of listening time (24 hours with case).',
        shortDescription: 'Premium wireless freedom',
        basePrice: 199.99,
        salePrice: null,
        costPrice: 130.00,
        stock: 120,
        weight: 0.056,
        isNewArrival: true,
        specifications: {
          driver: '11mm Dynamic',
          anc: 'Hybrid ANC',
          battery: '6h + 18h (case)',
          waterproof: 'IPX4',
          bluetooth: '5.3',
          features: 'Spatial Audio, Wireless Charging'
        },
        tags: ['earbuds', 'tws', 'anc', 'wireless']
      }
    ]
  },
  clothing: {
    mens: [
      {
        name: 'Classic Cotton T-Shirt',
        sku: 'SHIRT-001',
        description: 'Comfortable 100% cotton t-shirt available in multiple colors. Pre-shrunk and machine washable. Perfect for everyday wear.',
        shortDescription: 'Everyday comfort',
        basePrice: 19.99,
        salePrice: null,
        costPrice: 8.00,
        stock: 500,
        weight: 0.17,
        attributes: {
          sizes: ['XS', 'S', 'M', 'L', 'XL', 'XXL'],
          colors: ['White', 'Black', 'Navy', 'Gray', 'Red']
        },
        tags: ['tshirt', 'cotton', 'casual', 'basics']
      },
      {
        name: 'Classic Denim Jeans',
        sku: 'JEANS-001',
        description: 'Comfortable slim-fit jeans made from premium denim. Five-pocket design with button fly. Available in multiple washes.',
        shortDescription: 'Timeless denim style',
        basePrice: 59.99,
        salePrice: null,
        costPrice: 28.00,
        stock: 250,
        weight: 0.68,
        attributes: {
          sizes: ['28', '30', '32', '34', '36', '38', '40'],
          colors: ['Dark Blue', 'Light Blue', 'Black', 'Gray']
        },
        tags: ['jeans', 'denim', 'pants', 'casual']
      },
      {
        name: 'Formal Business Shirt',
        sku: 'SHIRT-002',
        description: 'Premium cotton dress shirt for professional settings. Non-iron fabric, regular fit, button-down collar.',
        shortDescription: 'Professional elegance',
        basePrice: 49.99,
        salePrice: 39.99,
        costPrice: 22.00,
        stock: 180,
        weight: 0.23,
        attributes: {
          sizes: ['S', 'M', 'L', 'XL', 'XXL'],
          colors: ['White', 'Blue', 'Light Blue', 'Pink']
        },
        tags: ['shirt', 'formal', 'business', 'dress']
      }
    ],
    womens: [
      {
        name: 'Summer Floral Dress',
        sku: 'DRESS-001',
        description: 'Beautiful floral print dress perfect for summer occasions. Made from breathable cotton blend with adjustable straps.',
        shortDescription: 'Elegant summer wear',
        basePrice: 79.99,
        salePrice: 59.99,
        costPrice: 35.00,
        stock: 80,
        weight: 0.32,
        isFeatured: true,
        attributes: {
          sizes: ['XS', 'S', 'M', 'L', 'XL'],
          colors: ['Pink Floral', 'Blue Floral', 'Yellow Floral']
        },
        tags: ['dress', 'summer', 'floral', 'casual']
      },
      {
        name: 'Yoga Leggings',
        sku: 'LEGGINGS-001',
        description: 'High-waisted yoga leggings with moisture-wicking fabric. Four-way stretch for maximum comfort during workouts.',
        shortDescription: 'Active comfort',
        basePrice: 39.99,
        salePrice: null,
        costPrice: 18.00,
        stock: 300,
        weight: 0.21,
        attributes: {
          sizes: ['XS', 'S', 'M', 'L', 'XL'],
          colors: ['Black', 'Navy', 'Gray', 'Pink', 'Purple']
        },
        tags: ['leggings', 'yoga', 'activewear', 'fitness']
      }
    ],
    accessories: [
      {
        name: 'Luxury Analog Watch',
        sku: 'WATCH-001',
        description: 'Elegant stainless steel watch with leather strap. Japanese quartz movement, water-resistant up to 50m.',
        shortDescription: 'Timeless elegance',
        basePrice: 249.99,
        salePrice: null,
        costPrice: 150.00,
        stock: 30,
        weight: 0.12,
        specifications: {
          movement: 'Japanese Quartz',
          case: 'Stainless Steel 42mm',
          strap: 'Genuine Leather',
          waterResistance: '5 ATM',
          warranty: '2 Years'
        },
        tags: ['watch', 'accessory', 'luxury', 'timepiece']
      },
      {
        name: 'Leather Wallet',
        sku: 'WALLET-001',
        description: 'Genuine leather bi-fold wallet with RFID blocking. Multiple card slots and bill compartment.',
        shortDescription: 'Classic leather craftsmanship',
        basePrice: 49.99,
        salePrice: 44.99,
        costPrice: 22.00,
        stock: 120,
        weight: 0.09,
        attributes: {
          colors: ['Black', 'Brown', 'Tan']
        },
        tags: ['wallet', 'leather', 'accessory', 'rfid']
      }
    ]
  }
};

/**
 * Generate slug from name
 */
function generateSlug(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

/**
 * Generate SKU if not provided
 */
function generateSKU(name) {
  const prefix = name.split(' ')[0].toUpperCase().slice(0, 4);
  const suffix = nanoid(6).toUpperCase();
  return `${prefix}-${suffix}`;
}

/**
 * Seed products
 */
export async function seedProducts() {
  try {
    logger.info('🌱 Seeding products...');

    // Check if products already exist
    const [existing] = await db.execute('SELECT COUNT(*) as count FROM products');
    
    if (existing[0].count > 0) {
      logger.warn('⚠️  Products already exist. Skipping seed.');
      return {
        success: true,
        skipped: true,
        count: existing[0].count
      };
    }

    // Get category IDs
    const [categories] = await db.execute('SELECT id, name, slug FROM categories');
    const categoryMap = {};
    categories.forEach(cat => {
      categoryMap[cat.slug] = cat.id;
    });

    let totalProducts = 0;
    let successCount = 0;
    let errorCount = 0;

    // Insert products
    for (const [mainCat, subCategories] of Object.entries(PRODUCT_CATALOG)) {
      for (const [subCat, products] of Object.entries(subCategories)) {
        const categoryId = categoryMap[subCat];
        
        if (!categoryId) {
          logger.warn(`   ⚠️  Category not found: ${subCat}`);
          continue;
        }

        for (const product of products) {
          totalProducts++;
          
          try {
            const slug = generateSlug(product.name);
            const sku = product.sku || generateSKU(product.name);

            const [result] = await db.execute(
              `INSERT INTO products (
                category_id, sku, name, slug, description, short_description,
                base_price, sale_price, cost_price, stock_quantity,
                weight, status, is_featured, is_bestseller, is_new_arrival,
                specifications, attributes, tags, created_by, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
              [
                categoryId,
                sku,
                product.name,
                slug,
                product.description,
                product.shortDescription,
                product.basePrice,
                product.salePrice || null,
                product.costPrice || null,
                product.stock || 0,
                product.weight || null,
                'active',
                product.isFeatured || false,
                product.isBestseller || false,
                product.isNewArrival || false,
                product.specifications ? JSON.stringify(product.specifications) : null,
                product.attributes ? JSON.stringify(product.attributes) : null,
                product.tags ? JSON.stringify(product.tags) : null,
                1 // Created by admin
              ]
            );

            successCount++;
            logger.info(`   ✓ Created product: ${product.name} (${sku})`);

          } catch (error) {
            errorCount++;
            logger.error(`   ✗ Failed to create product: ${product.name}`, {
              error: error.message
            });
          }
        }
      }
    }

    logger.info('');
    logger.info('📦 Product Seed Summary:');
    logger.info(`   • Total products: ${totalProducts}`);
    logger.info(`   • Created: ${successCount}`);
    logger.info(`   • Failed: ${errorCount}`);
    logger.info('✅ Products seeded successfully');

    return {
      success: true,
      total: totalProducts,
      created: successCount,
      failed: errorCount
    };

  } catch (error) {
    logger.error('❌ Product seeding failed:', error);
    throw error;
  }
}

/**
 * Get product statistics
 */
export async function getProductStats() {
  try {
    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) as total_products,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_products,
        SUM(CASE WHEN is_featured = TRUE THEN 1 ELSE 0 END) as featured_products,
        SUM(CASE WHEN is_bestseller = TRUE THEN 1 ELSE 0 END) as bestsellers,
        SUM(CASE WHEN is_new_arrival = TRUE THEN 1 ELSE 0 END) as new_arrivals,
        SUM(stock_quantity) as total_stock,
        AVG(base_price) as avg_price,
        SUM(CASE WHEN stock_quantity = 0 THEN 1 ELSE 0 END) as out_of_stock
      FROM products
    `);

    return stats[0];

  } catch (error) {
    logger.error('Failed to get product stats:', error);
    throw error;
  }
}

export default seedProducts;

/**
 * CLI execution
 */
if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    try {
      await seedProducts();
      process.exit(0);
    } catch (error) {
      console.error('Seed failed:', error);
      process.exit(1);
    }
  })();
}
