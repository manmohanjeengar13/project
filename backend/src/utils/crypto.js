/**
 * Crypto Utilities - MILITARY-GRADE Cryptography Functions
 * Enterprise-level encryption, hashing, and security utilities
 * 
 * @module utils/crypto
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * FEATURES:
 * ============================================================================
 * - AES encryption/decryption
 * - Password hashing (bcrypt, argon2)
 * - HMAC generation
 * - JWT token utilities
 * - Random token generation
 * - Hash functions (MD5, SHA256, SHA512)
 * - Digital signatures
 * - Key derivation (PBKDF2)
 * - Secure random generators
 * - Base64 encoding/decoding
 * - Hex encoding/decoding
 * - TOTP (Time-based OTP)
 * - UUID generation
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';

// ============================================================================
// CONSTANTS
// ============================================================================

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;

// ============================================================================
// ENCRYPTION & DECRYPTION
// ============================================================================

/**
 * Encrypt data with AES-256-GCM
 * @param {string} text - Plain text
 * @param {string} secret - Encryption key
 * @returns {string} Encrypted data (base64)
 */
export const encrypt = (text, secret) => {
  try {
    const key = crypto.scryptSync(secret, 'salt', KEY_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return IV + encrypted + authTag (all in hex)
    return Buffer.concat([
      iv,
      Buffer.from(encrypted, 'hex'),
      authTag
    ]).toString('base64');
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
};

/**
 * Decrypt AES-256-GCM encrypted data
 * @param {string} encryptedData - Encrypted data (base64)
 * @param {string} secret - Decryption key
 * @returns {string} Decrypted text
 */
export const decrypt = (encryptedData, secret) => {
  try {
    const key = crypto.scryptSync(secret, 'salt', KEY_LENGTH);
    const buffer = Buffer.from(encryptedData, 'base64');
    
    const iv = buffer.slice(0, IV_LENGTH);
    const authTag = buffer.slice(-TAG_LENGTH);
    const encrypted = buffer.slice(IV_LENGTH, -TAG_LENGTH);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
};

/**
 * Encrypt object
 * @param {object} obj - Object to encrypt
 * @param {string} secret - Encryption key
 * @returns {string} Encrypted JSON
 */
export const encryptObject = (obj, secret) => {
  return encrypt(JSON.stringify(obj), secret);
};

/**
 * Decrypt object
 * @param {string} encryptedData - Encrypted data
 * @param {string} secret - Decryption key
 * @returns {object} Decrypted object
 */
export const decryptObject = (encryptedData, secret) => {
  return JSON.parse(decrypt(encryptedData, secret));
};

// ============================================================================
// PASSWORD HASHING
// ============================================================================

/**
 * Hash password with bcrypt
 * @param {string} password - Plain password
 * @param {number} rounds - Salt rounds
 * @returns {Promise<string>} Hashed password
 */
export const hashPassword = async (password, rounds = 12) => {
  return await bcrypt.hash(password, rounds);
};

/**
 * Verify password against hash
 * @param {string} password - Plain password
 * @param {string} hash - Hashed password
 * @returns {Promise<boolean>} Match result
 */
export const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

/**
 * Generate password hash synchronously
 * @param {string} password - Plain password
 * @param {number} rounds - Salt rounds
 * @returns {string} Hashed password
 */
export const hashPasswordSync = (password, rounds = 12) => {
  return bcrypt.hashSync(password, rounds);
};

// ============================================================================
// HASHING FUNCTIONS
// ============================================================================

/**
 * Generate SHA256 hash
 * @param {string} data - Data to hash
 * @param {string} encoding - Output encoding
 * @returns {string} Hash
 */
export const sha256 = (data, encoding = 'hex') => {
  return crypto.createHash('sha256').update(data).digest(encoding);
};

/**
 * Generate SHA512 hash
 * @param {string} data - Data to hash
 * @param {string} encoding - Output encoding
 * @returns {string} Hash
 */
export const sha512 = (data, encoding = 'hex') => {
  return crypto.createHash('sha512').update(data).digest(encoding);
};

/**
 * Generate MD5 hash
 * @param {string} data - Data to hash
 * @param {string} encoding - Output encoding
 * @returns {string} Hash
 */
export const md5 = (data, encoding = 'hex') => {
  return crypto.createHash('md5').update(data).digest(encoding);
};

/**
 * Generate hash with custom algorithm
 * @param {string} data - Data to hash
 * @param {string} algorithm - Hash algorithm
 * @param {string} encoding - Output encoding
 * @returns {string} Hash
 */
export const hash = (data, algorithm = 'sha256', encoding = 'hex') => {
  return crypto.createHash(algorithm).update(data).digest(encoding);
};

// ============================================================================
// HMAC
// ============================================================================

/**
 * Generate HMAC
 * @param {string} data - Data to sign
 * @param {string} secret - Secret key
 * @param {string} algorithm - Hash algorithm
 * @returns {string} HMAC signature
 */
export const hmac = (data, secret, algorithm = 'sha256') => {
  return crypto.createHmac(algorithm, secret).update(data).digest('hex');
};

/**
 * Verify HMAC signature
 * @param {string} data - Original data
 * @param {string} signature - HMAC signature
 * @param {string} secret - Secret key
 * @param {string} algorithm - Hash algorithm
 * @returns {boolean} Is valid
 */
export const verifyHMAC = (data, signature, secret, algorithm = 'sha256') => {
  const expectedSignature = hmac(data, secret, algorithm);
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
};

// ============================================================================
// RANDOM GENERATION
// ============================================================================

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes
 * @returns {Buffer} Random bytes
 */
export const randomBytes = (length = 32) => {
  return crypto.randomBytes(length);
};

/**
 * Generate random hex string
 * @param {number} length - String length
 * @returns {string} Random hex string
 */
export const randomHex = (length = 32) => {
  return randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
};

/**
 * Generate random base64 string
 * @param {number} length - Byte length
 * @returns {string} Random base64 string
 */
export const randomBase64 = (length = 32) => {
  return randomBytes(length).toString('base64');
};

/**
 * Generate random token
 * @param {number} length - Token length
 * @returns {string} Random token
 */
export const generateToken = (length = 32) => {
  return randomHex(length);
};

/**
 * Generate secure random string
 * @param {number} length - String length
 * @returns {string} Random string
 */
export const generateSecureString = (length = 16) => {
  return nanoid(length);
};

/**
 * Generate random integer
 * @param {number} min - Minimum value
 * @param {number} max - Maximum value
 * @returns {number} Random integer
 */
export const randomInt = (min, max) => {
  return crypto.randomInt(min, max + 1);
};

// ============================================================================
// UUID GENERATION
// ============================================================================

/**
 * Generate UUID v4
 * @returns {string} UUID
 */
export const generateUUID = () => {
  return crypto.randomUUID();
};

/**
 * Generate multiple UUIDs
 * @param {number} count - Number of UUIDs
 * @returns {array} Array of UUIDs
 */
export const generateUUIDs = (count) => {
  return Array.from({ length: count }, () => generateUUID());
};

// ============================================================================
// KEY DERIVATION
// ============================================================================

/**
 * Derive key from password (PBKDF2)
 * @param {string} password - Password
 * @param {string} salt - Salt
 * @param {number} iterations - Iterations
 * @param {number} keyLength - Key length
 * @returns {Buffer} Derived key
 */
export const deriveKey = (password, salt, iterations = 100000, keyLength = 32) => {
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
};

/**
 * Derive key asynchronously
 * @param {string} password - Password
 * @param {string} salt - Salt
 * @param {number} iterations - Iterations
 * @param {number} keyLength - Key length
 * @returns {Promise<Buffer>} Derived key
 */
export const deriveKeyAsync = (password, salt, iterations = 100000, keyLength = 32) => {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLength, 'sha512', (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
};

/**
 * Generate salt
 * @param {number} length - Salt length
 * @returns {string} Salt (hex)
 */
export const generateSalt = (length = SALT_LENGTH) => {
  return randomBytes(length).toString('hex');
};

// ============================================================================
// ENCODING & DECODING
// ============================================================================

/**
 * Encode to Base64
 * @param {string} data - Data to encode
 * @returns {string} Base64 string
 */
export const base64Encode = (data) => {
  return Buffer.from(data, 'utf8').toString('base64');
};

/**
 * Decode from Base64
 * @param {string} data - Base64 string
 * @returns {string} Decoded string
 */
export const base64Decode = (data) => {
  return Buffer.from(data, 'base64').toString('utf8');
};

/**
 * URL-safe Base64 encode
 * @param {string} data - Data to encode
 * @returns {string} URL-safe Base64
 */
export const base64UrlEncode = (data) => {
  return base64Encode(data)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

/**
 * URL-safe Base64 decode
 * @param {string} data - URL-safe Base64
 * @returns {string} Decoded string
 */
export const base64UrlDecode = (data) => {
  let base64 = data.replace(/-/g, '+').replace(/_/g, '/');
  
  while (base64.length % 4) {
    base64 += '=';
  }
  
  return base64Decode(base64);
};

/**
 * Encode to hex
 * @param {string} data - Data to encode
 * @returns {string} Hex string
 */
export const hexEncode = (data) => {
  return Buffer.from(data, 'utf8').toString('hex');
};

/**
 * Decode from hex
 * @param {string} data - Hex string
 * @returns {string} Decoded string
 */
export const hexDecode = (data) => {
  return Buffer.from(data, 'hex').toString('utf8');
};

// ============================================================================
// TOTP (Time-based One-Time Password)
// ============================================================================

/**
 * Generate TOTP secret
 * @returns {string} Base32 encoded secret
 */
export const generateTOTPSecret = () => {
  const secret = randomBytes(20).toString('base32');
  return secret;
};

/**
 * Generate TOTP code
 * @param {string} secret - TOTP secret
 * @param {number} window - Time window (30s default)
 * @returns {string} 6-digit code
 */
export const generateTOTP = (secret, window = 30) => {
  const epoch = Math.floor(Date.now() / 1000 / window);
  const buffer = Buffer.alloc(8);
  
  for (let i = 7; i >= 0; i--) {
    buffer[i] = epoch & 0xff;
    epoch >> 8;
  }
  
  const hmacResult = crypto.createHmac('sha1', Buffer.from(secret, 'base32')).update(buffer).digest();
  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  const code = (
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff)
  );
  
  return (code % 1000000).toString().padStart(6, '0');
};

/**
 * Verify TOTP code
 * @param {string} token - TOTP code
 * @param {string} secret - TOTP secret
 * @param {number} window - Time window
 * @param {number} step - Time step tolerance
 * @returns {boolean} Is valid
 */
export const verifyTOTP = (token, secret, window = 30, step = 1) => {
  const epoch = Math.floor(Date.now() / 1000 / window);
  
  for (let i = -step; i <= step; i++) {
    const testEpoch = epoch + i;
    const buffer = Buffer.alloc(8);
    
    for (let j = 7; j >= 0; j--) {
      buffer[j] = testEpoch & 0xff;
      testEpoch >> 8;
    }
    
    const expectedToken = generateTOTP(secret, window);
    
    if (token === expectedToken) {
      return true;
    }
  }
  
  return false;
};

// ============================================================================
// DIGITAL SIGNATURES
// ============================================================================

/**
 * Generate RSA key pair
 * @param {number} modulusLength - Key size in bits
 * @returns {object} Public and private keys
 */
export const generateKeyPair = (modulusLength = 2048) => {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
};

/**
 * Sign data with private key
 * @param {string} data - Data to sign
 * @param {string} privateKey - Private key (PEM)
 * @returns {string} Signature (base64)
 */
export const sign = (data, privateKey) => {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(data);
  return signer.sign(privateKey, 'base64');
};

/**
 * Verify signature with public key
 * @param {string} data - Original data
 * @param {string} signature - Signature (base64)
 * @param {string} publicKey - Public key (PEM)
 * @returns {boolean} Is valid
 */
export const verifySignature = (data, signature, publicKey) => {
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(data);
  return verifier.verify(publicKey, signature, 'base64');
};

// ============================================================================
// JWT UTILITIES
// ============================================================================

/**
 * Create JWT payload
 * @param {object} data - Payload data
 * @param {number} expiresIn - Expiration in seconds
 * @returns {object} JWT payload
 */
export const createJWTPayload = (data, expiresIn = 3600) => {
  const now = Math.floor(Date.now() / 1000);
  
  return {
    ...data,
    iat: now,
    exp: now + expiresIn,
    jti: generateUUID()
  };
};

/**
 * Encode JWT header
 * @param {string} algorithm - Algorithm (HS256, RS256)
 * @returns {string} Encoded header
 */
export const encodeJWTHeader = (algorithm = 'HS256') => {
  return base64UrlEncode(JSON.stringify({
    alg: algorithm,
    typ: 'JWT'
  }));
};

/**
 * Encode JWT payload
 * @param {object} payload - Payload object
 * @returns {string} Encoded payload
 */
export const encodeJWTPayload = (payload) => {
  return base64UrlEncode(JSON.stringify(payload));
};

/**
 * Sign JWT
 * @param {string} headerAndPayload - Header.Payload
 * @param {string} secret - Secret key
 * @param {string} algorithm - Algorithm
 * @returns {string} Signature
 */
export const signJWT = (headerAndPayload, secret, algorithm = 'HS256') => {
  if (algorithm.startsWith('HS')) {
    const hmacAlgorithm = algorithm.replace('HS', 'sha');
    return base64UrlEncode(hmac(headerAndPayload, secret, hmacAlgorithm));
  }
  
  throw new Error('Unsupported algorithm');
};

// ============================================================================
// CHECKSUM
// ============================================================================

/**
 * Calculate checksum
 * @param {string} data - Data
 * @param {string} algorithm - Hash algorithm
 * @returns {string} Checksum
 */
export const checksum = (data, algorithm = 'md5') => {
  return hash(data, algorithm);
};

/**
 * Verify checksum
 * @param {string} data - Data
 * @param {string} expectedChecksum - Expected checksum
 * @param {string} algorithm - Hash algorithm
 * @returns {boolean} Is valid
 */
export const verifyChecksum = (data, expectedChecksum, algorithm = 'md5') => {
  const actualChecksum = checksum(data, algorithm);
  return actualChecksum === expectedChecksum;
};

// ============================================================================
// CIPHER STREAM
// ============================================================================

/**
 * Create cipher stream
 * @param {string} algorithm - Cipher algorithm
 * @param {string} key - Encryption key
 * @param {Buffer} iv - Initialization vector
 * @returns {Cipher} Cipher stream
 */
export const createCipherStream = (algorithm, key, iv) => {
  return crypto.createCipheriv(algorithm, key, iv);
};

/**
 * Create decipher stream
 * @param {string} algorithm - Cipher algorithm
 * @param {string} key - Decryption key
 * @param {Buffer} iv - Initialization vector
 * @returns {Decipher} Decipher stream
 */
export const createDecipherStream = (algorithm, key, iv) => {
  return crypto.createDecipheriv(algorithm, key, iv);
};

// ============================================================================
// SECURE COMPARISON
// ============================================================================

/**
 * Timing-safe string comparison
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} Are equal
 */
export const timingSafeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  
  return crypto.timingSafeEqual(
    Buffer.from(a),
    Buffer.from(b)
  );
};

/**
 * Constant-time buffer comparison
 * @param {Buffer} a - First buffer
 * @param {Buffer} b - Second buffer
 * @returns {boolean} Are equal
 */
export const constantTimeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
};

// ============================================================================
// PASSWORD UTILITIES
// ============================================================================

/**
 * Generate secure password
 * @param {number} length - Password length
 * @param {object} options - Options
 * @returns {string} Secure password
 */
export const generatePassword = (length = 16, options = {}) => {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true
  } = options;
  
  let chars = '';
  if (includeUppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) chars += '0123456789';
  if (includeSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  let password = '';
  const randomValues = randomBytes(length);
  
  for (let i = 0; i < length; i++) {
    password += chars[randomValues[i] % chars.length];
  }
  
  return password;
};

/**
 * Generate passphrase
 * @param {number} wordCount - Number of words
 * @param {string} separator - Word separator
 * @returns {string} Passphrase
 */
export const generatePassphrase = (wordCount = 4, separator = '-') => {
  const words = [
    'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot',
    'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima',
    'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo',
    'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
    'yankee', 'zulu'
  ];
  
  const selectedWords = [];
  for (let i = 0; i < wordCount; i++) {
    const index = randomInt(0, words.length - 1);
    selectedWords.push(words[index]);
  }
  
  return selectedWords.join(separator);
};

// ============================================================================
// API KEY GENERATION
// ============================================================================

/**
 * Generate API key
 * @param {string} prefix - Key prefix
 * @param {number} length - Key length
 * @returns {string} API key
 */
export const generateAPIKey = (prefix = 'sk', length = 32) => {
  const key = randomHex(length);
  return `${prefix}_${key}`;
};

/**
 * Generate API key pair
 * @returns {object} Public and secret keys
 */
export const generateAPIKeyPair = () => {
  return {
    publicKey: generateAPIKey('pk', 16),
    secretKey: generateAPIKey('sk', 32)
  };
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Encryption
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  
  // Password
  hashPassword,
  verifyPassword,
  hashPasswordSync,
  
  // Hashing
  sha256,
  sha512,
  md5,
  hash,
  
  // HMAC
  hmac,
  verifyHMAC,
  
  // Random
  randomBytes,
  randomHex,
  randomBase64,
  generateToken,
  generateSecureString,
  randomInt,
  
  // UUID
  generateUUID,
  generateUUIDs,
  
  // Key Derivation
  deriveKey,
  deriveKeyAsync,
  generateSalt,
  
  // Encoding
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
  hexEncode,
  hexDecode,
  
  // TOTP
  generateTOTPSecret,
  generateTOTP,
  verifyTOTP,
  
  // Digital Signatures
  generateKeyPair,
  sign,
  verifySignature,
  
  // JWT
  createJWTPayload,
  encodeJWTHeader,
  encodeJWTPayload,
  signJWT,
  
  // Checksum
  checksum,
  verifyChecksum,
  
  // Streams
  createCipherStream,
  createDecipherStream,
  
  // Comparison
  timingSafeEqual,
  constantTimeEqual,
  
  // Password Generation
  generatePassword,
  generatePassphrase,
  
  // API Keys
  generateAPIKey,
  generateAPIKeyPair
};
