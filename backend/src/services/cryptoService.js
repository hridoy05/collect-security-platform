// ============================================================
// Crypto Service — Topic 1 + 2
// AES-256-GCM encryption, bcrypt hashing, key management
// Quantum-safe awareness
// ============================================================

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;        // 96 bits — GCM recommended
const AUTH_TAG_LENGTH = 16;  // 128 bits
const BCRYPT_ROUNDS = 12;    // Cost factor — slow enough to resist brute force
const CURRENT_KEY_VERSION = 'v1';

// ─────────────────────────────────────────
// SYMMETRIC ENCRYPTION — AES-256-GCM
// Topic 1: Why GCM?
// GCM = encryption + authentication tag
// If ciphertext is tampered with → decryption throws
// CBC does NOT provide this guarantee — always use GCM
// ─────────────────────────────────────────

function encrypt(plaintext) {
  // NEVER use Math.random() — use CSPRNG (crypto.randomBytes)
  // Topic 1: CSPRNG requirement
  const iv = crypto.randomBytes(IV_LENGTH);

  // Get key from environment — never hardcode
  // Topic 7: Key distribution — keys from secrets manager
  const key = getEncryptionKey();

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  // Store keyVersion for key rotation support
  // Topic 7: Crypto-agility — key_version enables migration
  return {
    keyVersion: CURRENT_KEY_VERSION,
    algorithm: ALGORITHM,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64')
  };
}

function decrypt(encryptedObj) {
  const key = getEncryptionKey(encryptedObj.keyVersion);
  const iv = Buffer.from(encryptedObj.iv, 'base64');
  const authTag = Buffer.from(encryptedObj.authTag, 'base64');
  const ciphertext = Buffer.from(encryptedObj.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final() // Throws if auth tag verification fails
    ]);
    return decrypted.toString('utf8');
  } catch (err) {
    // Auth tag failed = data was tampered with
    // Topic 1: GCM authentication provides integrity
    throw new Error('Decryption failed: data integrity check failed. Possible tampering detected.');
  }
}

// ─────────────────────────────────────────
// PASSWORD HASHING — bcrypt
// Topic 1: Why bcrypt not SHA-256?
// bcrypt is SLOW by design — cost factor 12
// SHA-256 can do 10 billion hashes/second on GPU
// bcrypt with cost 12 ≈ 200ms/hash
// Brute forcing 1 billion passwords = 6300 years
// ─────────────────────────────────────────

async function hashPassword(password) {
  // bcrypt automatically generates and embeds the salt
  // Topic 1: Salt prevents rainbow table attacks
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// ─────────────────────────────────────────
// HMAC — Topic 1: Message Authentication
// Used for API request signing, webhook validation
// Combines key + data to prove both integrity AND authenticity
// ─────────────────────────────────────────

function generateHMAC(data, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(typeof data === 'string' ? data : JSON.stringify(data))
    .digest('hex');
}

function verifyHMAC(data, secret, expectedHMAC) {
  const computedHMAC = generateHMAC(data, secret);
  // Use timingSafeEqual to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(computedHMAC, 'hex'),
    Buffer.from(expectedHMAC, 'hex')
  );
}

// ─────────────────────────────────────────
// QUANTUM RISK ASSESSMENT — Topic 2
// Assess whether an algorithm is quantum-safe
// ─────────────────────────────────────────

const QUANTUM_VULNERABLE = ['RSA', 'ECDSA', 'ECDH', 'DSA', 'DH', 'ECC'];
const BROKEN_ALGORITHMS = ['MD5', 'SHA-1', 'DES', '3DES', 'RC4', 'AES-128-CBC'];
const QUANTUM_SAFE = ['AES-256', 'AES-256-GCM', 'SHA-256', 'SHA-3', 'CRYSTALS-Kyber', 'CRYSTALS-Dilithium'];

function assessAlgorithmRisk(algorithm) {
  const algo = algorithm.toUpperCase();

  if (BROKEN_ALGORITHMS.some(b => algo.includes(b.toUpperCase()))) {
    return {
      risk: 'critical',
      quantumSafe: false,
      reason: `Broken algorithm: ${algorithm}. Replace immediately.`,
      recommendation: 'Upgrade to AES-256-GCM for symmetric, SHA-256 for hashing'
    };
  }

  if (QUANTUM_VULNERABLE.some(v => algo.includes(v))) {
    return {
      risk: 'high',
      quantumSafe: false,
      reason: `Quantum-vulnerable: ${algorithm}. Shor's algorithm can break this.`,
      recommendation: 'Plan migration to CRYSTALS-Kyber (key exchange) or CRYSTALS-Dilithium (signatures)',
      timeline: 'Migrate before 2030 — harvest now, decrypt later threat is active'
    };
  }

  if (QUANTUM_SAFE.some(s => algo.includes(s.toUpperCase()))) {
    return {
      risk: 'low',
      quantumSafe: true,
      reason: `Quantum-safe: ${algorithm}`,
      recommendation: 'No action required'
    };
  }

  return {
    risk: 'medium',
    quantumSafe: false,
    reason: `Unknown algorithm: ${algorithm}. Manual review required.`,
    recommendation: 'Verify algorithm security against current standards'
  };
}

// ─────────────────────────────────────────
// SHANNON ENTROPY — Topic 8
// Used for DNS tunneling detection
// High entropy in domain names = encoded data
// ─────────────────────────────────────────

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  return Object.values(freq).reduce((entropy, count) => {
    const p = count / str.length;
    return entropy - p * Math.log2(p);
  }, 0);
}

// ─────────────────────────────────────────
// KEY MANAGEMENT
// Topic 7: Keys from environment/secrets manager
// ─────────────────────────────────────────

function getEncryptionKey(version = CURRENT_KEY_VERSION) {
  const keyHex = process.env.ENCRYPTION_KEY;
  if (!keyHex) throw new Error('ENCRYPTION_KEY not set in environment');
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex chars) for AES-256');
  return key;
}

function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  encrypt,
  decrypt,
  hashPassword,
  verifyPassword,
  generateHMAC,
  verifyHMAC,
  assessAlgorithmRisk,
  calculateEntropy,
  generateSecureToken,
  QUANTUM_VULNERABLE,
  BROKEN_ALGORITHMS
};
