// ============================================================
// AES-256-GCM encryption, bcrypt hashing, key management
// Quantum-safe awareness
// ============================================================

import * as crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const BCRYPT_ROUNDS = 12;
const CURRENT_KEY_VERSION = 'v1';

export interface EncryptedPayload {
  keyVersion: string;
  algorithm: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface AlgorithmRiskAssessment {
  risk: 'low' | 'medium' | 'high' | 'critical';
  quantumSafe: boolean;
  reason: string;
  recommendation: string;
  timeline?: string;
}

export function encrypt(plaintext: string): EncryptedPayload {
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = getEncryptionKey();

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return {
    keyVersion: CURRENT_KEY_VERSION,
    algorithm: ALGORITHM,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64')
  };
}

export function decrypt(encryptedObj: EncryptedPayload): string {
  const key = getEncryptionKey(encryptedObj.keyVersion);
  const iv = Buffer.from(encryptedObj.iv, 'base64');
  const authTag = Buffer.from(encryptedObj.authTag, 'base64');
  const ciphertext = Buffer.from(encryptedObj.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH
  });

  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    throw new Error('Decryption failed: data integrity check failed. Possible tampering detected.');
  }
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateHMAC(data: unknown, secret: string): string {
  return crypto
    .createHmac('sha256', secret)
    .update(typeof data === 'string' ? data : JSON.stringify(data))
    .digest('hex');
}

export function verifyHMAC(data: unknown, secret: string, expectedHMAC: string): boolean {
  const computedHMAC = generateHMAC(data, secret);
  return crypto.timingSafeEqual(
    Buffer.from(computedHMAC, 'hex'),
    Buffer.from(expectedHMAC, 'hex')
  );
}

export const QUANTUM_VULNERABLE = ['RSA', 'ECDSA', 'ECDH', 'DSA', 'DH', 'ECC'] as const;
export const BROKEN_ALGORITHMS = ['MD5', 'SHA-1', 'DES', '3DES', 'RC4', 'AES-128-CBC'] as const;
const QUANTUM_SAFE = [
  'AES-256',
  'AES-256-GCM',
  'SHA-256',
  'SHA-3',
  'CRYSTALS-Kyber',
  'CRYSTALS-Dilithium'
] as const;

export function assessAlgorithmRisk(algorithm: string): AlgorithmRiskAssessment {
  const algo = algorithm.toUpperCase();

  if (BROKEN_ALGORITHMS.some((broken) => algo.includes(broken.toUpperCase()))) {
    return {
      risk: 'critical',
      quantumSafe: false,
      reason: `Broken algorithm: ${algorithm}. Replace immediately.`,
      recommendation: 'Upgrade to AES-256-GCM for symmetric, SHA-256 for hashing'
    };
  }

  if (QUANTUM_VULNERABLE.some((value) => algo.includes(value))) {
    return {
      risk: 'high',
      quantumSafe: false,
      reason: `Quantum-vulnerable: ${algorithm}. Shor's algorithm can break this.`,
      recommendation:
        'Plan migration to CRYSTALS-Kyber (key exchange) or CRYSTALS-Dilithium (signatures)',
      timeline: 'Migrate before 2030 — harvest now, decrypt later threat is active'
    };
  }

  if (QUANTUM_SAFE.some((value) => algo.includes(value.toUpperCase()))) {
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

export function calculateEntropy(str: string): number {
  if (!str) {
    return 0;
  }

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  return Object.values(freq).reduce((entropy, count) => {
    const p = count / str.length;
    return entropy - p * Math.log2(p);
  }, 0);
}

function getEncryptionKey(_version = CURRENT_KEY_VERSION): Buffer {
  const keyHex = process.env.ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error('ENCRYPTION_KEY not set in environment');
  }

  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex chars) for AES-256');
  }

  return key;
}

export function generateSecureToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}
