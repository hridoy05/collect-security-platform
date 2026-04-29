const { BROKEN_ALGORITHMS, QUANTUM_VULNERABLE } = require('../crypto');

const QUANTUM_SAFE_ALGORITHMS = [
  'AES-256',
  'SHA-256',
  'SHA-3',
  'CRYSTALS',
  'ARGON2',
  'BCRYPT'
];

const MS_PER_DAY = 1000 * 60 * 60 * 24;

function calculateDaysToExpiry(expiryDate) {
  if (!expiryDate) {
    return null;
  }

  return Math.floor((new Date(expiryDate) - new Date()) / MS_PER_DAY);
}

function assessAsset(asset) {
  const issues = [];
  let riskRating = 'green';
  let riskScore = 0;

  const algorithm = asset.algorithm || '';
  const normalizedAlgorithm = algorithm.toUpperCase();

  if (BROKEN_ALGORITHMS.some((broken) => normalizedAlgorithm.includes(broken.toUpperCase()))) {
    issues.push(`Broken algorithm: ${algorithm} — replace immediately`);
    riskRating = 'red';
    riskScore = Math.max(riskScore, 90);
  }

  if (normalizedAlgorithm.includes('RSA') && asset.key_length && asset.key_length < 2048) {
    issues.push(`RSA key length ${asset.key_length} is below minimum (2048)`);
    riskRating = 'red';
    riskScore = Math.max(riskScore, 85);
  }

  if (normalizedAlgorithm.includes('AES') && asset.key_length && asset.key_length < 256) {
    issues.push(`AES-${asset.key_length} — recommend AES-256`);
    if (riskRating !== 'red') {
      riskRating = 'amber';
    }
    riskScore = Math.max(riskScore, 60);
  }

  const isQuantumVulnerable = QUANTUM_VULNERABLE.some((value) => normalizedAlgorithm.includes(value));
  const isQuantumSafe = QUANTUM_SAFE_ALGORITHMS.some((value) => normalizedAlgorithm.includes(value));

  if (isQuantumVulnerable) {
    issues.push(`Quantum-vulnerable: ${algorithm} — broken by Shor's algorithm`);
    if (riskRating === 'green') {
      riskRating = 'amber';
    }
    riskScore = Math.max(riskScore, 55);
  }

  const daysToExpiry = calculateDaysToExpiry(asset.expiry_date);
  if (daysToExpiry !== null) {
    if (daysToExpiry < 0) {
      issues.push(`EXPIRED ${Math.abs(daysToExpiry)} days ago — immediate action required`);
      riskRating = 'red';
      riskScore = Math.max(riskScore, 95);
    } else if (daysToExpiry <= 7) {
      issues.push(`Expires in ${daysToExpiry} days — CRITICAL`);
      riskRating = 'red';
      riskScore = Math.max(riskScore, 88);
    } else if (daysToExpiry <= 30) {
      issues.push(`Expires in ${daysToExpiry} days`);
      if (riskRating !== 'red') {
        riskRating = 'amber';
      }
      riskScore = Math.max(riskScore, 65);
    }
  }

  if (!asset.rotation_policy || asset.rotation_policy === 'none') {
    issues.push('No rotation policy defined');
    if (riskRating === 'green') {
      riskRating = 'amber';
    }
    riskScore = Math.max(riskScore, 45);
  }

  if (asset.environment === 'production' && riskRating === 'amber') {
    riskScore = Math.min(riskScore + 10, 100);
  }

  return {
    ...asset,
    risk_rating: riskRating,
    risk_score: riskScore,
    quantum_safe: isQuantumSafe && !isQuantumVulnerable,
    days_to_expiry: daysToExpiry,
    issues: issues.join('; ') || null,
    updated_at: new Date()
  };
}

module.exports = {
  assessAsset,
  calculateDaysToExpiry
};
