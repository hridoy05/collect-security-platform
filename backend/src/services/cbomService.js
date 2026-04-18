// ============================================================
// CBOM Service — Cryptographic Bill of Materials
// Topic 7: Cryptographic Risk Management
// ICAM cycle: Inventory → Classify → Assess → Mitigate
// ============================================================

const prisma = require('../config/prismaClient');
const { assessAlgorithmRisk, BROKEN_ALGORITHMS, QUANTUM_VULNERABLE } = require('./cryptoService');
const { esClient, ES_INDICES } = require('./elasticService');

// ─────────────────────────────────────────
// ASSESS — Rate each asset Red/Amber/Green
// Topic 7: ICAM cycle — A = Assess
// ─────────────────────────────────────────

function assessAsset(asset) {
  const issues = [];
  let riskRating = 'green';
  let riskScore = 0;

  const algo = (asset.algorithm || '').toUpperCase();

  // 1. Check for broken algorithms → always RED
  if (BROKEN_ALGORITHMS.some(b => algo.includes(b.toUpperCase()))) {
    issues.push(`Broken algorithm: ${asset.algorithm} — replace immediately`);
    riskRating = 'red';
    riskScore = Math.max(riskScore, 90);
  }

  // 2. Check key length minimums
  if (algo.includes('RSA') && asset.key_length && asset.key_length < 2048) {
    issues.push(`RSA key length ${asset.key_length} is below minimum (2048)`);
    riskRating = 'red';
    riskScore = Math.max(riskScore, 85);
  }

  if (algo.includes('AES') && asset.key_length && asset.key_length < 256) {
    issues.push(`AES-${asset.key_length} — recommend AES-256`);
    if (riskRating !== 'red') riskRating = 'amber';
    riskScore = Math.max(riskScore, 60);
  }

  // 3. Check quantum vulnerability
  const isQuantumVulnerable = QUANTUM_VULNERABLE.some(v => algo.includes(v));
  const isQuantumSafe = ['AES-256', 'SHA-256', 'SHA-3', 'CRYSTALS', 'ARGON2', 'BCRYPT']
    .some(s => algo.includes(s));

  if (isQuantumVulnerable) {
    issues.push(`Quantum-vulnerable: ${asset.algorithm} — broken by Shor's algorithm`);
    if (riskRating === 'green') riskRating = 'amber';
    riskScore = Math.max(riskScore, 55);
  }

  // 4. Check certificate expiry
  let daysToExpiry = null;
  if (asset.expiry_date) {
    daysToExpiry = Math.floor(
      (new Date(asset.expiry_date) - new Date()) / (1000 * 60 * 60 * 24)
    );

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
      if (riskRating !== 'red') riskRating = 'amber';
      riskScore = Math.max(riskScore, 65);
    }
  }

  // 5. Check rotation policy
  if (!asset.rotation_policy || asset.rotation_policy === 'none') {
    issues.push('No rotation policy defined');
    if (riskRating === 'green') riskRating = 'amber';
    riskScore = Math.max(riskScore, 45);
  }

  // 6. Production environment amplifies risk
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

// ─────────────────────────────────────────
// GET ALL ASSETS — with assessment
// ─────────────────────────────────────────

async function getAllAssets(filters = {}) {
  const where = {};
  if (filters.riskRating) where.riskRating = filters.riskRating;
  if (filters.environment) where.environment = filters.environment;
  if (filters.quantumSafe !== undefined) where.quantumSafe = filters.quantumSafe;

  // Use findMany for the main query
  const assets = await prisma.cryptoAsset.findMany({
    where,
    orderBy: [
      { riskRating: 'asc' }, // Standard sort as a baseline
      { daysToExpiry: 'asc' }
    ]
  });

  // Re-map to match original camelCase/snake_case expectations if necessary
  // The original returned snake_case from PG. Prisma returns camelCase.
  // I will transform them back to snake_case to maintain API compatibility.
  return assets.map(a => ({
    ...a,
    asset_id: a.assetId,
    asset_type: a.assetType,
    key_length: a.keyLength,
    hash_algorithm: a.hashAlgorithm,
    system_name: a.systemName,
    owner_team: a.ownerTeam,
    expiry_date: a.expiryDate,
    days_to_expiry: a.daysToExpiry,
    last_rotated: a.lastRotated,
    rotation_policy: a.rotationPolicy,
    quantum_safe: a.quantumSafe,
    risk_rating: a.riskRating,
    updated_at: a.updatedAt,
    created_at: a.createdAt
  }));
}

// ─────────────────────────────────────────
// UPSERT ASSET — with auto-assessment
// ─────────────────────────────────────────

async function upsertAsset(assetData) {
  const assessed = assessAsset(assetData);

  const result = await prisma.cryptoAsset.upsert({
    where: { assetId: assessed.asset_id },
    update: {
      algorithm: assessed.algorithm,
      keyLength: assessed.key_length,
      expiryDate: assessed.expiry_date ? new Date(assessed.expiry_date) : null,
      daysToExpiry: assessed.days_to_expiry,
      quantumSafe: assessed.quantum_safe,
      riskRating: assessed.risk_rating,
      issues: assessed.issues,
      updatedAt: new Date()
    },
    create: {
      assetId: assessed.asset_id,
      assetType: assessed.asset_type,
      algorithm: assessed.algorithm,
      keyLength: assessed.key_length,
      hashAlgorithm: assessed.hash_algorithm,
      systemName: assessed.system_name,
      environment: assessed.environment,
      ownerTeam: assessed.owner_team,
      issuer: assessed.issuer,
      expiryDate: assessed.expiry_date ? new Date(assessed.expiry_date) : null,
      daysToExpiry: assessed.days_to_expiry,
      lastRotated: assessed.last_rotated ? new Date(assessed.last_rotated) : null,
      rotationPolicy: assessed.rotation_policy,
      quantumSafe: assessed.quantum_safe,
      riskRating: assessed.risk_rating,
      issues: assessed.issues,
      notes: assessed.notes,
      updatedAt: new Date()
    }
  });

  // Also index in Elasticsearch for SIEM correlation
  await esClient.index({
    index: ES_INDICES.CBOM,
    id: assessed.asset_id,
    document: { ...assessed, '@timestamp': new Date() }
  });

  // Map result back to snake_case for compatibility
  return {
    ...result,
    asset_id: result.assetId,
    asset_type: result.assetType,
    key_length: result.keyLength,
    hash_algorithm: result.hashAlgorithm,
    system_name: result.systemName,
    owner_team: result.ownerTeam,
    expiry_date: result.expiryDate,
    days_to_expiry: result.daysToExpiry,
    last_rotated: result.lastRotated,
    rotation_policy: result.rotationPolicy,
    quantum_safe: result.quantumSafe,
    risk_rating: result.riskRating,
    updated_at: result.updatedAt,
    created_at: result.createdAt
  };
}

// ─────────────────────────────────────────
// RISK SUMMARY — for dashboard
// ─────────────────────────────────────────

async function getRiskSummary() {
  const [total, red, amber, green, quantumVulnerable, expiringSoon, expired, noRotation] = await Promise.all([
    prisma.cryptoAsset.count(),
    prisma.cryptoAsset.count({ where: { riskRating: 'red' } }),
    prisma.cryptoAsset.count({ where: { riskRating: 'amber' } }),
    prisma.cryptoAsset.count({ where: { riskRating: 'green' } }),
    prisma.cryptoAsset.count({ where: { quantumSafe: false } }),
    prisma.cryptoAsset.count({ where: { daysToExpiry: { gte: 0, lte: 30 } } }),
    prisma.cryptoAsset.count({ where: { daysToExpiry: { lt: 0 } } }),
    prisma.cryptoAsset.count({ where: { OR: [{ rotationPolicy: 'none' }, { rotationPolicy: null }] } })
  ]);

  return {
    total,
    red,
    amber,
    green,
    quantum_vulnerable: quantumVulnerable,
    expiring_soon: expiringSoon,
    expired,
    no_rotation_policy: noRotation
  };
}

// ─────────────────────────────────────────
// MIGRATION ROADMAP — quantum transition
// Topic 2: Crypto-agility + quantum migration
// ─────────────────────────────────────────

async function generateMigrationRoadmap() {
  const vulnerableAssets = await prisma.cryptoAsset.findMany({
    where: {
      quantumSafe: false,
      environment: 'production'
    },
    orderBy: [
      { riskRating: 'asc' }
    ]
  });

  return vulnerableAssets.map(asset => ({
    assetId: asset.assetId,
    currentAlgorithm: asset.algorithm,
    system: asset.systemName,
    riskRating: asset.riskRating,
    recommendation: getQuantumMigrationRecommendation(asset.algorithm),
    estimatedEffort: estimateMigrationEffort(asset),
    priority: asset.riskRating === 'red' ? 1 : asset.riskRating === 'amber' ? 2 : 3
  }));
}

function getQuantumMigrationRecommendation(algorithm) {
  const algo = algorithm.toUpperCase();
  if (algo.includes('RSA') || algo.includes('ECDSA') || algo.includes('ECDH')) {
    return {
      replacementAlgorithm: 'CRYSTALS-Kyber (key exchange) + CRYSTALS-Dilithium (signatures)',
      approach: 'Hybrid deployment — run classical + quantum-safe in parallel',
      timeline: '12-18 months',
      reference: 'NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)'
    };
  }
  if (algo.includes('AES-128')) {
    return {
      replacementAlgorithm: 'AES-256-GCM',
      approach: 'Key rotation with version migration',
      timeline: '1-3 months',
      reference: 'NIST recommendation — AES-128 drops to 64-bit effective security vs quantum'
    };
  }
  return {
    replacementAlgorithm: 'Review required',
    approach: 'Manual assessment needed',
    timeline: 'TBD'
  };
}

function estimateMigrationEffort(asset) {
  const type = asset.assetType || asset.asset_type;
  if (type === 'TLS Certificate') return 'Low — certificate renewal';
  if (type === 'JWT Signing Key') return 'Medium — update auth service + client validation';
  if (type === 'Database Key') return 'High — background data re-encryption required';
  if (type === 'SSH Key') return 'Low — generate new key pair, update authorized_keys';
  return 'Medium';
}

module.exports = {
  assessAsset,
  getAllAssets,
  upsertAsset,
  getRiskSummary,
  generateMigrationRoadmap
};
