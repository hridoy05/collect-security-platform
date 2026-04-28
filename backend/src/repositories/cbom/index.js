const prisma = require('../../config/prismaClient');

async function findMany(filters = {}) {
  const where = {};

  if (filters.riskRating) {
    where.riskRating = filters.riskRating;
  }

  if (filters.environment) {
    where.environment = filters.environment;
  }

  if (filters.quantumSafe !== undefined) {
    where.quantumSafe = filters.quantumSafe;
  }

  return prisma.cryptoAsset.findMany({
    where,
    orderBy: [
      { riskRating: 'asc' },
      { daysToExpiry: 'asc' }
    ]
  });
}

async function upsert(payload) {
  return prisma.cryptoAsset.upsert(payload);
}

async function getRiskSummary() {
  const [total, red, amber, green, quantumVulnerable, expiringSoon, expired, noRotation] =
    await Promise.all([
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

async function getDashboardStats() {
  const [red, amber, green, expiringSoon, quantumVulnerable] = await Promise.all([
    prisma.cryptoAsset.count({ where: { riskRating: 'red' } }),
    prisma.cryptoAsset.count({ where: { riskRating: 'amber' } }),
    prisma.cryptoAsset.count({ where: { riskRating: 'green' } }),
    prisma.cryptoAsset.count({ where: { daysToExpiry: { gte: 0, lte: 30 } } }),
    prisma.cryptoAsset.count({ where: { quantumSafe: false, environment: 'production' } })
  ]);

  return {
    red,
    amber,
    green,
    expiring_soon: expiringSoon,
    quantum_vulnerable: quantumVulnerable
  };
}

async function findProductionQuantumVulnerableAssets() {
  return prisma.cryptoAsset.findMany({
    where: {
      quantumSafe: false,
      environment: 'production'
    },
    orderBy: [{ riskRating: 'asc' }]
  });
}

module.exports = {
  findMany,
  findProductionQuantumVulnerableAssets,
  getDashboardStats,
  getRiskSummary,
  upsert
};
