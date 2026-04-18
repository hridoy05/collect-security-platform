const asyncHandler = require('express-async-handler');
const prisma = require('../config/prismaClient');

/**
 * @desc    Get aggregated stats for the main dashboard
 * @route   GET /api/dashboard/stats
 * @access  Private
 */
const getDashboardStats = asyncHandler(async (req, res) => {
  // Parallel queries for speed
  const [cbomStats, alertStats, iocCount, cveStats] = await Promise.all([
    (async () => {
      const [red, amber, green, expiringSoon, quantumVulnerable] = await Promise.all([
        prisma.cryptoAsset.count({ where: { riskRating: 'red' } }),
        prisma.cryptoAsset.count({ where: { riskRating: 'amber' } }),
        prisma.cryptoAsset.count({ where: { riskRating: 'green' } }),
        prisma.cryptoAsset.count({ where: { daysToExpiry: { gte: 0, lte: 30 } } }),
        prisma.cryptoAsset.count({ where: { quantumSafe: false, environment: 'production' } })
      ]);
      return { red, amber, green, expiring_soon: expiringSoon, quantum_vulnerable: quantumVulnerable };
    })(),
    (async () => {
      const [critical_open, high_open, total_open, last_24h] = await Promise.all([
        prisma.securityAlert.count({ where: { severity: 'critical', status: 'open' } }),
        prisma.securityAlert.count({ where: { severity: 'high', status: 'open' } }),
        prisma.securityAlert.count({ where: { status: 'open' } }),
        prisma.securityAlert.count({ where: { createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } })
      ]);
      return { critical_open, high_open, total_open, last_24h };
    })(),
    prisma.threatIndicator.count({ where: { isActive: true } }),
    (async () => {
      const [kev_open, critical_open] = await Promise.all([
        prisma.cveTracking.count({ where: { isKev: true, status: 'open' } }),
        prisma.cveTracking.count({ where: { cvssScore: { gte: 9.0 }, status: 'open' } })
      ]);
      return { kev_open, critical_open };
    })()
  ]);

  res.json({
    cbom: cbomStats,
    alerts: alertStats,
    threatIntel: { activeIOCs: iocCount },
    cve: cveStats,
    lastUpdated: new Date()
  });
});

module.exports = {
  getDashboardStats
};
