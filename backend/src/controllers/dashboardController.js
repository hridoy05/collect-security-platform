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

/**
 * @desc    Get chart data for dashboard (timeline, MITRE, attack distribution)
 * @route   GET /api/dashboard/charts
 * @access  Private
 */
const getDashboardCharts = asyncHandler(async (req, res) => {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const alerts = await prisma.securityAlert.findMany({
    where: { createdAt: { gte: since24h } },
    select: { createdAt: true, mitreTactic: true, title: true }
  });

  // Hourly timeline — 24 buckets
  const hourMap = {};
  for (let h = 0; h < 24; h++) {
    const hourDate = new Date(since24h.getTime() + h * 3600000);
    hourMap[h] = { h: `${hourDate.getHours()}:00`, events: 0, alerts: 0 };
  }
  for (const alert of alerts) {
    const idx = Math.min(23, Math.max(0, Math.floor((alert.createdAt.getTime() - since24h.getTime()) / 3600000)));
    hourMap[idx].alerts += 1;
    hourMap[idx].events += 18; // each alert implies ~18 raw log events
  }

  // MITRE tactic counts
  const mitreMap = {};
  for (const a of alerts) {
    if (a.mitreTactic) mitreMap[a.mitreTactic] = (mitreMap[a.mitreTactic] || 0) + 1;
  }

  // Attack type distribution
  const distMap = { 'Brute Force': 0, 'DNS Tunnel': 0, 'Port Scan': 0, 'Exfil': 0, 'Other': 0 };
  for (const a of alerts) {
    const t = (a.title || '').toLowerCase();
    if (t.includes('brute') || t.includes('credential')) distMap['Brute Force']++;
    else if (t.includes('dns') || t.includes('tunnel'))  distMap['DNS Tunnel']++;
    else if (t.includes('port') || t.includes('scan'))   distMap['Port Scan']++;
    else if (t.includes('exfil') || t.includes('data'))  distMap['Exfil']++;
    else distMap['Other']++;
  }

  res.json({
    timeline: Object.values(hourMap),
    mitre: Object.entries(mitreMap).map(([tactic, count]) => ({ tactic, count })),
    attackDistribution: Object.entries(distMap).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }))
  });
});

module.exports = {
  getDashboardStats,
  getDashboardCharts
};
