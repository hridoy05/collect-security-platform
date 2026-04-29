const cryptoAssetRepository = require('../../repositories/cbom');
const cveTrackingRepository = require('../../repositories/threatIntel/cveRepository');
const securityAlertRepository = require('../../repositories/alerts');
const threatIndicatorRepository = require('../../repositories/threatIntel/indicatorRepository');

async function getDashboardStats() {
  const [cbomStats, alertStats, activeIOCs, cveStats] = await Promise.all([
    cryptoAssetRepository.getDashboardStats(),
    securityAlertRepository.countOpenStats(),
    threatIndicatorRepository.countActive(),
    cveTrackingRepository.getDashboardStats()
  ]);

  return {
    cbom: cbomStats,
    alerts: alertStats,
    threatIntel: { activeIOCs },
    cve: cveStats,
    lastUpdated: new Date()
  };
}

async function getDashboardCharts() {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const alerts = await securityAlertRepository.findRecentForDashboard(since24h);

  const hourMap = {};
  for (let hour = 0; hour < 24; hour += 1) {
    const hourDate = new Date(since24h.getTime() + hour * 3600000);
    hourMap[hour] = { h: `${hourDate.getHours()}:00`, events: 0, alerts: 0 };
  }

  for (const alert of alerts) {
    const index = Math.min(
      23,
      Math.max(0, Math.floor((alert.createdAt.getTime() - since24h.getTime()) / 3600000))
    );
    hourMap[index].alerts += 1;
    hourMap[index].events += 18;
  }

  const mitreMap = {};
  for (const alert of alerts) {
    if (alert.mitreTactic) {
      mitreMap[alert.mitreTactic] = (mitreMap[alert.mitreTactic] || 0) + 1;
    }
  }

  const distMap = { 'Brute Force': 0, 'DNS Tunnel': 0, 'Port Scan': 0, Exfil: 0, Other: 0 };
  for (const alert of alerts) {
    const title = (alert.title || '').toLowerCase();
    if (title.includes('brute') || title.includes('credential')) {
      distMap['Brute Force'] += 1;
    } else if (title.includes('dns') || title.includes('tunnel')) {
      distMap['DNS Tunnel'] += 1;
    } else if (title.includes('port') || title.includes('scan')) {
      distMap['Port Scan'] += 1;
    } else if (title.includes('exfil') || title.includes('data')) {
      distMap.Exfil += 1;
    } else {
      distMap.Other += 1;
    }
  }

  return {
    timeline: Object.values(hourMap),
    mitre: Object.entries(mitreMap).map(([tactic, count]) => ({ tactic, count })),
    attackDistribution: Object.entries(distMap)
      .filter(([, value]) => value > 0)
      .map(([name, value]) => ({ name, value }))
  };
}

module.exports = {
  getDashboardCharts,
  getDashboardStats
};
