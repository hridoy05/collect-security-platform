// ============================================================
// SIEM Correlator Job
// Runs every 5 minutes — correlates ES events, scores via ML,
// creates SecurityAlert records, and pushes via Socket.IO
// ============================================================

const cron = require('node-cron');
const prisma = require('../config/prismaClient');
const { correlateEvents, esClient, ES_INDICES } = require('../services/elasticService');
const logger = require('../services/loggerService');

// Mirrors detectBruteForce() scoring formula directly on aggregated data.
// Avoids a second ES query for raw events — numerically equivalent.
function scoreFromCorrelation(activity) {
  const score = Math.min(activity.failureCount / 100, 1.0);
  const severity = score >= 0.8 ? 'critical' : score >= 0.5 ? 'high' : 'medium';
  return { score, severity };
}

async function runSiemCorrelation(io) {
  try {
    const suspiciousActivity = await correlateEvents(5);

    for (const activity of suspiciousActivity) {
      // Dedup — skip if an alert for this IP was already created in the last 5 minutes
      const existing = await prisma.securityAlert.findFirst({
        where: {
          sourceIp: activity.ip,
          createdAt: { gte: new Date(Date.now() - 5 * 60 * 1000) }
        }
      });
      if (existing) continue;

      const { score, severity } = scoreFromCorrelation(activity);

      const savedAlert = await prisma.securityAlert.create({
        data: {
          alertId: `SIEM-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
          title: `${activity.attackType === 'credential_stuffing' ? 'Credential Stuffing' : 'Brute Force'} Attack Detected`,
          description: `${activity.failureCount} failed logins from ${activity.ip} targeting ${activity.uniqueUsers} unique accounts`,
          severity,
          status: 'open',
          sourceType: 'siem_cron',
          sourceIp: activity.ip,
          mitreTactic: 'Credential Access',
          mitreTechnique: 'T1110 — Brute Force',
          alertScore: score * 100,
          rawEvent: { ...activity }
        }
      });

      // Index in Elasticsearch
      await esClient.index({
        index: ES_INDICES.ALERTS,
        document: { ...savedAlert, '@timestamp': new Date() }
      });

      // Push real-time via WebSocket
      if (io) io.emit('alert:new', savedAlert);

      logger.info(`SIEM cron: alert created for ${activity.ip} (score: ${score}, severity: ${severity})`);
    }
  } catch (err) {
    logger.error(`SIEM correlator error: ${err.message}`);
  }
}

function startSiemCorrelator(io) {
  // Run immediately on startup
  runSiemCorrelation(io);

  // Then every 5 minutes
  cron.schedule('*/5 * * * *', () => runSiemCorrelation(io));

  logger.info('✅ SIEM correlator scheduled (every 5 minutes)');
}

module.exports = { startSiemCorrelator };
