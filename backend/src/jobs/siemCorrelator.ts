// ============================================================
// SIEM Correlator Job
// Runs every 5 minutes — correlates ES events, scores via ML,
// creates SecurityAlert records, and pushes via Socket.IO
// ============================================================

import cron from 'node-cron';
import logger from '../infrastructure/logging/logger';
import { runScheduledCorrelation } from '../services/alerts';

async function runSiemCorrelation(io) {
  try {
    const createdAlerts = await runScheduledCorrelation();

    createdAlerts.forEach(({ activity, alert, score, severity }) => {
      if (io) {
        io.emit('alert:new', alert);
      }

      logger.info(
        `SIEM cron: alert created for ${activity.ip} (score: ${score}, severity: ${severity})`
      );
    });
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

export { startSiemCorrelator };
