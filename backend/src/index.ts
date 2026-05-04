import 'dotenv/config';
import createServer from './server';

import { initElasticsearch } from './infrastructure/elasticsearch/bootstrap';
import { startCertScanner } from './jobs/certScanner';
import { startSiemCorrelator } from './jobs/siemCorrelator';
import logger from './infrastructure/logging/logger';

const PORT = process.env.PORT || 4000;
const { app, server, io } = createServer();

async function start() {
  try {
    await initElasticsearch();
    logger.info('✅ Elasticsearch connected and indices ready');

    startCertScanner(io);
    logger.info('✅ Certificate scanner started');

    startSiemCorrelator(io);
    logger.info('✅ SIEM correlator started');

    server.listen(PORT, () => {
      logger.info(`Connect Security Platform API running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start:', err);
    process.exit(1);
  }
}

start();

export { app, server, io, start };
