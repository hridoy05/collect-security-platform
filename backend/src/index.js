require('dotenv').config();
const createServer = require('./server');

const { initElasticsearch } = require('./services/elasticService');
const { startCertScanner } = require('./jobs/certScanner');
const { startSiemCorrelator } = require('./jobs/siemCorrelator');
const logger = require('./services/loggerService');

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

module.exports = { app, server, io, start };
