const { esClient } = require('../../infrastructure/elasticsearch/client');
const { ES_INDICES } = require('../../infrastructure/elasticsearch/indices');

async function indexAppLog(log) {
  try {
    return await esClient.index({
      index: ES_INDICES.APP_LOGS,
      document: {
        ...log,
        '@timestamp': log.timestamp || new Date()
      }
    });
  } catch (error) {
    console.error('Failed to index app log in Elasticsearch:', error.message);
    return null;
  }
}

module.exports = {
  indexAppLog
};
