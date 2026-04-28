const { esClient } = require('../../infrastructure/elasticsearch/client');
const { ES_INDICES } = require('../../infrastructure/elasticsearch/indices');
const { toApiAlert } = require('./index');

async function indexAlert(alert) {
  return esClient.index({
    index: ES_INDICES.ALERTS,
    document: {
      ...toApiAlert(alert),
      '@timestamp': new Date()
    }
  });
}

module.exports = {
  indexAlert
};
