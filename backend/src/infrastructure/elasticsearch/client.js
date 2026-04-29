const { Client } = require('@elastic/elasticsearch');

const esClient = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
  requestTimeout: 30000
});

module.exports = {
  esClient
};
