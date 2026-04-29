const { esClient } = require('../../infrastructure/elasticsearch/client');
const { ES_INDICES } = require('../../infrastructure/elasticsearch/indices');

async function getProtocolStats() {
  const result = await esClient.search({
    index: `${ES_INDICES.NETWORK_LOGS}*`,
    body: {
      size: 0,
      aggs: {
        by_protocol: { terms: { field: 'dest_port', size: 20 } },
        by_country: { terms: { field: 'country', size: 10 } }
      },
      query: { range: { '@timestamp': { gte: 'now-24h' } } }
    }
  });

  return result.aggregations;
}

async function getDnsAnomalies() {
  const result = await esClient.search({
    index: 'connect-dns_query-*',
    body: {
      query: {
        bool: {
          must: [
            { range: { '@timestamp': { gte: 'now-24h' } } },
            { range: { dns_entropy: { gte: 3.0 } } }
          ]
        }
      },
      sort: [{ dns_entropy: { order: 'desc' } }],
      size: 50
    }
  });

  return result.hits.hits.map((hit) => hit._source);
}

async function getTopIps() {
  const result = await esClient.search({
    index: 'connect-firewall_event-*',
    body: {
      size: 0,
      aggs: {
        top_ips: {
          terms: { field: 'source_ip', size: 10 },
          aggs: {
            countries: { terms: { field: 'country', size: 1 } },
            actions: { terms: { field: 'action', size: 5 } }
          }
        }
      },
      query: { range: { '@timestamp': { gte: 'now-24h' } } }
    }
  });

  return result.aggregations;
}

module.exports = {
  getDnsAnomalies,
  getProtocolStats,
  getTopIps
};
