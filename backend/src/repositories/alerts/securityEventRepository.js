const { esClient } = require('../../infrastructure/elasticsearch/client');
const { ES_INDICES } = require('../../infrastructure/elasticsearch/indices');

async function indexSecurityEvent(event) {
  return esClient.index({
    index: ES_INDICES.SECURITY_EVENTS,
    document: {
      ...event,
      '@timestamp': event.timestamp || new Date()
    }
  });
}

async function findSuspiciousAuthActivity(timeWindowMinutes = 10) {
  const cutoff = new Date(Date.now() - timeWindowMinutes * 60 * 1000);
  const result = await esClient.search({
    index: ES_INDICES.SECURITY_EVENTS,
    body: {
      query: {
        bool: {
          must: [
            { term: { event_type: 'auth_failure' } },
            { range: { '@timestamp': { gte: cutoff } } }
          ]
        }
      },
      aggs: {
        by_ip: {
          terms: { field: 'source_ip', size: 50 },
          aggs: {
            failure_count: { value_count: { field: 'source_ip' } },
            unique_users: { cardinality: { field: 'target_user' } }
          }
        }
      },
      size: 0
    }
  });

  return result.aggregations.by_ip.buckets
    .filter((bucket) => bucket.doc_count > 10)
    .map((bucket) => ({
      ip: bucket.key,
      failureCount: bucket.doc_count,
      uniqueUsers: bucket.unique_users.value,
      attackType: bucket.unique_users.value > 5 ? 'credential_stuffing' : 'brute_force'
    }));
}

async function lookupThreatIntel(indicator, indicatorType = 'ip') {
  const result = await esClient.search({
    index: ES_INDICES.THREAT_INTEL,
    body: {
      query: {
        bool: {
          must: [
            { term: { ioc_type: indicatorType } },
            { term: { ioc_value: indicator } },
            { term: { is_active: true } }
          ]
        }
      }
    }
  });

  if (result.hits.total.value > 0) {
    return result.hits.hits[0]._source;
  }

  return null;
}

async function indexMlAnomaly(anomaly) {
  return esClient.index({
    index: ES_INDICES.ML_ANOMALIES,
    document: {
      ...anomaly,
      '@timestamp': new Date()
    }
  });
}

async function getRecentAnomalies(hours = 24) {
  const result = await esClient.search({
    index: ES_INDICES.ML_ANOMALIES,
    body: {
      query: {
        bool: {
          must: [
            { term: { is_anomaly: true } },
            { range: { '@timestamp': { gte: `now-${hours}h` } } }
          ]
        }
      },
      sort: [{ anomaly_score: { order: 'desc' } }],
      size: 50
    }
  });

  return result.hits.hits.map((hit) => hit._source);
}

async function getDashboardStats() {
  const result = await esClient.search({
    index: ES_INDICES.SECURITY_EVENTS,
    body: {
      size: 0,
      aggs: {
        events_over_time: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: 'hour',
            min_doc_count: 0
          }
        },
        by_event_type: {
          terms: { field: 'event_type', size: 20 }
        },
        top_source_ips: {
          terms: { field: 'source_ip', size: 10 }
        },
        severity_distribution: {
          terms: { field: 'severity', size: 5 }
        }
      },
      query: {
        range: { '@timestamp': { gte: 'now-24h' } }
      }
    }
  });

  return result.aggregations;
}

module.exports = {
  findSuspiciousAuthActivity,
  getDashboardStats,
  getRecentAnomalies,
  indexMlAnomaly,
  indexSecurityEvent,
  lookupThreatIntel
};
