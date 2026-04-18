// ============================================================
// Elasticsearch Service — Topic 5: SIEM
// Index management, log ingestion, correlation queries
// ============================================================

const { Client } = require('@elastic/elasticsearch');

const esClient = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
  requestTimeout: 30000
});

// Index names — organized by data type
const ES_INDICES = {
  SECURITY_EVENTS: 'connect-security-events',
  ALERTS: 'connect-alerts',
  CBOM: 'connect-cbom',
  THREAT_INTEL: 'connect-threat-intel',
  ML_ANOMALIES: 'connect-ml-anomalies',
  DNS_LOGS: 'connect-dns-logs',
  NETWORK_LOGS: 'connect-network-logs',
  APP_LOGS: 'connect-app-logs'
};

// ─────────────────────────────────────────
// INITIALIZE — Create indices with mappings
// ─────────────────────────────────────────

async function initElasticsearch() {
  for (const [name, index] of Object.entries(ES_INDICES)) {
    const exists = await esClient.indices.exists({ index });
    if (!exists) {
      await esClient.indices.create({
        index,
        mappings: getMappingForIndex(index)
      });
      console.log(`✅ Created Elasticsearch index: ${index}`);
    }
  }

  // Seed some sample security events
  await seedSampleEvents();
}

function getMappingForIndex(index) {
  const base = {
    properties: {
      '@timestamp': { type: 'date' },
      source_ip: { type: 'ip' },
      dest_ip: { type: 'ip' }
    }
  };

  if (index === ES_INDICES.ALERTS) {
    return {
      properties: {
        ...base.properties,
        title: { type: 'text', fields: { keyword: { type: 'keyword' } } },
        severity: { type: 'keyword' },
        status: { type: 'keyword' },
        source_type: { type: 'keyword' },
        alert_score: { type: 'float' },
        mitre_tactic: { type: 'keyword' },
        mitre_technique: { type: 'keyword' },
        affected_user: { type: 'keyword' },
        affected_system: { type: 'keyword' }
      }
    };
  }

  if (index === ES_INDICES.CBOM) {
    return {
      properties: {
        asset_id: { type: 'keyword' },
        asset_type: { type: 'keyword' },
        algorithm: { type: 'keyword' },
        key_length: { type: 'integer' },
        risk_rating: { type: 'keyword' },
        quantum_safe: { type: 'boolean' },
        days_to_expiry: { type: 'integer' },
        environment: { type: 'keyword' },
        '@timestamp': { type: 'date' }
      }
    };
  }

  if (index === ES_INDICES.APP_LOGS) {
    return {
      properties: {
        '@timestamp': { type: 'date' },
        level: { type: 'keyword' },
        message: { type: 'text', fields: { keyword: { type: 'keyword' } } },
        service: { type: 'keyword' },
        metadata: { type: 'object', enabled: false } // flexible for different log shapes
      }
    };
  }

  return base;
}

// ─────────────────────────────────────────
// INDEX EVENT — ingest a security event
// ─────────────────────────────────────────

async function indexSecurityEvent(event) {
  return esClient.index({
    index: ES_INDICES.SECURITY_EVENTS,
    document: { ...event, '@timestamp': event.timestamp || new Date() }
  });
}

// ─────────────────────────────────────────
// APP LOGGING — ingest application logs
// ─────────────────────────────────────────

async function indexAppLog(log) {
  try {
    return await esClient.index({
      index: ES_INDICES.APP_LOGS,
      document: {
        ...log,
        '@timestamp': log.timestamp || new Date()
      }
    });
  } catch (e) {
    // Fail silently to prevent logging failures from crashing the app
    console.error('Failed to index app log in ES:', e.message);
  }
}

// ─────────────────────────────────────────
// SIEM CORRELATION — Topic 5
// Find brute force + account takeover pattern
// ─────────────────────────────────────────

async function correlateEvents(timeWindowMinutes = 10) {
  const cutoff = new Date(Date.now() - timeWindowMinutes * 60 * 1000);

  // Aggregation: group failed logins by IP
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

  const suspiciousIPs = result.aggregations.by_ip.buckets
    .filter(b => b.doc_count > 10)
    .map(b => ({
      ip: b.key,
      failureCount: b.doc_count,
      uniqueUsers: b.unique_users.value,
      attackType: b.unique_users.value > 5 ? 'credential_stuffing' : 'brute_force'
    }));

  return suspiciousIPs;
}

// ─────────────────────────────────────────
// THREAT INTEL LOOKUP — Topic 6
// Check if an IP/domain is known bad
// ─────────────────────────────────────────

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

// ─────────────────────────────────────────
// ML ANOMALIES — store and query
// Topic 8: ML results in Elasticsearch
// ─────────────────────────────────────────

async function indexMLAnomaly(anomaly) {
  return esClient.index({
    index: ES_INDICES.ML_ANOMALIES,
    document: { ...anomaly, '@timestamp': new Date() }
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

  return result.hits.hits.map(h => h._source);
}

// ─────────────────────────────────────────
// SECURITY DASHBOARD STATS
// Topic 5: SIEM analytics
// ─────────────────────────────────────────

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

// ─────────────────────────────────────────
// SEED SAMPLE EVENTS — for demo
// ─────────────────────────────────────────

async function seedSampleEvents() {
  const events = [];
  const now = Date.now();

  // Simulate brute force attack
  for (let i = 0; i < 50; i++) {
    events.push({
      '@timestamp': new Date(now - i * 6000),
      event_type: i === 0 ? 'auth_success' : 'auth_failure',
      source_ip: '45.33.32.156',
      target_user: 'karim@paybdapp.com',
      severity: i === 0 ? 'critical' : 'medium',
      description: i === 0 ? 'Successful login after 49 failures' : 'Login failure',
      country: 'Russia'
    });
  }

  // Simulate DNS tunneling
  const tunnelDomains = [
    'aGVsbG8gd29ybGQ.attacker.com',
    'dGhpcyBpcyBzdG9sZW4gZGF0YQ.attacker.com',
    'cGF5bWVudCBkYXRh.attacker.com'
  ];
  tunnelDomains.forEach((domain, i) => {
    events.push({
      '@timestamp': new Date(now - 3600000 + i * 1000),
      event_type: 'dns_query',
      source_ip: '10.0.0.45',
      dns_query: domain,
      severity: 'high',
      description: 'Possible DNS tunneling detected'
    });
  });

  // Batch index
  if (events.length > 0) {
    const body = events.flatMap(doc => [
      { index: { _index: ES_INDICES.SECURITY_EVENTS } },
      doc
    ]);
    await esClient.bulk({ body });
  }
}

module.exports = { 
  esClient, 
  ES_INDICES, 
  initElasticsearch, 
  indexSecurityEvent, 
  indexAppLog,
  correlateEvents, 
  lookupThreatIntel, 
  indexMLAnomaly, 
  getRecentAnomalies, 
  getDashboardStats 
};
