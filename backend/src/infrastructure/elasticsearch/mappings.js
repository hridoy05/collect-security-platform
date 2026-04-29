const { ES_INDICES } = require('./indices');

function getMappingForIndex(index) {
  const baseMapping = {
    properties: {
      '@timestamp': { type: 'date' },
      source_ip: { type: 'ip' },
      dest_ip: { type: 'ip' }
    }
  };

  if (index === ES_INDICES.ALERTS) {
    return {
      properties: {
        ...baseMapping.properties,
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

  if (index === ES_INDICES.SECURITY_EVENTS) {
    return {
      properties: {
        '@timestamp': { type: 'date' },
        source_ip: { type: 'ip' },
        dest_ip: { type: 'ip' },
        event_type: { type: 'keyword' },
        event_outcome: { type: 'keyword' },
        severity: { type: 'keyword' },
        country: { type: 'keyword' },
        target_user: { type: 'keyword' },
        description: { type: 'text', fields: { keyword: { type: 'keyword' } } },
        dns_query: { type: 'keyword' },
        auth_result: { type: 'keyword' },
        'user.name': { type: 'keyword' }
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
        metadata: { type: 'object', enabled: false }
      }
    };
  }

  return baseMapping;
}

module.exports = {
  getMappingForIndex
};
