const { esClient } = require('./client');
const { ES_INDICES } = require('./indices');
const { getMappingForIndex } = require('./mappings');

async function initElasticsearch() {
  for (const index of Object.values(ES_INDICES)) {
    const exists = await esClient.indices.exists({ index });
    if (!exists) {
      await esClient.indices.create({
        index,
        mappings: getMappingForIndex(index)
      });
      console.log(`Created Elasticsearch index: ${index}`);
    }
  }

  await seedSampleSecurityEvents();
}

async function seedSampleSecurityEvents() {
  const events = [];
  const now = Date.now();

  for (let index = 0; index < 50; index += 1) {
    events.push({
      '@timestamp': new Date(now - index * 6000),
      event_type: index === 0 ? 'auth_success' : 'auth_failure',
      source_ip: '45.33.32.156',
      target_user: 'karim@paybdapp.com',
      severity: index === 0 ? 'critical' : 'medium',
      description: index === 0 ? 'Successful login after 49 failures' : 'Login failure',
      country: 'Russia'
    });
  }

  const tunnelDomains = [
    'aGVsbG8gd29ybGQ.attacker.com',
    'dGhpcyBpcyBzdG9sZW4gZGF0YQ.attacker.com',
    'cGF5bWVudCBkYXRh.attacker.com'
  ];

  tunnelDomains.forEach((domain, index) => {
    events.push({
      '@timestamp': new Date(now - 3600000 + index * 1000),
      event_type: 'dns_query',
      source_ip: '10.0.0.45',
      dns_query: domain,
      severity: 'high',
      description: 'Possible DNS tunneling detected'
    });
  });

  if (events.length === 0) {
    return;
  }

  const body = events.flatMap((document) => [
    { index: { _index: ES_INDICES.SECURITY_EVENTS } },
    document
  ]);

  await esClient.bulk({ body });
}

module.exports = {
  initElasticsearch
};
