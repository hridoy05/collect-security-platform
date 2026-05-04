import { esClient } from '../../infrastructure/elasticsearch/client';
import { ES_INDICES } from '../../infrastructure/elasticsearch/indices';
import { toApiAlert } from './index';

async function indexAlert(alert) {
  return esClient.index({
    index: ES_INDICES.ALERTS,
    document: {
      ...toApiAlert(alert),
      '@timestamp': new Date()
    }
  });
}

export {
  indexAlert
};
