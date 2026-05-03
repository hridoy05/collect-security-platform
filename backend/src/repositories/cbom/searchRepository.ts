import { esClient } from '../../infrastructure/elasticsearch/client';
import { ES_INDICES } from '../../infrastructure/elasticsearch/indices';

async function indexAsset(asset) {
  return esClient.index({
    index: ES_INDICES.CBOM,
    id: asset.asset_id,
    document: {
      ...asset,
      '@timestamp': new Date()
    }
  });
}

export {
  indexAsset
};
