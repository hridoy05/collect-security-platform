const { esClient } = require('../../infrastructure/elasticsearch/client');
const { ES_INDICES } = require('../../infrastructure/elasticsearch/indices');

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

module.exports = {
  indexAsset
};
