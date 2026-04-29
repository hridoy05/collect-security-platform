// ============================================================
// CBOM Service — Cryptographic Bill of Materials
// ============================================================

const { assessAsset } = require('./assetAssessment');
const { toApiAsset, toPrismaUpsertPayload } = require('./assetMapper');
const { toRoadmapItem } = require('./migrationRoadmap');
const cryptoAssetRepository = require('../../repositories/cbom');
const { indexAsset } = require('../../repositories/cbom/searchRepository');

async function getAllAssets(filters = {}) {
  const assets = await cryptoAssetRepository.findMany(filters);
  return assets.map(toApiAsset);
}

async function upsertAsset(assetData) {
  const assessed = assessAsset(assetData);
  const result = await cryptoAssetRepository.upsert(toPrismaUpsertPayload(assessed));

  await indexAsset(assessed);

  return toApiAsset(result);
}

async function getRiskSummary() {
  return cryptoAssetRepository.getRiskSummary();
}

async function generateMigrationRoadmap() {
  const vulnerableAssets = await cryptoAssetRepository.findProductionQuantumVulnerableAssets();
  return vulnerableAssets.map(toRoadmapItem);
}

module.exports = {
  assessAsset,
  generateMigrationRoadmap,
  getAllAssets,
  getRiskSummary,
  upsertAsset
};
