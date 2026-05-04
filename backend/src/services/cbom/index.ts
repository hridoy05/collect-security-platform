// ============================================================
// CBOM Service — Cryptographic Bill of Materials
// ============================================================

import { assessAsset } from './assetAssessment';
import { toApiAsset, toPrismaUpsertPayload } from './assetMapper';
import { toRoadmapItem } from './migrationRoadmap';
import * as cryptoAssetRepository from '../../repositories/cbom';
import { indexAsset } from '../../repositories/cbom/searchRepository';

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

export {
  assessAsset,
  generateMigrationRoadmap,
  getAllAssets,
  getRiskSummary,
  upsertAsset
};
