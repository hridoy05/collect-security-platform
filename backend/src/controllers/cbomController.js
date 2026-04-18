const asyncHandler = require('express-async-handler');
const { 
  getAllAssets, 
  upsertAsset, 
  getRiskSummary, 
  generateMigrationRoadmap 
} = require('../services/cbomService');

/**
 * @desc    Get all crypto assets with filtering
 * @route   GET /api/cbom
 * @access  Private
 */
const getCbomAssets = asyncHandler(async (req, res) => {
  const { risk, environment, quantumSafe } = req.query;
  const assets = await getAllAssets({
    riskRating: risk,
    environment,
    quantumSafe: quantumSafe !== undefined ? quantumSafe === 'true' : undefined
  });
  res.json(assets);
});

/**
 * @desc    Get crypto risk summary
 * @route   GET /api/cbom/summary
 * @access  Private
 */
const getCbomSummary = asyncHandler(async (req, res) => {
  const summary = await getRiskSummary();
  res.json(summary);
});

/**
 * @desc    Get quantum migration roadmap
 * @route   GET /api/cbom/migration-roadmap
 * @access  Private
 */
const getMigrationRoadmap = asyncHandler(async (req, res) => {
  const roadmap = await generateMigrationRoadmap();
  res.json(roadmap);
});

/**
 * @desc    Upsert a crypto asset
 * @route   POST /api/cbom
 * @access  Private
 */
const upsertCbomAsset = asyncHandler(async (req, res) => {
  const asset = await upsertAsset(req.body);
  
  // Emit real-time update if red
  if (asset.risk_rating === 'red') {
    req.app.get('io').emit('cbom:red_asset', asset);
  }
  
  res.json(asset);
});

module.exports = {
  getCbomAssets,
  getCbomSummary,
  getMigrationRoadmap,
  upsertCbomAsset
};
